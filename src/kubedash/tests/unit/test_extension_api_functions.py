"""
Unit tests for Kubernetes Extension API functions

This module tests the core functions of the Extension API:
- Project operations (list, get, create, update, delete)
- Authentication functions
- Authorization functions
- Helper functions
"""
import pytest
from unittest.mock import patch, MagicMock, Mock
from kubernetes.client.rest import ApiException

from lib.extension_api.projects import (
    list_all_namespaces,
    get_namespace,
    list_projects,
    get_project,
    create_project,
    update_project,
    delete_project,
    _filter_by_labels
)
from lib.extension_api.authentication import (
    AuthenticatedUser,
    authenticate_front_proxy,
    extract_bearer_token,
    authenticate_request,
    get_user_from_session_or_token
)
from lib.extension_api.authorization import (
    check_namespace_access,
    filter_namespaces_by_permission,
    can_user_list_all_namespaces,
    check_self_subject_access
)
from lib.extension_api.helpers import (
    get_resource_version,
    build_project_object,
    build_project_list,
    build_status_response,
    build_not_found_response,
    build_forbidden_response,
    build_unauthorized_response
)


##############################################################
## Helper Functions Tests
##############################################################

class TestHelperFunctions:
    """Test helper functions for Extension API"""
    
    def test_get_resource_version(self):
        """Test resource version generation"""
        version = get_resource_version()
        assert isinstance(version, str)
        assert version.isdigit()
        # Should be a reasonable timestamp (after 2020)
        assert int(version) > 1577836800  # 2020-01-01
    
    def test_build_project_object(self):
        """Test building a Project object from namespace data"""
        namespace_data = {
            "name": "test-ns",
            "uid": "test-uid-123",
            "created": "2024-01-01T00:00:00Z",
            "labels": {"env": "test"},
            "annotations": {
                "kubedash.devopstales.github.io/protected": "true",
                "metadata.k8s.io/owner": "testuser",
                "metadata.k8s.io/repository": "https://github.com/test/repo",
                "metadata.k8s.io/pipeline": "https://ci.test.com/pipeline"
            },
            "status": "Active",
            "resource_version": "12345"
        }
        
        project = build_project_object(namespace_data)
        
        assert project["kind"] == "Project"
        assert project["apiVersion"] == "kubedash.devopstales.github.io/v1"
        assert project["metadata"]["name"] == "test-ns"
        assert project["metadata"]["uid"] == "test-uid-123"
        assert project["spec"]["protected"] is True
        assert project["spec"]["owner"] == "testuser"
        assert project["spec"]["repository"] == "https://github.com/test/repo"
        assert project["spec"]["pipeline"] == "https://ci.test.com/pipeline"
        assert project["status"]["phase"] == "Active"
    
    def test_build_project_object_minimal(self):
        """Test building Project object with minimal data"""
        namespace_data = {
            "name": "minimal-ns",
            "uid": "uid-123",
            "status": "Active"
        }
        
        project = build_project_object(namespace_data)
        
        assert project["kind"] == "Project"
        assert project["metadata"]["name"] == "minimal-ns"
        assert project["spec"]["protected"] is False
        assert project["spec"]["owner"] == ""
    
    def test_build_project_list(self):
        """Test building a ProjectList object"""
        projects = [
            build_project_object({"name": "ns1", "uid": "uid1", "status": "Active"}),
            build_project_object({"name": "ns2", "uid": "uid2", "status": "Active"})
        ]
        
        project_list = build_project_list(projects)
        
        assert project_list["kind"] == "ProjectList"
        assert project_list["apiVersion"] == "kubedash.devopstales.github.io/v1"
        assert len(project_list["items"]) == 2
        assert "resourceVersion" in project_list["metadata"]
    
    def test_build_status_response(self):
        """Test building a Status response"""
        status = build_status_response(
            status="Failure",
            message="Resource not found",
            reason="NotFound",
            code=404,
            details={"name": "test"}
        )
        
        assert status["kind"] == "Status"
        assert status["status"] == "Failure"
        assert status["message"] == "Resource not found"
        assert status["reason"] == "NotFound"
        assert status["code"] == 404
        assert status["details"]["name"] == "test"
    
    def test_build_not_found_response(self):
        """Test building NotFound response"""
        response = build_not_found_response("projects", "test-ns")
        
        assert response["kind"] == "Status"
        assert response["status"] == "Failure"
        assert response["reason"] == "NotFound"
        assert response["code"] == 404
        assert "test-ns" in response["message"]
        assert response["details"]["name"] == "test-ns"
    
    def test_build_forbidden_response(self):
        """Test building Forbidden response"""
        response = build_forbidden_response("projects", "test-ns", "testuser")
        
        assert response["kind"] == "Status"
        assert response["status"] == "Failure"
        assert response["reason"] == "Forbidden"
        assert response["code"] == 403
        assert "testuser" in response["message"]
        assert "test-ns" in response["message"]
    
    def test_build_unauthorized_response(self):
        """Test building Unauthorized response"""
        response = build_unauthorized_response()
        
        assert response["kind"] == "Status"
        assert response["status"] == "Failure"
        assert response["reason"] == "Unauthorized"
        assert response["code"] == 401


##############################################################
## Authentication Functions Tests
##############################################################

class TestAuthenticationFunctions:
    """Test authentication functions"""
    
    def test_authenticate_front_proxy(self, app):
        """Test front-proxy authentication"""
        with app.test_request_context(headers={
            'X-Remote-User': 'testuser',
            'X-Remote-Group': 'system:masters,developers'
        }):
            from flask import request
            user = authenticate_front_proxy(request)
            
            assert user is not None
            assert user.username == 'testuser'
            assert 'system:masters' in user.groups
            assert 'developers' in user.groups
    
    def test_authenticate_front_proxy_no_headers(self, app):
        """Test front-proxy authentication without headers"""
        with app.test_request_context():
            from flask import request
            user = authenticate_front_proxy(request)
            assert user is None
    
    def test_extract_bearer_token(self, app):
        """Test extracting Bearer token"""
        with app.test_request_context(headers={
            'Authorization': 'Bearer test-token-123'
        }):
            from flask import request
            token = extract_bearer_token(request)
            assert token == 'test-token-123'
    
    def test_extract_bearer_token_no_header(self, app):
        """Test extracting Bearer token without header"""
        with app.test_request_context():
            from flask import request
            token = extract_bearer_token(request)
            assert token is None
    
    def test_extract_bearer_token_invalid_format(self, app):
        """Test extracting Bearer token with invalid format"""
        with app.test_request_context(headers={
            'Authorization': 'Basic dGVzdDp0ZXN0'
        }):
            from flask import request
            token = extract_bearer_token(request)
            assert token is None
    
    @patch('lib.extension_api.authentication.k8sClientConfigGet')
    @patch('lib.extension_api.authentication.k8s_client.AuthenticationV1Api')
    def test_authenticate_request_success(self, mock_api_class, mock_config, app):
        """Test successful token authentication"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.authenticated = True
        mock_result.status.user.username = "tokenuser"
        mock_result.status.user.uid = "uid-123"
        mock_result.status.user.groups = ["developers"]
        mock_result.status.user.extra = {}
        mock_api.create_token_review.return_value = mock_result
        
        with app.test_request_context(headers={
            'Authorization': 'Bearer valid-token'
        }):
            from flask import request
            user = authenticate_request(request)
            
            assert user is not None
            assert user.username == "tokenuser"
            assert user.uid == "uid-123"
            assert "developers" in user.groups
    
    @patch('lib.extension_api.authentication.k8sClientConfigGet')
    @patch('lib.extension_api.authentication.k8s_client.AuthenticationV1Api')
    def test_authenticate_request_failed(self, mock_api_class, mock_config, app):
        """Test failed token authentication"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.authenticated = False
        mock_result.status.error = "Token expired"
        mock_api.create_token_review.return_value = mock_result
        
        with app.test_request_context(headers={
            'Authorization': 'Bearer invalid-token'
        }):
            from flask import request
            user = authenticate_request(request)
            assert user is None
    
    @patch('lib.extension_api.authentication.k8sClientConfigGet')
    @patch('lib.extension_api.authentication.k8s_client.AuthenticationV1Api')
    def test_authenticate_request_api_exception(self, mock_api_class, mock_config, app):
        """Test token authentication with API exception"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        mock_api.create_token_review.side_effect = ApiException(status=500, reason="Internal Error")
        
        with app.test_request_context(headers={
            'Authorization': 'Bearer test-token'
        }):
            from flask import request
            user = authenticate_request(request)
            assert user is None
    
    def test_get_user_from_session_or_token_front_proxy(self, app):
        """Test getting user from front-proxy headers"""
        with app.test_request_context(headers={
            'X-Remote-User': 'proxyuser',
            'X-Remote-Group': 'admins'
        }):
            from flask import request
            user = get_user_from_session_or_token(request)
            
            assert user is not None
            assert user.username == 'proxyuser'
            assert 'admins' in user.groups
    
    def test_get_user_from_session_or_token_session(self, app):
        """Test getting user from session"""
        with app.test_request_context() as ctx:
            from flask import request, session
            session['username'] = 'sessionuser'
            session['user_id'] = 123
            session['user_role'] = 'Admin'
            
            user = get_user_from_session_or_token(request, session)
            
            assert user is not None
            assert user.username == 'sessionuser'
            assert user.uid == '123'
            assert 'Admin' in user.groups
    
    def test_get_user_from_session_or_token_no_auth(self, app):
        """Test getting user with no authentication"""
        with app.test_request_context():
            from flask import request
            user = get_user_from_session_or_token(request)
            assert user is None


##############################################################
## Authorization Functions Tests
##############################################################

class TestAuthorizationFunctions:
    """Test authorization functions"""
    
    @patch('lib.extension_api.authorization.k8sClientConfigGet')
    @patch('lib.extension_api.authorization.k8s_client.AuthorizationV1Api')
    def test_check_namespace_access_allowed(self, mock_api_class, mock_config):
        """Test checking namespace access - allowed"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.allowed = True
        mock_api.create_subject_access_review.return_value = mock_result
        
        user = AuthenticatedUser("testuser", groups=["developers"])
        has_access = check_namespace_access(user, "default", "list", "pods")
        
        assert has_access is True
        mock_api.create_subject_access_review.assert_called_once()
    
    @patch('lib.extension_api.authorization.k8sClientConfigGet')
    @patch('lib.extension_api.authorization.k8s_client.AuthorizationV1Api')
    def test_check_namespace_access_denied(self, mock_api_class, mock_config):
        """Test checking namespace access - denied"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.allowed = False
        mock_api.create_subject_access_review.return_value = mock_result
        
        user = AuthenticatedUser("testuser", groups=["developers"])
        has_access = check_namespace_access(user, "restricted", "list", "pods")
        
        assert has_access is False
    
    @patch('lib.extension_api.authorization.k8sClientConfigGet')
    @patch('lib.extension_api.authorization.k8s_client.AuthorizationV1Api')
    def test_check_namespace_access_api_exception(self, mock_api_class, mock_config):
        """Test checking namespace access with API exception"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        mock_api.create_subject_access_review.side_effect = ApiException(status=500, reason="Error")
        
        user = AuthenticatedUser("testuser")
        has_access = check_namespace_access(user, "default", "list", "pods")
        
        # Should fail closed (deny access)
        assert has_access is False
    
    @patch('lib.extension_api.authorization.check_namespace_access')
    def test_filter_namespaces_by_permission(self, mock_check):
        """Test filtering namespaces by permission"""
        # Setup mock - allow access to ns1 and ns3, deny ns2
        def check_side_effect(user, namespace, verb, resource, api_group):
            return namespace in ["ns1", "ns3"]
        
        mock_check.side_effect = check_side_effect
        
        user = AuthenticatedUser("testuser")
        namespaces = ["ns1", "ns2", "ns3", "ns4"]
        
        allowed = filter_namespaces_by_permission(user, namespaces, "list", "pods")
        
        assert allowed == ["ns1", "ns3"]
        assert mock_check.call_count == 4
    
    @patch('lib.extension_api.authorization.k8sClientConfigGet')
    @patch('lib.extension_api.authorization.k8s_client.AuthorizationV1Api')
    def test_can_user_list_all_namespaces_allowed(self, mock_api_class, mock_config):
        """Test checking if user can list all namespaces - allowed"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.allowed = True
        mock_api.create_subject_access_review.return_value = mock_result
        
        user = AuthenticatedUser("admin", groups=["system:masters"])
        can_list = can_user_list_all_namespaces(user)
        
        assert can_list is True
    
    @patch('lib.extension_api.authorization.k8sClientConfigGet')
    @patch('lib.extension_api.authorization.k8s_client.AuthorizationV1Api')
    def test_can_user_list_all_namespaces_denied(self, mock_api_class, mock_config):
        """Test checking if user can list all namespaces - denied"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_result = MagicMock()
        mock_result.status.allowed = False
        mock_api.create_subject_access_review.return_value = mock_result
        
        user = AuthenticatedUser("regularuser")
        can_list = can_user_list_all_namespaces(user)
        
        assert can_list is False


##############################################################
## Project Functions Tests
##############################################################

class TestProjectFunctions:
    """Test project operation functions"""
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    def test_list_all_namespaces_success(self, mock_api_class, mock_config):
        """Test listing all namespaces successfully"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_ns1 = MagicMock()
        mock_ns1.metadata.name = "default"
        mock_ns1.metadata.uid = "uid-1"
        mock_ns1.metadata.creation_timestamp = None
        mock_ns1.metadata.labels = {}
        mock_ns1.metadata.annotations = {}
        mock_ns1.metadata.resource_version = "1"
        mock_ns1.status.phase = "Active"
        
        mock_ns2 = MagicMock()
        mock_ns2.metadata.name = "kube-system"
        mock_ns2.metadata.uid = "uid-2"
        mock_ns2.metadata.creation_timestamp = None
        mock_ns2.metadata.labels = {}
        mock_ns2.metadata.annotations = {}
        mock_ns2.metadata.resource_version = "2"
        mock_ns2.status.phase = "Active"
        
        mock_response = MagicMock()
        mock_response.items = [mock_ns1, mock_ns2]
        mock_api.list_namespace.return_value = mock_response
        
        namespaces, error = list_all_namespaces()
        
        assert error is None
        assert len(namespaces) == 2
        assert namespaces[0]["name"] == "default"
        assert namespaces[1]["name"] == "kube-system"
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    def test_list_all_namespaces_api_exception(self, mock_api_class, mock_config):
        """Test listing namespaces with API exception"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        mock_api.list_namespace.side_effect = ApiException(status=500, reason="Internal Error")
        
        namespaces, error = list_all_namespaces()
        
        assert namespaces == []
        assert error is not None
        assert "ApiException" in error
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    def test_get_namespace_success(self, mock_api_class, mock_config):
        """Test getting a namespace successfully"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_ns = MagicMock()
        mock_ns.metadata.name = "test-ns"
        mock_ns.metadata.uid = "uid-123"
        mock_ns.metadata.creation_timestamp = None
        mock_ns.metadata.labels = {"env": "test"}
        mock_ns.metadata.annotations = {}
        mock_ns.metadata.resource_version = "123"
        mock_ns.status.phase = "Active"
        mock_api.read_namespace.return_value = mock_ns
        
        ns_data, error = get_namespace("test-ns")
        
        assert error is None
        assert ns_data is not None
        assert ns_data["name"] == "test-ns"
        assert ns_data["uid"] == "uid-123"
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    def test_get_namespace_not_found(self, mock_api_class, mock_config):
        """Test getting a non-existent namespace"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        mock_api.read_namespace.side_effect = ApiException(status=404, reason="Not Found")
        
        ns_data, error = get_namespace("nonexistent")
        
        assert ns_data is None
        assert error == "NotFound"
    
    @patch('lib.extension_api.projects.list_all_namespaces')
    @patch('lib.extension_api.projects.can_user_list_all_namespaces')
    @patch('lib.extension_api.projects.filter_namespaces_by_permission')
    def test_list_projects_cluster_admin(self, mock_filter, mock_can_list, mock_list_all):
        """Test listing projects for cluster admin"""
        # Setup mocks
        mock_list_all.return_value = ([
            {"name": "ns1", "uid": "uid1", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "1"},
            {"name": "ns2", "uid": "uid2", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "2"}
        ], None)
        mock_can_list.return_value = True
        
        user = AuthenticatedUser("admin", groups=["system:masters"])
        projects, error = list_projects(user)
        
        assert error is None
        assert projects["kind"] == "ProjectList"
        assert len(projects["items"]) == 2
        mock_filter.assert_not_called()  # Should not filter for cluster admin
    
    @patch('lib.extension_api.projects.list_all_namespaces')
    @patch('lib.extension_api.projects.can_user_list_all_namespaces')
    @patch('lib.extension_api.projects.filter_namespaces_by_permission')
    def test_list_projects_regular_user(self, mock_filter, mock_can_list, mock_list_all):
        """Test listing projects for regular user"""
        # Setup mocks
        mock_list_all.return_value = ([
            {"name": "ns1", "uid": "uid1", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "1"},
            {"name": "ns2", "uid": "uid2", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "2"}
        ], None)
        mock_can_list.return_value = False
        mock_filter.return_value = ["ns1"]  # User can only access ns1
        
        user = AuthenticatedUser("regularuser")
        projects, error = list_projects(user)
        
        assert error is None
        assert projects["kind"] == "ProjectList"
        assert len(projects["items"]) == 1
        assert projects["items"][0]["metadata"]["name"] == "ns1"
        mock_filter.assert_called_once()
    
    def test_filter_by_labels(self):
        """Test filtering namespaces by labels"""
        namespaces = [
            {"name": "ns1", "labels": {"env": "prod", "team": "backend"}},
            {"name": "ns2", "labels": {"env": "dev", "team": "frontend"}},
            {"name": "ns3", "labels": {"env": "prod", "team": "frontend"}},
        ]
        
        # Test equality selector
        filtered = _filter_by_labels(namespaces, "env=prod")
        assert len(filtered) == 2
        assert all(ns["labels"]["env"] == "prod" for ns in filtered)
        
        # Test inequality selector
        filtered = _filter_by_labels(namespaces, "env!=prod")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "ns2"
        
        # Test multiple selectors
        filtered = _filter_by_labels(namespaces, "env=prod,team=backend")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "ns1"
        
        # Test existence check
        filtered = _filter_by_labels(namespaces, "env")
        assert len(filtered) == 3  # All have env label
    
    def test_filter_by_labels_empty_selector(self):
        """Test filtering with empty selector"""
        namespaces = [
            {"name": "ns1", "labels": {"env": "prod"}},
            {"name": "ns2", "labels": {}},
        ]
        
        filtered = _filter_by_labels(namespaces, "")
        assert len(filtered) == 2  # Should return all
    
    @patch('lib.extension_api.projects.get_namespace')
    @patch('lib.extension_api.projects.can_user_list_all_namespaces')
    @patch('lib.extension_api.projects.check_namespace_access')
    def test_get_project_success(self, mock_check, mock_can_list, mock_get_ns):
        """Test getting a project successfully"""
        # Setup mocks
        mock_get_ns.return_value = ({
            "name": "test-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {},
            "resource_version": "123"
        }, None)
        mock_can_list.return_value = False
        mock_check.return_value = True
        
        user = AuthenticatedUser("testuser")
        project, error, status = get_project(user, "test-ns")
        
        assert error is None
        assert status == 200
        assert project is not None
        assert project["metadata"]["name"] == "test-ns"
    
    @patch('lib.extension_api.projects.get_namespace')
    def test_get_project_not_found(self, mock_get_ns):
        """Test getting a non-existent project"""
        mock_get_ns.return_value = (None, "NotFound")
        
        user = AuthenticatedUser("testuser")
        project, error, status = get_project(user, "nonexistent")
        
        assert project is None
        assert status == 404
        assert "not found" in error.lower()
    
    @patch('lib.extension_api.projects.get_namespace')
    @patch('lib.extension_api.projects.can_user_list_all_namespaces')
    @patch('lib.extension_api.projects.check_namespace_access')
    def test_get_project_access_denied(self, mock_check, mock_can_list, mock_get_ns):
        """Test getting a project with access denied"""
        # Setup mocks
        mock_get_ns.return_value = ({
            "name": "restricted-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {},
            "resource_version": "123"
        }, None)
        mock_can_list.return_value = False
        mock_check.return_value = False  # Access denied
        
        user = AuthenticatedUser("testuser")
        project, error, status = get_project(user, "restricted-ns")
        
        # Should return 404 to not leak namespace existence
        assert project is None
        assert status == 404
        assert "not found" in error.lower()
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.AuthorizationV1Api')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    @patch('lib.extension_api.projects.get_namespace')
    def test_create_project_success(self, mock_get_ns, mock_api_class, mock_auth_api_class, mock_config):
        """Test creating a project successfully"""
        # Setup mocks
        mock_get_ns.return_value = (None, None)  # Namespace doesn't exist
        
        mock_auth_api = MagicMock()
        mock_auth_api_class.return_value = mock_auth_api
        mock_auth_result = MagicMock()
        mock_auth_result.status.allowed = True
        mock_auth_api.create_subject_access_review.return_value = mock_auth_result
        
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_created_ns = MagicMock()
        mock_created_ns.metadata.name = "new-project"
        mock_created_ns.metadata.uid = "uid-new"
        mock_created_ns.metadata.creation_timestamp = None
        mock_created_ns.metadata.labels = {}
        mock_created_ns.metadata.annotations = {
            "kubedash.devopstales.github.io/protected": "true",
            "metadata.k8s.io/owner": "testuser"
        }
        mock_created_ns.metadata.resource_version = "1"
        mock_created_ns.status.phase = "Active"
        mock_api.create_namespace.return_value = mock_created_ns
        
        user = AuthenticatedUser("testuser")
        project, error, status = create_project(
            user, "new-project", protected=True, owner="testuser"
        )
        
        assert error is None
        assert status == 201
        assert project is not None
        assert project["metadata"]["name"] == "new-project"
        assert project["spec"]["protected"] is True
        assert project["spec"]["owner"] == "testuser"
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.AuthorizationV1Api')
    @patch('lib.extension_api.projects.get_namespace')
    def test_create_project_already_exists(self, mock_get_ns, mock_auth_api_class, mock_config):
        """Test creating a project that already exists"""
        # Setup mocks - user is authorized to create namespaces
        mock_auth_api = MagicMock()
        mock_auth_api_class.return_value = mock_auth_api
        mock_auth_result = MagicMock()
        mock_auth_result.status.allowed = True
        mock_auth_api.create_subject_access_review.return_value = mock_auth_result
        
        # Namespace already exists
        mock_get_ns.return_value = ({
            "name": "existing-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {},
            "resource_version": "123"
        }, None)
        
        user = AuthenticatedUser("testuser")
        project, error, status = create_project(
            user, "existing-ns", protected=False
        )
        
        assert project is None
        assert status == 409
        assert "already exists" in error.lower()
    
    def test_create_project_missing_protected(self):
        """Test creating a project without required protected field"""
        user = AuthenticatedUser("testuser")
        project, error, status = create_project(
            user, "test-ns", protected=None
        )
        
        assert project is None
        assert status == 400
        assert "protected is required" in error.lower()
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.AuthorizationV1Api')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    @patch('lib.extension_api.projects.get_namespace')
    def test_update_project_success(self, mock_get_ns, mock_api_class, mock_auth_api_class, mock_config):
        """Test updating a project successfully"""
        # Setup mocks
        mock_get_ns.return_value = ({
            "name": "test-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {},
            "resource_version": "123"
        }, None)
        
        mock_auth_api = MagicMock()
        mock_auth_api_class.return_value = mock_auth_api
        mock_auth_result = MagicMock()
        mock_auth_result.status.allowed = True
        mock_auth_api.create_subject_access_review.return_value = mock_auth_result
        
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        mock_updated_ns = MagicMock()
        mock_updated_ns.metadata.name = "test-ns"
        mock_updated_ns.metadata.uid = "uid-123"
        mock_updated_ns.metadata.creation_timestamp = None
        mock_updated_ns.metadata.labels = {"env": "prod"}
        mock_updated_ns.metadata.annotations = {
            "metadata.k8s.io/owner": "newowner"
        }
        mock_updated_ns.metadata.resource_version = "124"
        mock_updated_ns.status.phase = "Active"
        mock_api.read_namespace.return_value = mock_updated_ns
        mock_api.patch_namespace.return_value = mock_updated_ns
        
        user = AuthenticatedUser("testuser")
        project, error, status = update_project(
            user, "test-ns", owner="newowner", labels={"env": "prod"}
        )
        
        assert error is None
        assert status == 200
        assert project is not None
        assert project["spec"]["owner"] == "newowner"
    
    @patch('lib.extension_api.projects.get_namespace')
    def test_update_project_not_found(self, mock_get_ns):
        """Test updating a non-existent project"""
        mock_get_ns.return_value = (None, "NotFound")
        
        user = AuthenticatedUser("testuser")
        project, error, status = update_project(user, "nonexistent", owner="newowner")
        
        assert project is None
        assert status == 404
        assert "not found" in error.lower()
    
    @patch('lib.extension_api.projects.k8sClientConfigGet')
    @patch('lib.extension_api.projects.k8s_client.AuthorizationV1Api')
    @patch('lib.extension_api.projects.k8s_client.CoreV1Api')
    @patch('lib.extension_api.projects.get_namespace')
    def test_delete_project_success(self, mock_get_ns, mock_api_class, mock_auth_api_class, mock_config):
        """Test deleting a project successfully"""
        # Setup mocks
        mock_get_ns.return_value = ({
            "name": "test-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {},  # Not protected
            "resource_version": "123"
        }, None)
        
        mock_auth_api = MagicMock()
        mock_auth_api_class.return_value = mock_auth_api
        mock_auth_result = MagicMock()
        mock_auth_result.status.allowed = True
        mock_auth_api.create_subject_access_review.return_value = mock_auth_result
        
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        user = AuthenticatedUser("testuser")
        status_obj, error, status = delete_project(user, "test-ns")
        
        assert error is None
        assert status == 200
        assert status_obj is not None
        assert status_obj["kind"] == "Status"
        assert status_obj["status"] == "Success"
        mock_api.delete_namespace.assert_called_once()
    
    @patch('lib.extension_api.projects.get_namespace')
    def test_delete_project_protected(self, mock_get_ns):
        """Test deleting a protected project"""
        mock_get_ns.return_value = ({
            "name": "protected-ns",
            "uid": "uid-123",
            "status": "Active",
            "labels": {},
            "annotations": {
                "kubedash.devopstales.github.io/protected": "true"
            },
            "resource_version": "123"
        }, None)
        
        user = AuthenticatedUser("testuser")
        status_obj, error, status = delete_project(user, "protected-ns")
        
        assert status_obj is None
        assert status == 403
        assert "protected" in error.lower()
        assert "cannot be deleted" in error.lower()
    
    @patch('lib.extension_api.projects.get_namespace')
    def test_delete_project_not_found(self, mock_get_ns):
        """Test deleting a non-existent project"""
        mock_get_ns.return_value = (None, "NotFound")
        
        user = AuthenticatedUser("testuser")
        status_obj, error, status = delete_project(user, "nonexistent")
        
        assert status_obj is None
        assert status == 404
        assert "not found" in error.lower()

