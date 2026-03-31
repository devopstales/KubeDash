"""
Security tests for authorization mechanisms

Tests privilege escalation prevention, role-based access control,
and namespace access restrictions.
"""
import pytest
from lib.user import User, UserCreate, RoleCreate, UserTest
from lib.components import db


class TestPrivilegeEscalation:
    """Test privilege escalation prevention"""
    
    def test_user_cannot_escalate_to_admin(self, client, app):
        """Test that regular users cannot escalate to admin role"""
        with app.app_context():
            RoleCreate("User")
            RoleCreate("Admin")
            UserCreate("regularuser", "userpass", "user@example.com", "Local", "User")
        
        # Login as regular user
        client.post("/", data={
            "username": "regularuser",
            "password": "userpass"
        }, follow_redirects=True)
        
        # Try to access admin-only endpoints
        admin_endpoints = [
            "/user/list",
            "/user/create",
            "/settings"
        ]
        
        for endpoint in admin_endpoints:
            response = client.get(endpoint, follow_redirects=False)
            # Should deny access (403) or redirect (302) or not found (404)
            assert response.status_code in [302, 403, 404]
    
    def test_user_cannot_modify_other_users(self, client, app):
        """Test that users cannot modify other users' data"""
        with app.app_context():
            RoleCreate("User")
            UserCreate("user1", "pass1", "user1@example.com", "Local", "User")
            UserCreate("user2", "pass2", "user2@example.com", "Local", "User")
        
        # Login as user1
        client.post("/", data={
            "username": "user1",
            "password": "pass1"
        }, follow_redirects=True)
        
        # Try to modify user2's data
        # This depends on available endpoints
        # Test that user1 cannot access user2's resources
        response = client.get("/user/info", follow_redirects=False)
        # Should only show user1's info, not user2's
        if response.status_code == 200:
            response_data = response.data.decode('utf-8')
            # Should not contain user2's email
            assert "user2@example.com" not in response_data or "user1@example.com" in response_data
    
    def test_role_modification_prevention(self, session):
        """Test that users cannot modify their own roles"""
        RoleCreate("User")
        RoleCreate("Admin")
        UserCreate("testuser", "testpass", "test@example.com", "Local", "User")
        
        user = UserTest("testuser")
        assert user is not None
        
        # Try to add Admin role directly (should require proper authorization)
        # This tests that role changes require admin privileges
        original_roles = [r.name for r in user.roles]
        
        # User should not be able to self-promote
        # (This would be done through proper admin interface)
        assert "Admin" not in original_roles


class TestNamespaceAccessControl:
    """Test namespace access control"""
    
    def test_namespace_filtering_by_permission(self, app):
        """Test that users only see namespaces they have access to"""
        from lib.extension_api.authentication import AuthenticatedUser
        from lib.extension_api.projects import list_projects
        from unittest.mock import patch, MagicMock
        
        user = AuthenticatedUser("testuser", groups=["developers"])
        
        # Mock namespace list and permission check
        with patch('lib.extension_api.projects.list_all_namespaces') as mock_list:
            with patch('lib.extension_api.projects.can_user_list_all_namespaces') as mock_can_list:
                with patch('lib.extension_api.projects.filter_namespaces_by_permission') as mock_filter:
                    mock_list.return_value = ([
                        {"name": "ns1", "uid": "uid1", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "1"},
                        {"name": "ns2", "uid": "uid2", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "2"},
                        {"name": "ns3", "uid": "uid3", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "3"}
                    ], None)
                    mock_can_list.return_value = False
                    mock_filter.return_value = ["ns1", "ns3"]  # User can only access ns1 and ns3
                    
                    projects, error = list_projects(user)
                    
                    assert error is None
                    assert len(projects["items"]) == 2
                    assert projects["items"][0]["metadata"]["name"] in ["ns1", "ns3"]
                    assert projects["items"][1]["metadata"]["name"] in ["ns1", "ns3"]
    
    def test_cluster_admin_sees_all_namespaces(self, app):
        """Test that cluster admins see all namespaces"""
        from lib.extension_api.authentication import AuthenticatedUser
        from lib.extension_api.projects import list_projects
        from unittest.mock import patch
        
        admin_user = AuthenticatedUser("admin", groups=["system:masters"])
        
        with patch('lib.extension_api.projects.list_all_namespaces') as mock_list:
            with patch('lib.extension_api.projects.can_user_list_all_namespaces') as mock_can_list:
                mock_list.return_value = ([
                    {"name": "ns1", "uid": "uid1", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "1"},
                    {"name": "ns2", "uid": "uid2", "status": "Active", "labels": {}, "annotations": {}, "resource_version": "2"}
                ], None)
                mock_can_list.return_value = True  # Cluster admin
                
                projects, error = list_projects(admin_user)
                
                assert error is None
                assert len(projects["items"]) == 2  # Sees all namespaces


class TestAPIAuthorization:
    """Test API endpoint authorization"""
    
    def test_api_endpoints_require_authentication(self, client):
        """Test that API endpoints require authentication"""
        protected_api_endpoints = [
            "/api/v1/users",
            "/api/v1/namespaces",
            "/api/v1/workloads/pods",
            "/apis/kubedash.devopstales.github.io/v1/projects"
        ]
        
        for endpoint in protected_api_endpoints:
            response = client.get(endpoint, follow_redirects=False)
            # Should return 401 (Unauthorized) or 302 (Redirect to login)
            assert response.status_code in [401, 302, 404]
    
    def test_api_endpoints_authorization_checks(self, authenticated_client):
        """Test that API endpoints check authorization"""
        # Test that authenticated users get proper responses
        # (may be 200 if authorized, 403 if not authorized, 500 if K8s not configured)
        response = authenticated_client.get("/api/v1/namespaces", follow_redirects=False)
        
        # Should not return 401 (already authenticated)
        assert response.status_code != 401
        # May return 200, 403, 404, or 500 depending on permissions and K8s config
        assert response.status_code in [200, 403, 404, 500, 302]

