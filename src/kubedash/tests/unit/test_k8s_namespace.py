"""
Unit tests for Kubernetes namespace operations
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from kubernetes.client.rest import ApiException

from lib.k8s.namespace import k8sListNamespaces


class TestK8sListNamespaces:
    """Test namespace listing operations"""
    
    @patch('lib.k8s.namespace.k8sClientConfigGet')
    @patch('lib.k8s.namespace.k8s_client.CoreV1Api')
    def test_list_namespaces_success(self, mock_api_class, mock_config):
        """Test successful namespace listing"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Create mock namespace objects
        mock_ns1 = MagicMock()
        mock_ns1.metadata.name = "default"
        mock_ns1.metadata.uid = "ns-1"
        
        mock_ns2 = MagicMock()
        mock_ns2.metadata.name = "kube-system"
        mock_ns2.metadata.uid = "ns-2"
        
        mock_response = MagicMock()
        mock_response.items = [mock_ns1, mock_ns2]
        mock_api.list_namespace.return_value = mock_response
        
        # Use unique parameters to avoid cache hits from other tests
        # The function is cached, so we need unique params for each test
        unique_role = "TestAdmin_Success_Unique"
        unique_token = "test_token_success_unique"
        
        # Execute
        result, error = k8sListNamespaces(unique_role, unique_token)
        
        # Assert
        assert error is None
        assert result is not None
        assert len(result.items) == 2
        assert result.items[0].metadata.name == "default"
        assert result.items[1].metadata.name == "kube-system"
        mock_config.assert_called_once_with(unique_role, unique_token)
        mock_api.list_namespace.assert_called_once()
    
    @patch('lib.k8s.namespace.k8sClientConfigGet')
    @patch('lib.k8s.namespace.k8s_client.CoreV1Api')
    def test_list_namespaces_api_error_403(self, mock_api_class, mock_config):
        """Test namespace listing with 403 Forbidden error"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        api_exception = ApiException(status=403, reason="Forbidden")
        mock_api.list_namespace.side_effect = api_exception
        
        # Use unique parameters to avoid cache hits
        unique_role = "TestUser_403"
        unique_token = "test_token_403"
        
        # Execute
        result, error = k8sListNamespaces(unique_role, unique_token)
        
        # Assert
        assert error is not None
        assert result == ""
        assert error.status == 403
    
    @patch('lib.k8s.namespace.k8sClientConfigGet')
    @patch('lib.k8s.namespace.k8s_client.CoreV1Api')
    def test_list_namespaces_api_error_404(self, mock_api_class, mock_config):
        """Test namespace listing with 404 Not Found error (should not log)"""
        # Setup mock
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        api_exception = ApiException(status=404, reason="Not Found")
        mock_api.list_namespace.side_effect = api_exception
        
        # Use unique parameters to avoid cache hits
        unique_role = "TestAdmin_404"
        unique_token = "test_token_404"
        
        # Execute
        result, error = k8sListNamespaces(unique_role, unique_token)
        
        # Assert
        assert error is not None
        assert result == ""
        assert error.status == 404
    
    @patch('lib.k8s.namespace.k8sClientConfigGet')
    @patch('lib.k8s.namespace.k8s_client.CoreV1Api')
    def test_list_namespaces_connection_error(self, mock_api_class, mock_config):
        """Test namespace listing with connection error"""
        # Setup mock - the function does: k8s_client.CoreV1Api().list_namespace()
        mock_api_instance = MagicMock()
        mock_api_class.return_value = mock_api_instance
        
        # Use a generic Exception (not ApiException) to trigger the CannotConnect path
        connection_error = Exception("Cannot connect to Kubernetes")
        mock_api_instance.list_namespace.side_effect = connection_error
        
        # Use unique parameters to avoid cache hits from other tests
        # The cache key includes username_role and user_token
        unique_role = "TestAdmin_ConnectionError"
        unique_token = "test_token_connection_error"
        
        # Execute
        result, error = k8sListNamespaces(unique_role, unique_token)
        
        # Assert - the function catches generic Exception and returns "CannotConnect"
        assert error == "CannotConnect"
        assert result == ""


class TestK8sNamespaceListGet:
    """Test getting namespace list as names"""
    
    @patch('lib.k8s.namespace.k8sListNamespaces')
    def test_namespace_list_get_success(self, mock_list):
        """Test successful namespace list retrieval"""
        from lib.k8s.namespace import k8sNamespaceListGet
        
        # Setup mock
        mock_ns1 = MagicMock()
        mock_ns1.metadata.name = "default"
        mock_ns2 = MagicMock()
        mock_ns2.metadata.name = "kube-system"
        
        mock_response = MagicMock()
        mock_response.items = [mock_ns1, mock_ns2]
        mock_list.return_value = (mock_response, None)
        
        # Execute
        result, error = k8sNamespaceListGet("Admin", None)
        
        # Assert
        assert error is None
        assert result == ["default", "kube-system"]
    
    @patch('lib.k8s.namespace.k8sClientConfigGet')
    @patch('lib.k8s.namespace.k8sListNamespaces')
    def test_namespace_list_get_error(self, mock_list, mock_config):
        """Test namespace list retrieval with error"""
        from lib.k8s.namespace import k8sNamespaceListGet
        
        # Setup mock - k8sNamespaceListGet calls k8sClientConfigGet first
        mock_config.return_value = None
        mock_list.return_value = ("", ApiException(status=403, reason="Forbidden"))
        
        # Execute
        result, error = k8sNamespaceListGet("User", "token")
        
        # Assert
        assert error is not None
        assert result == []

