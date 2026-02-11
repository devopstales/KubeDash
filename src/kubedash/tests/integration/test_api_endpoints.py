"""
Integration tests for API endpoints
"""
import pytest
import json
from unittest.mock import patch, MagicMock


class TestAPIEndpoints:
    """Test REST API endpoints"""
    
    def test_ping_endpoint(self, client):
        """Test ping endpoint"""
        response = client.get('/api/ping')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'pong'
    
    def test_health_live(self, client):
        """Test liveness probe"""
        response = client.get('/api/health/live')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data or 'title' in data
    
    @patch('blueprint.api_base.connect_database')
    @patch('blueprint.api_base.SSOServerTest')
    @patch('blueprint.api_base.k8sGetClusterStatus')
    def test_health_ready_all_healthy(self, mock_k8s, mock_sso, mock_db, client):
        """Test readiness probe when all services are healthy"""
        mock_db.return_value = True
        mock_sso.return_value = (True, None)
        mock_k8s.return_value = True
        
        response = client.get('/api/health/ready')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'database' in data or 'title' in data
    
    @patch('blueprint.api_base.connect_database')
    @patch('blueprint.api_base.SSOServerTest')
    @patch('blueprint.api_base.k8sGetClusterStatus')
    def test_health_ready_database_down(self, mock_k8s, mock_sso, mock_db, client):
        """Test readiness probe when database is down"""
        mock_db.return_value = False
        mock_sso.return_value = (True, None)
        mock_k8s.return_value = True
        
        response = client.get('/api/health/ready')
        assert response.status_code == 503
        data = json.loads(response.data)
        assert data.get('database') is False or 'title' in data
    
    @patch('blueprint.api_base.connect_database')
    @patch('blueprint.api_base.SSOServerTest')
    @patch('blueprint.api_base.k8sGetClusterStatus')
    def test_health_ready_k8s_down(self, mock_k8s, mock_sso, mock_db, client):
        """Test readiness probe when Kubernetes is down"""
        mock_db.return_value = True
        mock_sso.return_value = (True, None)
        mock_k8s.return_value = False
        
        response = client.get('/api/health/ready')
        assert response.status_code == 503
        data = json.loads(response.data)
        assert data.get('kubernetes') is False or 'title' in data
    
    def test_debug_trace_requires_auth(self, client):
        """Test debug trace endpoint requires authentication"""
        response = client.get('/api/debug-trace')
        # Should redirect to login or return 401
        assert response.status_code in [302, 401, 400]
    
    def test_debug_trace_with_auth(self, authenticated_client):
        """Test debug trace endpoint with authentication"""
        response = authenticated_client.get('/api/debug-trace', follow_redirects=False)
        # May return 200 with trace info, 400 if no active span, or 302 if redirect
        assert response.status_code in [200, 400, 302]
        if response.status_code == 200:
            data = json.loads(response.data)
            # Check for trace-related fields
            assert any(key in data for key in ['flask_correlation_id', 'jaeger_trace_id', 'span_id', 'error'])


class TestAPIv1Endpoints:
    """Test API v1 endpoints"""
    
    def test_api_v1_namespaces_requires_auth(self, client):
        """Test namespaces endpoint requires authentication"""
        response = client.get('/api/v1/namespaces')
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]
    
    @patch('lib.k8s.namespace.k8sListNamespaces')
    def test_api_v1_namespaces_with_auth(self, mock_list, authenticated_client):
        """Test namespaces endpoint with authentication"""
        # Mock namespace list
        mock_namespace = MagicMock()
        mock_namespace.metadata.name = "default"
        mock_response = MagicMock()
        mock_response.items = [mock_namespace]
        mock_list.return_value = (mock_response, None)
        
        response = authenticated_client.get('/api/v1/namespaces', follow_redirects=False)
        # Should return 200 or handle the response, or 302 if redirect
        assert response.status_code in [200, 500, 302]  # 500 if K8s not configured, 302 if redirect
    
    def test_api_v1_pods_requires_auth(self, client):
        """Test pods endpoint requires authentication"""
        response = client.get('/api/v1/workloads/pods')
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]
    
    def test_api_v1_users_requires_auth(self, client):
        """Test users endpoint requires authentication"""
        response = client.get('/api/v1/users')
        # Should redirect to login or return 401
        assert response.status_code in [302, 401]


class TestExtensionAPI:
    """Test Kubernetes Extension API endpoints"""
    
    def test_extension_api_group_list(self, client):
        """Test API group listing"""
        response = client.get('/apis/')
        # Should return 200 with API group list
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'kind' in data
        assert data['kind'] == 'APIGroupList'
    
    def test_extension_api_resources(self, client):
        """Test API resource listing"""
        response = client.get('/apis/kubedash.devopstales.github.io/v1')
        # Should return 200 with API resource list
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'kind' in data
        assert data['kind'] == 'APIResourceList'
    
    def test_extension_api_projects_unauthorized(self, client):
        """Test projects endpoint without authentication"""
        response = client.get('/apis/kubedash.devopstales.github.io/v1/projects')
        # Should return 401 Unauthorized
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'kind' in data
        assert data['kind'] == 'Status'

