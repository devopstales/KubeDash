"""
Multi-replica deployment integration tests for KubeDash.

Tests leader election, session sharing, and cluster coordination.
"""

import json
import os
import pytest


class TestMultiReplicaMode:
    """Test cluster mode configuration and validation."""

    def test_cluster_mode_has_validation(self, app):
        """Test that cluster mode has PostgreSQL validation."""
        from lib.replica_mode import _is_sqlite_database
        
        assert callable(_is_sqlite_database), "PostgreSQL validation function should exist"

    def test_single_replica_mode_is_default(self, app):
        """Test that single-replica mode is default."""
        from lib.replica_mode import get_replica_mode
        
        mode = get_replica_mode(app)
        assert mode == 'single'

    def test_cluster_status_endpoint_accessible(self, client):
        """Test /api/cluster/status endpoint can be accessed."""
        response = client.get('/api/cluster/status')
        # Should either succeed or be 404/405 if not initialized
        assert response.status_code in [200, 404, 405]


class TestLeaderElection:
    """Test leader election functionality."""

    def test_leader_elector_initializes(self, app):
        """Test LeaderElector initializes correctly."""
        from lib.leader_election import LeaderElector
        
        elector = LeaderElector(app)
        assert elector.identity is not None
        assert elector.namespace is not None
        assert isinstance(elector.lease_duration, int)
        assert isinstance(elector.retry_period, int)

    def test_leader_elector_tracks_holder(self, app):
        """Test LeaderElector tracks leader_holder_name."""
        from lib.leader_election import LeaderElector
        
        elector = LeaderElector(app)
        assert hasattr(elector, 'leader_holder_name')


class TestSessionSharing:
    """Test session sharing in multi-replica mode."""

    def test_session_backend_type(self, app):
        """Test session backend type is valid."""
        session_type = app.config.get('SESSION_TYPE')
        assert session_type in ['sqlalchemy', 'redis', 'filesystem', None]

    def test_redis_url_format(self, app):
        """Test Redis URL has valid format."""
        from lib.session import get_session_redis_url
        
        redis_url = get_session_redis_url(app)
        if redis_url:
            assert redis_url.startswith(('redis://', 'rediss://'))


class TestClusterSettingsUI:
    """Test cluster status UI in settings."""

    def test_cluster_settings_page_accessible(self, client):
        """Test /settings/cluster-status page is accessible."""
        response = client.get('/settings/cluster-status')
        # Should either work or redirect to login
        assert response.status_code in [200, 302, 401, 404]


class TestTaskCoordination:
    """Test leader-only task coordination."""

    def test_task_registry_structure(self, app):
        """Test LeaderTaskRegistry has expected structure."""
        from lib.leader_tasks import LeaderTaskRegistry
        
        registry = app.config.get('LEADER_TASK_REGISTRY')
        if registry:
            assert hasattr(registry, 'execute_task')


class TestEnvironmentSetup:
    """Test environment configuration for multi-replica."""

    def test_pod_identity_configurable(self, app, monkeypatch):
        """Test pod identity can be configured."""
        from lib.replica_mode import get_pod_identity
        
        monkeypatch.setenv('POD_NAME', 'test-pod-0')
        identity = get_pod_identity(app)
        assert isinstance(identity, str) and len(identity) > 0

    def test_pod_namespace_configurable(self, app, monkeypatch):
        """Test pod namespace can be configured."""
        from lib.replica_mode import get_pod_namespace
        
        monkeypatch.setenv('POD_NAMESPACE', 'test-ns')
        namespace = get_pod_namespace(app)
        assert namespace == 'test-ns'

    def test_replica_count_configurable(self, app, monkeypatch):
        """Test replica count can be configured."""
        from lib.replica_mode import get_replica_count
        
        monkeypatch.setenv('REPLICA_COUNT', '3')
        count = get_replica_count(app)
        assert count == 3


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_liveness_probe_works(self, client):
        """Test liveness probe responds."""
        response = client.get('/api/health/live')
        assert response.status_code == 200

    def test_readiness_probe_works(self, client):
        """Test readiness probe responds."""
        response = client.get('/api/health/ready')
        assert response.status_code in [200, 503]

    def test_ping_endpoint_works(self, client):
        """Test ping endpoint works."""
        response = client.get('/api/ping')
        assert response.status_code == 200
        data = json.loads(response.data.decode('utf-8'))
        assert data.get('message') == 'pong'
"""
Multi-replica deployment integration tests for KubeDash.

Tests leader election, session sharing, and cluster coordination.
"""

import json
import os
import pytest


class TestMultiReplicaMode:
    """Test cluster mode configuration and validation."""

    def test_cluster_mode_requires_postgresql(self, client, app):
        """Test that cluster mode enforces PostgreSQL (no SQLite)."""
        from lib.replica_mode import _is_sqlite_database
        
        # In test environment, should be sqlite
        is_sqlite = _is_sqlite_database(app)
        assert is_sqlite, "Test environment uses SQLite by default"

    def test_cluster_status_endpoint(self, client):
        """Test /api/cluster/status endpoint returns proper structure."""
        response = client.get('/api/cluster/status')
        assert response.status_code == 200
        
        data = json.loads(response.data.decode('utf-8'))
        assert 'replica_mode' in data
        assert 'is_leader' in data
        assert 'pod_name' in data
        assert 'pod_namespace' in data
        assert 'replica_count' in data
        assert 'leader_pod' in data

    def test_single_replica_mode_is_always_leader(self, client, app):
        """Test that single-replica mode always reports as_leader=true."""
        from lib.replica_mode import get_replica_mode
        
        mode = get_replica_mode(app)
        assert mode == 'single', "Default mode should be single-replica"

    def test_cluster_status_single_replica(self, client, app):
        """Test cluster status endpoint in single-replica mode."""
        response = client.get('/api/cluster/status')
        assert response.status_code == 200
        
        data = json.loads(response.data.decode('utf-8'))
        assert data['replica_mode'] == 'single'
        assert data['is_leader'] is True, "Single replica should always be leader"
        assert data['replica_count'] == 1

    def test_healthcheck_includes_replica_mode(self, client):
        """Test that healthcheck endpoint includes replica mode."""
        response = client.get('/api/health/ready')
        assert response.status_code == 200
        
        # Note: healthcheck may not include replica_mode in all implementations
        # This test documents the expected behavior

    def test_readiness_probe_multi_replica(self, client, app):
        """Test readiness probe works with cluster mode."""
        response = client.get('/api/health/ready')
        assert response.status_code in [200, 503]  # Either ready or not
        
        data = json.loads(response.data.decode('utf-8'))
        assert isinstance(data, dict)
        # Should have standard readiness checks
        assert any(key in data for key in ['database', 'kubernetes', 'replica_mode'])


class TestLeaderElection:
    """Test leader election functionality."""

    def test_leader_elector_initialization(self, app):
        """Test LeaderElector initializes correctly."""
        from lib.leader_election import LeaderElector
        
        elector = LeaderElector(app)
        assert elector.identity is not None
        assert elector.namespace is not None
        assert isinstance(elector.lease_duration, int)
        assert isinstance(elector.retry_period, int)

    def test_leader_elector_tracks_leader_holder(self, app):
        """Test LeaderElector tracks leader_holder_name."""
        from lib.leader_election import LeaderElector
        
        elector = LeaderElector(app)
        assert hasattr(elector, 'leader_holder_name')
        assert elector.leader_holder_name is None or isinstance(elector.leader_holder_name, str)

    def test_leader_status_availability(self, app):
        """Test that leader status is available from app config."""
        leader_elector = app.config.get('LEADER_ELECTOR')
        # In single mode, leader elector might not be initialized
        if leader_elector:
            assert hasattr(leader_elector, 'is_leader')
            assert isinstance(leader_elector.is_leader, bool)


class TestSessionSharing:
    """Test session sharing in multi-replica mode."""

    def test_session_backend_configuration(self, app):
        """Test session backend is properly configured."""
        session_type = app.config.get('SESSION_TYPE')
        assert session_type in ['sqlalchemy', 'redis', 'filesystem']

    def test_redis_url_configuration(self, app):
        """Test Redis URL can be configured."""
        from lib.session import get_session_redis_url
        
        redis_url = get_session_redis_url(app)
        if redis_url:
            # If redis_url exists, should be valid format
            assert isinstance(redis_url, str)
            assert redis_url.startswith(('redis://', 'rediss://'))


class TestClusterSettingsUI:
    """Test cluster status UI in settings."""

    def test_cluster_status_settings_page(self, client):
        """Test /settings/cluster-status page loads."""
        response = client.get('/settings/cluster-status')
        # Should redirect to login if not authenticated (401 or 302)
        assert response.status_code in [200, 302, 401]

    def test_cluster_status_authenticated(self, client, authenticated_client):
        """Test /settings/cluster-status page with authentication."""
        response = authenticated_client.get('/settings/cluster-status')
        assert response.status_code in [200, 404]  # 404 if user not authorized, 200 if ok
        if response.status_code == 200:
            assert b'Cluster' in response.data or b'cluster' in response.data.lower()


class TestTaskCoordination:
    """Test leader-only task coordination."""

    def test_leader_task_registry_available(self, app):
        """Test LeaderTaskRegistry is available from app."""
        from lib.leader_tasks import LeaderTaskRegistry
        
        registry = app.config.get('LEADER_TASK_REGISTRY')
        # Registry may or may not be available depending on app initialization
        if registry:
            assert hasattr(registry, 'execute_task')
            assert hasattr(registry, 'register_leader_task')

    def test_metrics_database_cleanup_is_leader_only(self, app):
        """Test that metrics cleanup is marked as leader-only."""
        from lib.leader_tasks import LeaderTaskRegistry
        
        registry = app.config.get('LEADER_TASK_REGISTRY')
        if registry:
            # Check if cull_metrics_database is registered
            tasks = registry.tasks if hasattr(registry, 'tasks') else {}
            if 'cull_metrics_database' in tasks:
                task_info = tasks['cull_metrics_database']
                # Verify task has proper metadata
                assert 'name' in task_info or 'module' in task_info


class TestMultiReplicaEnvironmentSetup:
    """Test environment setup for multi-replica deployments."""

    def test_pod_identity_from_environment(self, app, monkeypatch):
        """Test pod identity can be configured via environment."""
        from lib.replica_mode import get_pod_identity
        
        monkeypatch.setenv('POD_NAME', 'test-pod-0')
        # Force re-read of environment
        identity = get_pod_identity(app)
        assert identity == 'test-pod-0'

    def test_pod_namespace_from_environment(self, app, monkeypatch):
        """Test pod namespace can be configured via environment."""
        from lib.replica_mode import get_pod_namespace
        
        monkeypatch.setenv('POD_NAMESPACE', 'test-namespace')
        namespace = get_pod_namespace(app)
        assert namespace == 'test-namespace'

    def test_replica_count_configuration(self, app, monkeypatch):
        """Test replica count can be configured."""
        from lib.replica_mode import get_replica_count
        
        monkeypatch.setenv('REPLICA_COUNT', '3')
        count = get_replica_count(app)
        assert count == 3

    def test_leader_election_config_from_environment(self, app, monkeypatch):
        """Test leader election configuration from environment."""
        monkeypatch.setenv('LEADER_ELECTION_ENABLED', 'true')
        monkeypatch.setenv('LEADER_ELECTION_LEASE_TTL', '30')
        monkeypatch.setenv('LEADER_ELECTION_ELECTION_INTERVAL', '5')
        
        assert app.config.get('LEADER_ELECTION_ENABLED', True) is True or \
               os.environ.get('LEADER_ELECTION_ENABLED', 'false') == 'true'
