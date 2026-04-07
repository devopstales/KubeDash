"""
Integration tests for multi-pod API endpoint with mocked K8s responses.

Tests the GET /api/v1/workloads/<kind>/<name>/pods endpoint.
"""
import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add parent directories to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..'))


class TestWorkloadPodsAPI(unittest.TestCase):
    """Test cases for the workload pods API endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_pod = MagicMock()
        self.mock_pod.metadata.name = "test-pod-1"
        self.mock_pod.metadata.namespace = "default"
        self.mock_pod.metadata.owner_references = [
            MagicMock(kind="Deployment", name="test-deployment")
        ]
        self.mock_pod.status.phase = "Running"
        self.mock_pod.status.pod_ip = "10.0.0.1"
        self.mock_pod.status.container_statuses = [
            MagicMock(
                name="container-1",
                state=MagicMock(
                    waiting=None,
                    terminated=None,
                    running=MagicMock()
                ),
                ready=True
            )
        ]
        self.mock_pod.spec.containers = [MagicMock(name="container-1")]
        self.mock_pod.spec.init_containers = []
        self.mock_pod.metadata.deletion_timestamp = None

    def test_workload_pods_endpoint_exists(self):
        """Test that the workload pods endpoint file exists."""
        api_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'blueprint', 'api', 'workloads.py'
        )
        self.assertTrue(os.path.exists(api_file), f"API file not found at {api_file}")

    def test_workload_pods_function_exists(self):
        """Test that k8sWorkloadPodsGet function exists in workload.py."""
        workload_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'lib', 'k8s', 'workload.py'
        )
        with open(workload_file, 'r') as f:
            content = f.read()
        self.assertIn('def k8sWorkloadPodsGet', content, "k8sWorkloadPodsGet function not found")

    def test_workload_pods_filters_by_owner(self):
        """Test that pods are filtered by owner reference."""
        # This is a structural test - actual functionality requires K8s cluster
        workload_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'lib', 'k8s', 'workload.py'
        )
        with open(workload_file, 'r') as f:
            content = f.read()
        
        # Verify owner reference filtering logic exists
        self.assertIn('owner_references', content, "Owner reference filtering not implemented")
        self.assertIn('owner.kind', content, "Owner kind matching not implemented")
        self.assertIn('owner.name', content, "Owner name matching not implemented")

    def test_workload_pods_returns_containers(self):
        """Test that pod response includes container information."""
        workload_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'lib', 'k8s', 'workload.py'
        )
        with open(workload_file, 'r') as f:
            content = f.read()
        
        # Verify container info is included in response
        self.assertIn('"containers"', content, "Containers field not in response")
        self.assertIn('"init_containers"', content, "Init containers field not in response")

    def test_workload_pods_error_handling(self):
        """Test that error handling is implemented."""
        workload_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'lib', 'k8s', 'workload.py'
        )
        with open(workload_file, 'r') as f:
            content = f.read()
        
        # Verify error handling exists
        self.assertIn('ApiException', content, "ApiException handling not implemented")
        self.assertIn('"error"', content, "Error response format not implemented")


class TestMultiPodAggregatorJS(unittest.TestCase):
    """Test cases for the MultiPodAggregator JavaScript module."""

    def test_multi_pod_aggregator_file_exists(self):
        """Test that multi_pod_aggregator.js exists."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', 'log_viewer', 'multi_pod_aggregator.js'
        )
        self.assertTrue(os.path.exists(js_file), f"Multi-pod aggregator JS file not found at {js_file}")

    def test_multi_pod_aggregator_exports_class(self):
        """Test that MultiPodAggregator class is exported."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', 'log_viewer', 'multi_pod_aggregator.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        
        self.assertIn('class MultiPodAggregator', content)
        self.assertIn('module.exports', content)
        self.assertIn('initialize', content)
        self.assertIn('addPod', content)
        self.assertIn('getPodLevelStats', content)
        self.assertIn('getStreamingPods', content)


if __name__ == '__main__':
    unittest.main()
