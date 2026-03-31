#!/usr/bin/env python3
"""
K8sGPT integration for AI Chat plugin.

Diagnostics stubs (MCP integration removed). Cluster operations use lib/k8s via k8s_adapter.
"""

from typing import Dict, Any, List, Optional
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

logger = get_logger()
tracer = get_tracer()

_NOT_CONFIGURED_MSG = "K8sGPT diagnostics are not configured (MCP integration has been removed). Use 'list pods', 'describe pod', or 'get logs' for inspection."


class K8sGPTDiagnostics:
    """
    K8sGPT diagnostics placeholder.

    MCP integration has been removed; methods return a not-configured message.
    """

    def __init__(self, mcp_url: str, timeout: int = 120):
        self.mcp_url = mcp_url.rstrip('/')
        self.timeout = timeout

    def analyze(self, namespace: Optional[str] = None) -> Dict[str, Any]:
        """
        Run K8sGPT analysis on the cluster.

        Args:
            namespace: Optional namespace to analyze (None = all namespaces)

        Returns:
            Analysis results with problems and recommendations
        """
        return {"message": _NOT_CONFIGURED_MSG, "problems": []}

    def diagnose_resource(self, kind: str, name: str, namespace: str) -> Dict[str, Any]:
        """
        Diagnose a specific Kubernetes resource.

        Args:
            kind: Resource kind (Pod, Deployment, Service, etc.)
            name: Resource name
            namespace: Resource namespace

        Returns:
            Diagnostic results for the resource
        """
        return {"message": _NOT_CONFIGURED_MSG}

    def get_problems_summary(self, namespace: Optional[str] = None) -> str:
        """Get a human-readable summary of cluster problems."""
        return _NOT_CONFIGURED_MSG

    def troubleshoot_pod(self, name: str, namespace: str) -> str:
        """Troubleshoot a specific pod."""
        return _NOT_CONFIGURED_MSG


# Global K8sGPT client instance
_k8sgpt_client: Optional[K8sGPTDiagnostics] = None


def get_k8sgpt_client(mcp_url: Optional[str] = None) -> Optional[K8sGPTDiagnostics]:
    """
    Get or create K8sGPT diagnostics client.

    Args:
        mcp_url: Optional K8sGPT MCP server URL

    Returns:
        K8sGPTDiagnostics instance or None if not configured
    """
    global _k8sgpt_client

    if mcp_url:
        _k8sgpt_client = K8sGPTDiagnostics(mcp_url)
        return _k8sgpt_client

    return _k8sgpt_client


def run_diagnostics_intent(intent: Dict, mcp_url: str) -> str:
    """
    Run K8sGPT diagnostics based on detected intent.

    Args:
        intent: Detected intent dictionary
        mcp_url: K8sGPT MCP server URL

    Returns:
        Diagnostic results as string
    """
    client = get_k8sgpt_client(mcp_url)
    if not client:
        return "K8sGPT diagnostics is not configured."

    intent_type = intent.get('type', '')
    params = intent.get('params', {})

    if intent_type == 'diagnose_cluster':
        return client.get_problems_summary(params.get('namespace'))
    elif intent_type == 'diagnose_pod':
        return client.troubleshoot_pod(
            params.get('name'),
            params.get('namespace', 'default')
        )
    elif intent_type == 'diagnose_deployment':
        return client.troubleshoot_pod(
            params.get('name'),
            params.get('namespace', 'default')
        )
    else:
        return "K8sGPT diagnostics can help with:\n" \
               "- `diagnose cluster` - Analyze entire cluster\n" \
               "- `diagnose pod <name>` - Troubleshoot specific pod\n" \
               "- `diagnose deployment <name>` - Troubleshoot deployment"
