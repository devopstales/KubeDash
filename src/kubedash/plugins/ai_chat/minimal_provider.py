#!/usr/bin/env python3
"""
Minimal chat provider for local mode.

Pattern-based chatbot that works without external LLM dependencies.
Uses intent detection and MCP tool calls for Kubernetes operations.
"""

import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from lib.helper_functions import get_logger

logger = get_logger()


@dataclass
class LLMResponse:
    """Response from chat provider."""
    content: str
    tool_calls: Optional[List[Dict]] = None
    model: str = "minimal"
    usage: Optional[Dict] = None


class MinimalChatbotProvider:
    """
    Pattern-based chatbot for local mode (no LLM).

    Detects intents from user messages and executes corresponding
    Kubernetes operations via MCP or direct function calls.
    """

    # Intent patterns with regex
    PATTERNS = {
        # Greetings
        'greeting': r'\b(hi|hello|hey|greetings|good\s+(morning|afternoon|evening))\b',

        # Namespace operations
        'list_namespaces': r'\b(list|show|get|display)\s+(namespaces|ns)\b',

        # Pod operations (pods stay separate)
        'list_pods': r'\b(list|show|get|display)\s+(pods|pod)\b(?:\s+in\s+(\S+))?',
        'describe_pod': r'\b(describe|show\s+details?|get\s+details?|inspect)\s+pod\s+(\S+)(?:\s+in\s+(\S+))?',
        'get_logs': r'\b(logs?|show\s+logs?|get\s+logs?)\s+(?:for\s+)?pod\s+(\S+)(?:\s+in\s+(\S+))?',

        # Generic list/get for all other resources (deployment, service, configmap, secret, daemonset, statefulset)
        'resources_list': r'\b(list|show|get|display)\s+(deployments?|daemonsets?|statefulsets?|services?|configmaps?|cm|secrets?)\b(?:\s+in\s+(\S+))?',
        'resources_get': r'\b(describe|show\s+details?|get\s+details?|inspect)\s+(deployment|daemonset|statefulset|service|configmap|secret)\s+(\S+)(?:\s+in\s+(\S+))?',

        # Helm operations (list releases, helm list, list helm [releases], in <ns>)
        'helm_list': r'\b(helm\s+)?(list\s+releases?|releases?|helm\s+list|list\s+helm(?:\s+releases?)?)\b(?:\s+in\s+(\S+))?',

        # Create operations
        'create_namespace': r'\b(create|make)\s+namespace\s+(\S+)',

        # Delete operations
        'delete_pod': r'\b(delete|remove|kill)\s+pod\s+(\S+)(?:\s+in\s+(\S+))?',
        'delete_deployment': r'\b(delete|remove)\s+deployment\s+(\S+)(?:\s+in\s+(\S+))?',

        # Help
        'help': r'\b(help|what\s+can\s+you\s+do|commands|available\s+commands)\b',
    }

    def __init__(self):
        """Initialize minimal chatbot provider (uses k8s_adapter -> lib/k8s)."""

    async def chat(self, messages: List[Dict], tools: Optional[List] = None) -> LLMResponse:
        """
        Process chat message and return response.

        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions (not used in minimal mode)

        Returns:
            LLMResponse with content
        """
        if not messages:
            return LLMResponse(content="Please provide a message.")

        user_message = messages[-1]['content']
        intent = self._detect_intent(user_message)

        if not intent:
            return LLMResponse(
                content="I didn't understand that command. Try:\n\n"
                        "- 'list pods in default'\n"
                        "- 'show logs for pod my-pod'\n"
                        "- 'list namespaces'\n"
                        "- 'create namespace my-ns'"
            )

        # Execute the detected intent
        result = await self._execute_intent(intent, user_message, messages)
        return LLMResponse(content=result)

    def _detect_intent(self, message: str) -> Optional[Dict[str, Any]]:
        """
        Detect user intent from message.

        Args:
            message: User message

        Returns:
            Intent dict with type, groups, and parameters
        """
        message_lower = message.lower()

        for intent_type, pattern in self.PATTERNS.items():
            match = re.search(pattern, message_lower, re.IGNORECASE)
            if match:
                groups = match.groups()

                intent = {
                    'type': intent_type,
                    'groups': groups,
                    'original': message,
                }

                # Extract parameters based on intent type
                self._extract_intent_parameters(intent, groups)

                logger.debug("Detected intent: %s with params: %s", intent_type, intent.get('params', {}))
                return intent

        return None

    def _extract_intent_parameters(self, intent: Dict, groups: tuple):
        """Extract parameters from regex groups based on intent type."""
        intent_type = intent['type']
        params = {}

        if intent_type == 'list_pods':
            # Pattern: (verb)\s+(pods|pod)\b(?:\s+in\s+(namespace))? -> namespace is groups[2]
            params['namespace'] = groups[2] if len(groups) > 2 and groups[2] else 'default'

        elif intent_type in ('describe_pod', 'delete_pod'):
            params['name'] = groups[0] if groups else None
            params['namespace'] = groups[1] if len(groups) > 1 and groups[1] else 'default'

        elif intent_type == 'get_logs':
            params['name'] = groups[0] if groups else None
            params['namespace'] = groups[1] if len(groups) > 1 and groups[1] else 'default'

        elif intent_type == 'resources_list':
            # Pattern: (verb)\s+(resource_type)\b(?:\s+in\s+(namespace))? -> groups[1]=resource_type, groups[2]=namespace
            params['resource_type'] = groups[1] if len(groups) > 1 and groups[1] else None
            params['namespace'] = groups[2] if len(groups) > 2 and groups[2] else 'default'

        elif intent_type == 'resources_get':
            # Pattern: (verb)\s+(resource_type)\s+(name)(?:\s+in\s+(namespace))? -> groups[1]=resource_type, groups[2]=name, groups[3]=namespace
            params['resource_type'] = groups[1] if len(groups) > 1 and groups[1] else None
            params['name'] = groups[2] if len(groups) > 2 and groups[2] else None
            params['namespace'] = groups[3] if len(groups) > 3 and groups[3] else 'default'

        elif intent_type == 'delete_deployment':
            params['name'] = groups[0] if groups else None
            params['namespace'] = groups[1] if len(groups) > 1 and groups[1] else 'default'

        elif intent_type == 'helm_list':
            params['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None

        elif intent_type == 'create_namespace':
            params['name'] = groups[0] if groups else None

        intent['params'] = params

    async def _execute_intent(self, intent: Dict, message: str, messages: List[Dict]) -> str:
        """
        Execute detected intent.

        Args:
            intent: Detected intent dictionary
            message: Original user message
            messages: Full message history

        Returns:
            Response string
        """
        intent_type = intent['type']
        params = intent.get('params', {})

        try:
            # Use k8s adapter (lib/k8s) and helm operations
            from . import k8s_adapter as k8s_operations
            from . import helm_operations

            # Greeting responses
            if intent_type == 'greeting':
                return self._handle_greeting(message)

            # Help
            elif intent_type == 'help':
                return self._handle_help()

            # Namespace operations
            elif intent_type == 'list_namespaces':
                namespaces = k8s_operations.list_namespaces()
                return self._format_namespaces_list(namespaces)

            # Pod operations
            elif intent_type == 'list_pods':
                pods = k8s_operations.list_pods(params.get('namespace', 'default'))
                return self._format_pods_list(params.get('namespace', 'default'), pods)

            elif intent_type == 'describe_pod':
                pod = k8s_operations.describe_pod(params['name'], params.get('namespace', 'default'))
                return self._format_pod_details(pod)

            elif intent_type == 'get_logs':
                logs = k8s_operations.get_pod_logs(
                    params['name'],
                    params.get('namespace', 'default'),
                    tail_lines=50
                )
                return self._format_pod_logs(params['name'], logs)

            # Generic list/get for resources (deployment, service, configmap, secret, daemonset, statefulset)
            elif intent_type == 'resources_list':
                ns = params.get('namespace', 'default')
                items = k8s_operations.resources_list(params['resource_type'], ns)
                return self._format_resources_list(params['resource_type'], ns, items)

            elif intent_type == 'resources_get':
                resource = k8s_operations.resources_get(
                    params['resource_type'],
                    params['name'],
                    params.get('namespace', 'default')
                )
                return self._format_resource_details(params['resource_type'], resource)

            # Helm operations
            elif intent_type == 'helm_list':
                releases = helm_operations.list_releases(
                    namespace=params.get('namespace'),
                    all_namespaces=params.get('namespace') is None
                )
                return self._format_helm_releases(releases)

            # Create operations
            elif intent_type == 'create_namespace':
                if not params.get('name'):
                    return "Please specify a namespace name."
                result = k8s_operations.create_namespace(params['name'])
                return f"✅ Created namespace: **{result['name']}**"

            # Delete operations
            elif intent_type == 'delete_pod':
                result = k8s_operations.delete_resource(
                    'pod',
                    params['name'],
                    params.get('namespace', 'default')
                )
                return f"✅ Deleted pod: **{params['name']}**"

            elif intent_type == 'delete_deployment':
                result = k8s_operations.delete_resource(
                    'deployment',
                    params['name'],
                    params.get('namespace', 'default')
                )
                return f"✅ Deleted deployment: **{params['name']}**"

            # Diagnostics (K8sGPT) – not configured when using lib/k8s only
            elif intent_type in ('diagnose_cluster', 'diagnose_pod', 'diagnose_deployment'):
                return (
                    "Cluster diagnostics (K8sGPT) are not configured. "
                    "Use commands like 'list pods', 'describe pod <name>', or 'get logs for pod <name>' to inspect resources."
                )

            else:
                return f"Intent '{intent_type}' is not implemented yet."

        except RuntimeError as e:
            logger.warning("Intent execution error: %s", e)
            return f"❌ Error: {str(e)}"
        except Exception as e:
            logger.error("Unexpected error executing intent %s: %s", intent_type, e)
            return f"❌ An unexpected error occurred: {str(e)}"

    def _handle_greeting(self, message: str) -> str:
        """Handle greeting messages."""
        greetings = [
            "Hello! 👋 How can I help you with your Kubernetes cluster today?",
            "Hi there! What would you like to know about your cluster?",
            "Hey! I'm here to help you manage your Kubernetes resources. What do you need?",
        ]
        import random
        return random.choice(greetings)

    def _handle_help(self) -> str:
        """Handle help requests."""
        return (
            "I can help you with Kubernetes operations! Here's what I can do:\n\n"
            "**Namespaces:**\n"
            "- `list namespaces`\n"
            "- `create namespace <name>`\n\n"
            "**Pods:**\n"
            "- `list pods in <namespace>`\n"
            "- `describe pod <name> in <namespace>`\n"
            "- `show logs for pod <name>`\n"
            "- `delete pod <name> in <namespace>`\n\n"
            "**Resources (deployments, services, configmaps, secrets, daemonsets, statefulsets):**\n"
            "- `list <resource> in <namespace>` (e.g. list deployments in kube-system)\n"
            "- `describe <resource> <name> in <namespace>` (e.g. describe deployment nginx in default)\n"
            "- `delete deployment <name> in <namespace>`\n\n"
            "**Helm:**\n"
            "- `helm list` or `list releases in <namespace>`\n\n"
            "Just type your command in natural language!"
        )

    def handle_greeting_help_sync(self, intent_type: str, message: str) -> Optional[str]:
        """
        Handle only greeting and help intents synchronously (for use from sync request path).
        Returns reply string for greeting/help, or None for other intents.
        """
        if intent_type == "greeting":
            return self._handle_greeting(message)
        if intent_type == "help":
            return self._handle_help()
        return None

    def _format_namespaces_list(self, namespaces: List[Dict]) -> str:
        """Format namespaces list as markdown table."""
        if not namespaces:
            return "No namespaces found."

        lines = [
            "| NAME | STATUS | AGE |",
            "|------|--------|-----|",
        ]
        for ns in namespaces:
            lines.append(f"| {ns['name']} | {ns['status']} | {ns['age']} |")

        return f"**Namespaces** ({len(namespaces)}):\n\n" + "\n".join(lines)

    def _format_pods_list(self, namespace: str, pods: List[Dict]) -> str:
        """Format pods list as markdown table."""
        if not pods:
            return f"No pods found in namespace `{namespace}`."

        lines = [
            "| NAME | STATUS | READY | RESTARTS | AGE |",
            "|------|--------|-------|----------|-----|",
        ]
        for pod in pods:
            lines.append(
                f"| {pod['name']} | {pod['status']} | {pod['ready']} | "
                f"{pod['restarts']} | {pod['age']} |"
            )

        return f"**Pods in namespace `{namespace}`** ({len(pods)}):\n\n" + "\n".join(lines)

    def _format_pod_details(self, pod: Dict) -> str:
        """Format pod details."""
        containers_info = "\n".join(
            f"  - **{c['name']}**: Ready={c['ready']}, Restarts={c['restart_count']}, State={c['state']}"
            for c in pod.get('containers', [])
        )

        labels_info = ", ".join(f"{k}={v}" for k, v in pod.get('labels', {}).items()) or "None"

        return (
            f"**Pod: {pod['name']}**\n\n"
            f"- **Namespace:** {pod['namespace']}\n"
            f"- **Status:** {pod['status']}\n"
            f"- **IP:** {pod.get('ip', 'N/A')}\n"
            f"- **Node:** {pod.get('node', 'N/A')}\n"
            f"- **Service Account:** {pod.get('service_account', 'N/A')}\n"
            f"- **Labels:** {labels_info}\n"
            f"- **Created:** {pod.get('created', 'N/A')}\n\n"
            f"**Containers:**\n{containers_info}"
        )

    def _format_pod_logs(self, pod_name: str, logs: str) -> str:
        """Format pod logs."""
        if not logs:
            return f"No logs found for pod `{pod_name}`."

        # Truncate if too long
        if len(logs) > 10000:
            logs = logs[:10000] + "\n\n... (truncated)"

        return f"**Logs for pod `{pod_name}`:**\n\n```\n{logs}\n```"

    def _normalize_kind(self, resource_type: str) -> str:
        """Normalize resource type to singular kind for formatter dispatch."""
        s = (resource_type or "").lower().strip()
        if s in ('deployments', 'deployment'):
            return 'deployment'
        if s in ('daemonsets', 'daemonset'):
            return 'daemonset'
        if s in ('statefulsets', 'statefulset'):
            return 'statefulset'
        if s in ('services', 'service'):
            return 'service'
        if s in ('configmaps', 'configmap', 'cm'):
            return 'configmap'
        if s in ('secrets', 'secret'):
            return 'secret'
        return s

    def _format_resources_list(self, resource_type: str, namespace: str, items: List[Dict]) -> str:
        """Dispatch to the right list formatter by resource kind."""
        kind = self._normalize_kind(resource_type)
        if kind == 'deployment':
            return self._format_deployments_list(namespace, items)
        if kind == 'daemonset':
            return self._format_daemonsets_list(namespace, items)
        if kind == 'statefulset':
            return self._format_statefulsets_list(namespace, items)
        if kind == 'service':
            return self._format_services_list(namespace, items)
        if kind == 'configmap':
            return self._format_configmaps_list(namespace, items)
        if kind == 'secret':
            return self._format_secrets_list(namespace, items)
        return f"No formatter for resource type: {resource_type}"

    def _format_resource_details(self, resource_type: str, resource: Dict) -> str:
        """Format a single resource (describe-style). Dispatches by kind or uses generic format."""
        kind = self._normalize_kind(resource_type)
        if kind == 'deployment':
            return self._format_deployment_details(resource)
        # Generic format for service, configmap, secret, daemonset, statefulset
        lines = [f"**{kind.title()}: {resource.get('name', 'N/A')}**\n"]
        for key, value in resource.items():
            if key == 'name':
                continue
            if isinstance(value, dict):
                value = ", ".join(f"{k}={v}" for k, v in value.items()) or "None"
            elif isinstance(value, list):
                value = ", ".join(str(v) for v in value) or "None"
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        return "\n".join(lines)

    def _format_deployments_list(self, namespace: str, deployments: List[Dict]) -> str:
        """Format deployments list as markdown table."""
        if not deployments:
            return f"No deployments found in namespace `{namespace}`."

        lines = [
            "| NAME | READY | AVAILABLE | AGE |",
            "|------|-------|-----------|-----|",
        ]
        for dep in deployments:
            lines.append(
                f"| {dep['name']} | {dep['ready']} | {dep['available']} | {dep['age']} |"
            )

        return f"**Deployments in namespace `{namespace}`** ({len(deployments)}):\n\n" + "\n".join(lines)

    def _format_daemonsets_list(self, namespace: str, daemonsets: List[Dict]) -> str:
        """Format daemonsets list as markdown table."""
        if not daemonsets:
            return f"No daemonsets found in namespace `{namespace}`."

        lines = [
            "| NAME | READY | CURRENT | DESIRED | AGE |",
            "|------|-------|---------|---------|-----|",
        ]
        for ds in daemonsets:
            lines.append(
                f"| {ds['name']} | {ds['ready']} | {ds['current']} | {ds['desired']} | {ds['age']} |"
            )

        return f"**DaemonSets in namespace `{namespace}`** ({len(daemonsets)}):\n\n" + "\n".join(lines)

    def _format_statefulsets_list(self, namespace: str, statefulsets: List[Dict]) -> str:
        """Format statefulsets list as markdown table."""
        if not statefulsets:
            return f"No statefulsets found in namespace `{namespace}`."

        lines = [
            "| NAME | READY | REPLICAS | AGE |",
            "|------|-------|----------|-----|",
        ]
        for sts in statefulsets:
            lines.append(
                f"| {sts['name']} | {sts['ready']} | {sts['replicas']} | {sts['age']} |"
            )

        return f"**StatefulSets in namespace `{namespace}`** ({len(statefulsets)}):\n\n" + "\n".join(lines)

    def _format_deployment_details(self, deployment: Dict) -> str:
        """Format deployment details."""
        containers_info = "\n".join(f"  - {c}" for c in deployment.get('containers', []))
        labels_info = ", ".join(f"{k}={v}" for k, v in deployment.get('labels', {}).items()) or "None"
        selector_info = ", ".join(f"{k}={v}" for k, v in deployment.get('selector', {}).items()) or "None"

        return (
            f"**Deployment: {deployment['name']}**\n\n"
            f"- **Namespace:** {deployment['namespace']}\n"
            f"- **Replicas:** {deployment['replicas']} (Ready: {deployment['ready']}, Available: {deployment['available']})\n"
            f"- **Unavailable:** {deployment['unavailable']}\n"
            f"- **Strategy:** {deployment['strategy']}\n"
            f"- **Selector:** {selector_info}\n"
            f"- **Labels:** {labels_info}\n"
            f"- **Created:** {deployment.get('created', 'N/A')}\n\n"
            f"**Containers:**\n{containers_info}"
        )

    def _format_services_list(self, namespace: str, services: List[Dict]) -> str:
        """Format services list as markdown table."""
        if not services:
            return f"No services found in namespace `{namespace}`."

        lines = [
            "| NAME | TYPE | CLUSTER-IP | PORTS | AGE |",
            "|------|------|------------|-------|-----|",
        ]
        for svc in services:
            lines.append(
                f"| {svc['name']} | {svc['type']} | {svc['cluster_ip']} | "
                f"{svc['ports']} | {svc['age']} |"
            )

        return f"**Services in namespace `{namespace}`** ({len(services)}):\n\n" + "\n".join(lines)

    def _format_configmaps_list(self, namespace: str, configmaps: List[Dict]) -> str:
        """Format configmaps list as markdown table."""
        if not configmaps:
            return f"No configmaps found in namespace `{namespace}`."

        lines = [
            "| NAME | DATA KEYS | AGE |",
            "|------|-----------|-----|",
        ]
        for cm in configmaps:
            keys_info = ", ".join(cm.get('keys', [])) or "None"
            lines.append(f"| {cm['name']} | {cm['data_keys']} ({keys_info}) | {cm['age']} |")

        return f"**ConfigMaps in namespace `{namespace}`** ({len(configmaps)}):\n\n" + "\n".join(lines)

    def _format_secrets_list(self, namespace: str, secrets: List[Dict]) -> str:
        """Format secrets list as markdown table."""
        if not secrets:
            return f"No secrets found in namespace `{namespace}`."

        lines = [
            "| NAME | TYPE | DATA KEYS | AGE |",
            "|------|------|-----------|-----|",
        ]
        for secret in secrets:
            lines.append(
                f"| {secret['name']} | {secret['type']} | {secret['data_keys']} | {secret['age']} |"
            )

        return f"**Secrets in namespace `{namespace}`** ({len(secrets)}):\n\n" + "\n".join(lines)

    def _format_helm_releases(self, releases: List[Dict]) -> str:
        """Format Helm releases list as markdown table."""
        if not releases:
            return "No Helm releases found."

        lines = [
            "| NAME | NAMESPACE | REVISION | UPDATED | STATUS | CHART | APP VERSION |",
            "|------|-----------|----------|---------|--------|-------|-------------|",
        ]
        for release in releases:
            lines.append(
                f"| {release.get('name', 'N/A')} | {release.get('namespace', 'N/A')} | "
                f"{release.get('revision', 'N/A')} | {release.get('updated', 'N/A')} | "
                f"{release.get('status', 'N/A')} | {release.get('chart', 'N/A')} | "
                f"{release.get('app_version', 'N/A')} |"
            )

        return f"**Helm Releases** ({len(releases)}):\n\n" + "\n".join(lines)
