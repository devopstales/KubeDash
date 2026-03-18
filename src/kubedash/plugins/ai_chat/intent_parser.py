#!/usr/bin/env python3
"""
Intent parsing for AI Chat plugin.

Pattern-based intent detection for Kubernetes operations (list pods, describe pod,
get logs, list deployments, helm list, etc.). Used to route messages to k8s adapter (lib/k8s).
"""

import re
from typing import Dict, Any, Optional


def parse_intent(message: str) -> Optional[Dict[str, Any]]:
    """
    Parse user message to detect intent for Kubernetes operations.

    Args:
        message: User message

    Returns:
        Intent dict with type, namespace, name, and original; or None if no intent detected
    """
    message_lower = message.lower()

    patterns = {
        'greeting': r'\b(hi|hello|hey|greetings)\b',
        'help': r'\b(help|what\s+can\s+you\s+do|commands|available\s+commands)\b',
        'list_namespaces': r'\b(list|show|get)\s+(namespaces|ns)\b',
        'list_pods': r'\b(list|show|get)\s+(pods|pod)\b(?:\s+in\s+(\S+))?',
        'describe_pod': r'\b(describe|show\s+details?)\s+pod\s+(\S+)(?:\s+in\s+(\S+))?',
        'get_logs': r'\b(logs?|show\s+logs?)\s+(?:for\s+)?pod\s+(\S+)(?:\s+in\s+(\S+))?',
        'list_deployments': r'\b(list|show|get)\s+(deployments|deployment)\b(?:\s+in\s+(\S+))?',
        'list_daemonsets': r'\b(list|show|get)\s+(daemonsets|daemonset)\b(?:\s+in\s+(\S+))?',
        'list_statefulsets': r'\b(list|show|get)\s+(statefulsets|statefulset)\b(?:\s+in\s+(\S+))?',
        'list_services': r'\b(list|show|get)\s+(services|service)\b(?:\s+in\s+(\S+))?',
        'list_configmaps': r'\b(list|show|get)\s+(configmaps|configmap|cm)\b(?:\s+in\s+(\S+))?',
        'list_secrets': r'\b(list|show|get)\s+(secrets|secret)\b(?:\s+in\s+(\S+))?',
        'helm_list': r'\b(helm\s+)?(list\s+releases?|releases?|helm\s+list|list\s+helm(?:\s+releases?)?)\b(?:\s+in\s+(\S+))?',
        'diagnose_cluster': r'\b(diagnose|troubleshoot|analyze)\s+(cluster|clustering)\b',
        'diagnose_pod': r'\b(diagnose|troubleshoot)\s+pod\s+(\S+)(?:\s+in\s+(\S+))?',
        'diagnose_deployment': r'\b(diagnose|troubleshoot)\s+deployment\s+(\S+)(?:\s+in\s+(\S+))?',
    }

    for intent_type, pattern in patterns.items():
        match = re.search(pattern, message_lower)
        if match:
            groups = match.groups()
            intent = {'type': intent_type, 'original': message}

            # Namespace from text only; when not mentioned, leave None so API can use session namespace
            if intent_type == 'list_pods':
                intent['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None
            elif intent_type in ('describe_pod', 'get_logs', 'diagnose_pod'):
                intent['name'] = groups[1] if len(groups) > 1 and groups[1] else None
                intent['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None
            elif intent_type in ('list_deployments', 'list_daemonsets', 'list_statefulsets', 'list_services', 'list_configmaps', 'list_secrets'):
                intent['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None
            elif intent_type == 'helm_list':
                intent['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None
            elif intent_type == 'diagnose_deployment':
                intent['name'] = groups[1] if len(groups) > 1 and groups[1] else None
                intent['namespace'] = groups[2] if len(groups) > 2 and groups[2] else None
            elif intent_type == 'diagnose_cluster':
                pass

            return intent

    return None
