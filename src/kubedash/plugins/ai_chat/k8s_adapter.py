#!/usr/bin/env python3
"""
Kubernetes operations adapter for AI Chat plugin.

Uses lib/k8s for all cluster operations (no MCP). Normalizes responses
to the shapes expected by minimal_provider formatters.

Authentication (same as rest of dashboard):
- Admin: uses kubeconfig / incluster config (no token).
- User (SSO): uses session access token from lib.sso.get_user_token(session).
All k8s calls use (user_role, user_token) so RBAC respects the logged-in user.
"""

from typing import List, Dict, Optional, Any

from flask import session
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

logger = get_logger()
tracer = get_tracer()


def _session_creds():
    """
    Get (user_role, user_token) from Flask session — same pattern as dashboard
    (e.g. blueprint/api/cluster, blueprint/workload). Admin → kubeconfig;
    SSO User → access token from get_user_token(session).
    """
    user_role = session.get('user_role', 'Admin')
    user_token = get_user_token(session)
    return user_role, user_token


def list_namespaces() -> List[Dict[str, Any]]:
    """List namespaces. Returns list of {name, status, age}."""
    role, token = _session_creds()
    from lib.k8s.namespace import k8sNamespacesGet
    raw = k8sNamespacesGet(role, token)
    result = []
    for ns in raw or []:
        result.append({
            'name': ns.get('name'),
            'status': ns.get('status', 'Unknown'),
            'age': ns.get('created', 'Unknown'),
        })
    return result


def list_pods(namespace: str = "default") -> List[Dict[str, Any]]:
    """List pods. Returns list of {name, namespace, status, ready, restarts, age}."""
    role, token = _session_creds()
    from lib.k8s.server import k8sClientConfigGet
    from kubernetes import client as k8s_client
    k8sClientConfigGet(role, token)
    try:
        v1 = k8s_client.CoreV1Api()
        pods = v1.list_namespaced_pod(namespace, _request_timeout=10)
        result = []
        for pod in pods.items:
            cs = pod.status.container_statuses or []
            ready = sum(1 for c in cs if c.ready)
            total = len(cs) or len(pod.spec.containers or [])
            result.append({
                'name': pod.metadata.name,
                'namespace': pod.metadata.namespace,
                'status': pod.status.phase,
                'ready': f"{ready}/{total}",
                'restarts': sum(c.restart_count for c in cs),
                'age': pod.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S') if pod.metadata.creation_timestamp else 'Unknown',
            })
        return result
    except Exception as e:
        logger.error("list_pods %s: %s", namespace, e)
        raise RuntimeError(str(e)) from e


def describe_pod(name: str, namespace: str = "default") -> Dict[str, Any]:
    """Get pod details. Returns dict for _format_pod_details."""
    role, token = _session_creds()
    from lib.k8s.workload import k8sPodGet
    raw = k8sPodGet(role, token, namespace, name)
    if not raw or not raw.get('name'):
        raise RuntimeError(f"Pod '{name}' not found in namespace '{namespace}'")
    containers = []
    for c in raw.get('containers', []):
        containers.append({
            'name': c.get('name', ''),
            'ready': c.get('ready', 'Unknown'),
            'restart_count': c.get('restarts', 0),
            'state': str(c.get('ready', '')),
        })
    return {
        'name': raw['name'],
        'namespace': raw['namespace'],
        'status': raw.get('status', 'Unknown'),
        'ip': raw.get('pod_ip'),
        'node': raw.get('node'),
        'service_account': raw.get('service_account'),
        'labels': raw.get('labels') or {},
        'created': raw.get('created', 'N/A'),
        'containers': containers,
    }


def get_pod_logs(name: str, namespace: str = "default", tail_lines: int = 100, container: Optional[str] = None) -> str:
    """Get logs for a pod."""
    role, token = _session_creds()
    from lib.k8s.server import k8sClientConfigGet
    from kubernetes import client as k8s_client
    k8sClientConfigGet(role, token)
    try:
        v1 = k8s_client.CoreV1Api()
        kwargs = {'name': name, 'namespace': namespace, 'tail_lines': tail_lines}
        if container:
            kwargs['container'] = container
        return v1.read_namespaced_pod_log(**kwargs)
    except Exception as e:
        logger.error("get_pod_logs %s/%s: %s", namespace, name, e)
        raise RuntimeError(str(e)) from e


def describe_deployment(name: str, namespace: str = "default") -> Dict[str, Any]:
    """Get deployment details for _format_deployment_details."""
    role, token = _session_creds()
    from lib.k8s.server import k8sClientConfigGet
    from kubernetes import client as k8s_client
    k8sClientConfigGet(role, token)
    try:
        apps_v1 = k8s_client.AppsV1Api()
        dep = apps_v1.read_namespaced_deployment(name=name, namespace=namespace, _request_timeout=10)
        return {
            'name': dep.metadata.name,
            'namespace': dep.metadata.namespace,
            'replicas': dep.status.replicas or 0,
            'ready': dep.status.ready_replicas or 0,
            'available': dep.status.available_replicas or 0,
            'unavailable': dep.status.unavailable_replicas or 0,
            'strategy': dep.spec.strategy.type if dep.spec.strategy else 'RollingUpdate',
            'containers': [c.name for c in (dep.spec.template.spec.containers or [])],
            'labels': dict(dep.metadata.labels or {}),
            'selector': dict(dep.spec.selector.match_labels or {}),
            'created': dep.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S') if dep.metadata.creation_timestamp else 'N/A',
        }
    except Exception as e:
        logger.error("describe_deployment %s/%s: %s", namespace, name, e)
        raise RuntimeError(str(e)) from e


def list_deployments(namespace: str = "default") -> List[Dict[str, Any]]:
    """List deployments. Returns list of {name, namespace, ready, available, age}."""
    role, token = _session_creds()
    from lib.k8s.workload import k8sDeploymentsGet
    raw = k8sDeploymentsGet(role, token, namespace) or []
    result = []
    for d in raw:
        ready = d.get('ready') or 0
        desired = d.get('desired') or 0
        result.append({
            'name': d.get('name'),
            'namespace': d.get('namespace'),
            'ready': f"{ready}/{desired}",
            'available': ready,
            'age': d.get('created', 'Unknown'),
        })
    return result


def list_daemonsets(namespace: str = "default") -> List[Dict[str, Any]]:
    """List daemonsets. Returns list of {name, namespace, ready, current, desired, age}."""
    role, token = _session_creds()
    from lib.k8s.workload import k8sDaemonSetsGet
    raw = k8sDaemonSetsGet(role, token, namespace) or []
    result = []
    for ds in raw:
        ready = ds.get('ready') or 0
        desired = ds.get('desired') or 0
        result.append({
            'name': ds.get('name'),
            'namespace': ds.get('namespace'),
            'ready': f"{ready}/{desired}",
            'current': ds.get('current', 0),
            'desired': desired,
            'age': ds.get('created', 'Unknown'),
        })
    return result


def list_statefulsets(namespace: str = "default") -> List[Dict[str, Any]]:
    """List statefulsets. Returns list of {name, namespace, ready, replicas, age}."""
    role, token = _session_creds()
    from lib.k8s.workload import k8sStatefulSetsGet
    raw = k8sStatefulSetsGet(role, token, namespace) or []
    result = []
    for sts in raw:
        ready = sts.get('ready') or 0
        replicas = sts.get('replicas') or 0
        result.append({
            'name': sts.get('name'),
            'namespace': sts.get('namespace'),
            'ready': f"{ready}/{replicas}",
            'replicas': replicas,
            'age': sts.get('created', 'Unknown'),
        })
    return result


def list_services(namespace: str = "default") -> List[Dict[str, Any]]:
    """List services. Returns list of {name, type, cluster_ip, ports, age}."""
    role, token = _session_creds()
    from lib.k8s.network import k8sServiceListGet
    raw = k8sServiceListGet(role, token, namespace) or []
    result = []
    for svc in raw:
        ports = svc.get('ports') or []
        if ports and isinstance(ports[0], dict):
            port_str = ", ".join(str(p.get('port', p)) for p in ports[:5])
        elif ports:
            port_str = ", ".join(str(p) for p in ports[:5])
        else:
            port_str = "—"
        result.append({
            'name': svc.get('name'),
            'type': svc.get('type', 'ClusterIP'),
            'cluster_ip': svc.get('cluster_ip', '—'),
            'ports': port_str,
            'age': svc.get('created', 'Unknown'),
        })
    return result


def list_configmaps(namespace: str = "default") -> List[Dict[str, Any]]:
    """List configmaps. Returns list of {name, namespace, data_keys, keys, age}."""
    role, token = _session_creds()
    from lib.k8s.storage import k8sConfigmapListGet
    raw = k8sConfigmapListGet(role, token, namespace) or []
    result = []
    for cm in raw:
        data = cm.get('data') or {}
        keys = list(data.keys())[:5]
        result.append({
            'name': cm.get('name'),
            'namespace': namespace,
            'data_keys': len(data),
            'keys': keys,
            'age': cm.get('created', 'Unknown'),
        })
    return result


def list_secrets(namespace: str = "default") -> List[Dict[str, Any]]:
    """List secrets. Returns list of {name, namespace, type, data_keys, age}."""
    role, token = _session_creds()
    from lib.k8s.security import k8sSecretListGet
    raw = k8sSecretListGet(role, token, namespace) or []
    result = []
    for sec in raw:
        data = sec.get('data') or {}
        result.append({
            'name': sec.get('name'),
            'namespace': namespace,
            'type': sec.get('type', 'Opaque'),
            'data_keys': len(data),
            'age': sec.get('created', 'Unknown'),
        })
    return result


def create_namespace(name: str) -> Dict[str, Any]:
    """Create a namespace. Returns {name}."""
    role, token = _session_creds()
    from lib.k8s.namespace import k8sNamespaceCreate
    k8sNamespaceCreate(role, token, name)
    return {'name': name}


def delete_resource(kind: str, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
    """Delete a resource. Returns {status, kind, name}."""
    role, token = _session_creds()
    from lib.k8s.server import k8sClientConfigGet
    from kubernetes import client as k8s_client
    k8sClientConfigGet(role, token)
    kind_lower = kind.lower()
    try:
        if kind_lower == 'pod':
            if not namespace:
                raise RuntimeError("Namespace is required for deleting a pod")
            from lib.k8s.workload import k8sPodDelete
            ok = k8sPodDelete(role, token, namespace, name)
            if not ok:
                raise RuntimeError(f"Failed to delete pod '{name}'")
        elif kind_lower == 'deployment':
            if not namespace:
                raise RuntimeError("Namespace is required for deleting a deployment")
            apps_v1 = k8s_client.AppsV1Api()
            apps_v1.delete_namespaced_deployment(name=name, namespace=namespace, _request_timeout=10)
        else:
            raise RuntimeError(f"Unsupported resource kind: {kind}")
        return {'status': 'deleted', 'kind': kind, 'name': name}
    except Exception as e:
        logger.error("delete_resource %s %s: %s", kind, name, e)
        raise RuntimeError(str(e)) from e


# Optional: resources_list / resources_get for generic resource types (used by minimal_provider generic intents)
def resources_list(resource_type: str, namespace: str) -> List[Dict[str, Any]]:
    """List resources by kind. Dispatches to list_*."""
    kind = (resource_type or "").lower().strip()
    if kind in ('deployments', 'deployment'):
        return list_deployments(namespace)
    if kind in ('daemonsets', 'daemonset'):
        return list_daemonsets(namespace)
    if kind in ('statefulsets', 'statefulset'):
        return list_statefulsets(namespace)
    if kind in ('services', 'service'):
        return list_services(namespace)
    if kind in ('configmaps', 'configmap', 'cm'):
        return list_configmaps(namespace)
    if kind in ('secrets', 'secret'):
        return list_secrets(namespace)
    raise RuntimeError(f"Unsupported resource type: {resource_type}")


def resources_get(resource_type: str, name: str, namespace: str = "default") -> Dict[str, Any]:
    """Get a single resource. Dispatches to describe_*."""
    kind = (resource_type or "").lower().strip()
    if kind == 'pod':
        return describe_pod(name, namespace)
    if kind == 'deployment':
        return describe_deployment(name, namespace)
    raise RuntimeError(f"Describe not implemented for {resource_type}")
