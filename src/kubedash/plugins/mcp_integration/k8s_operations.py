"""
Reusable Kubernetes operations for MCP integration.

Provides list, get, create, update, delete that work for all K8s resource types
by trying known MCP tool name candidates (see mcp_tools.py).
"""

from lib.helper_functions import get_logger

from plugins.mcp_integration.mcp_session import query_mcp_tool
from plugins.mcp_integration.mcp_tools import (
    APPLY_PARAM_NAMES,
    TOOLS_APPLY,
    TOOLS_CREATE_NAMESPACE,
    TOOLS_CREATE_SIMPLE,
    TOOLS_DELETE,
    TOOLS_DESCRIBE_POD,
    TOOLS_GET_RESOURCE,
    TOOLS_LIST_NAMESPACES,
    TOOLS_LIST_PODS,
    TOOLS_LIST_RESOURCE,
    TOOLS_POD_LOGS,
    TOOLS_UPDATE_SIMPLE,
)
from plugins.mcp_integration.resource_yaml import (
    build_minimal_resource_yaml,
    extract_configmap_mount,
)

logger = get_logger()


def _try_tools(mcp_url: str, tool_candidates: tuple, args_or_builder, error_prefix: str) -> str:
    """
    Try each tool in tool_candidates. args_or_builder is either a dict (same args for all tools)
    or a callable tool_name -> dict of arguments. Returns first successful raw result.
    Raises RuntimeError with error_prefix + tried names.
    """
    last_error = None
    for tool_name in tool_candidates:
        try:
            args = args_or_builder(tool_name) if callable(args_or_builder) else args_or_builder
            return query_mcp_tool(mcp_url, tool_name, args)
        except RuntimeError as e:
            last_error = e
            err_lower = str(e).lower()
            if "unknown tool" in err_lower or "not found" in err_lower:
                logger.debug("MCP tool %s not available: %s", tool_name, e)
                continue
            raise
    tried = ", ".join(tool_candidates)
    raise RuntimeError("{} (tried: {}). {}".format(error_prefix, tried, last_error or ""))


def list_namespaces(mcp_url: str) -> str:
    """List all namespaces. Returns raw tool output."""
    return _try_tools(
        mcp_url,
        TOOLS_LIST_NAMESPACES,
        {},
        "List namespaces is not available",
    )


def list_pods(mcp_url: str, namespace: str) -> str:
    """List pods in a namespace. Returns raw tool output."""
    return _try_tools(
        mcp_url,
        TOOLS_LIST_PODS,
        {"namespace": namespace},
        "List pods is not available",
    )


def list_resource(
    mcp_url: str,
    api_version: str,
    kind: str,
    namespace: str | None = None,
) -> str:
    """List resources of the given apiVersion/kind, optionally in a namespace. Returns raw tool output."""
    params = {"apiVersion": api_version, "kind": kind}
    if namespace:
        params["namespace"] = namespace
    return _try_tools(
        mcp_url,
        TOOLS_LIST_RESOURCE,
        params,
        "List {} is not available".format(kind),
    )


def get_resource(
    mcp_url: str,
    namespace: str,
    kind: str,
    name: str,
    api_version: str | None = None,
) -> str:
    """
    Get/describe a single resource. For Pod, tries describe_pod first; else describe_resource.
    Returns raw tool output.
    """
    if kind.lower() == "pod":
        for tool_name in TOOLS_DESCRIBE_POD:
            try:
                if tool_name == "describe_resource":
                    args = {"namespace": namespace, "kind": "Pod", "name": name}
                else:
                    args = {"namespace": namespace, "pod_name": name}
                return query_mcp_tool(mcp_url, tool_name, args)
            except RuntimeError as e:
                err_lower = str(e).lower()
                if "unknown tool" in err_lower or "not found" in err_lower:
                    continue
                raise
        raise RuntimeError(
            "Describe pod is not available (tried: {}).".format(", ".join(TOOLS_DESCRIBE_POD))
        )
    for tool_name in TOOLS_GET_RESOURCE:
        try:
            args = {"namespace": namespace, "kind": kind, "name": name}
            if api_version:
                args["apiVersion"] = api_version
            return query_mcp_tool(mcp_url, tool_name, args)
        except RuntimeError as e:
            err_lower = str(e).lower()
            if "unknown tool" in err_lower or "not found" in err_lower:
                continue
            raise
    raise RuntimeError(
        "Describe resource is not available (tried: {}).".format(", ".join(TOOLS_GET_RESOURCE))
    )


def get_pod_logs(mcp_url: str, namespace: str, pod_name: str) -> str:
    """Get logs for a pod. Returns raw tool output."""
    last_error = None
    for tool_name in TOOLS_POD_LOGS:
        try:
            args = {"namespace": namespace, "name": pod_name} if tool_name == "pods_log" else {"namespace": namespace, "pod_name": pod_name}
            return query_mcp_tool(mcp_url, tool_name, args)
        except RuntimeError as e:
            last_error = e
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Pod logs are not available (tried: {}). {}".format(", ".join(TOOLS_POD_LOGS), last_error or "")
    )


def create_namespace(mcp_url: str, name: str) -> str:
    """Create a namespace. Returns raw tool output."""
    return _try_tools(
        mcp_url,
        TOOLS_CREATE_NAMESPACE,
        {"name": name},
        "Create namespace is not available",
    )


def create_resource(
    mcp_url: str,
    api_version: str,
    kind: str,
    name: str,
    namespace: str,
    content: str = "",
) -> str:
    """
    Create a K8s resource. Tries apply with generated YAML first, then simple create tools.
    Returns raw tool output.
    """
    yaml_manifest = build_minimal_resource_yaml(api_version, kind, name, namespace, content=content)
    if yaml_manifest:
        for apply_tool in TOOLS_APPLY:
            for param_name in APPLY_PARAM_NAMES:
                try:
                    args = {param_name: yaml_manifest}
                    raw = query_mcp_tool(mcp_url, apply_tool, args)
                    return raw or "Done."
                except RuntimeError as e:
                    err_lower = str(e).lower()
                    if "unknown tool" in err_lower or "not found" in err_lower:
                        break
                    raise
    for tool_name in TOOLS_CREATE_SIMPLE:
        try:
            args = {"namespace": namespace, "kind": kind, "name": name}
            if api_version:
                args["apiVersion"] = api_version
            return query_mcp_tool(mcp_url, tool_name, args) or "Done."
        except RuntimeError as e:
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Create resource is not available (tried apply tools and: {}).".format(", ".join(TOOLS_CREATE_SIMPLE))
    )


def update_resource(
    mcp_url: str,
    api_version: str,
    kind: str,
    name: str,
    namespace: str,
    content: str = "",
) -> str:
    """
    Update a K8s resource. Tries apply with generated YAML first, then simple update/patch tools.
    Returns raw tool output.
    """
    configmap_mount = extract_configmap_mount(content) if kind == "Deployment" else None
    yaml_manifest = build_minimal_resource_yaml(
        api_version, kind, name, namespace, content=content, configmap_mount=configmap_mount
    )
    if yaml_manifest:
        for apply_tool in TOOLS_APPLY:
            for param_name in APPLY_PARAM_NAMES:
                try:
                    args = {param_name: yaml_manifest}
                    raw = query_mcp_tool(mcp_url, apply_tool, args)
                    return raw or "Done."
                except RuntimeError as e:
                    err_lower = str(e).lower()
                    if "unknown tool" in err_lower or "not found" in err_lower:
                        break
                    raise
    for tool_name in TOOLS_UPDATE_SIMPLE:
        try:
            args = {"namespace": namespace, "kind": kind, "name": name}
            if api_version:
                args["apiVersion"] = api_version
            return query_mcp_tool(mcp_url, tool_name, args) or "Done."
        except RuntimeError as e:
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Update/patch is not available (tried apply tools and: {}).".format(", ".join(TOOLS_UPDATE_SIMPLE))
    )


def delete_resource(
    mcp_url: str,
    api_version: str,
    kind: str,
    name: str,
    namespace: str,
) -> str:
    """Delete a K8s resource. Returns raw tool output."""
    last_error = None
    for tool_name in TOOLS_DELETE:
        try:
            args = {"namespace": namespace, "kind": kind, "name": name}
            if api_version:
                args["apiVersion"] = api_version
            if tool_name == "kubectl_delete":
                args = {"namespace": namespace, "resource": kind.lower() + "s", "name": name}
            return query_mcp_tool(mcp_url, tool_name, args) or "Done."
        except RuntimeError as e:
            last_error = e
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Delete is not available (tried: {}). {}".format(", ".join(TOOLS_DELETE), last_error or "")
    )
