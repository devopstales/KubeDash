"""
Reusable Helm operations for MCP integration.

Provides list, install, uninstall that work with common MCP Helm tool names
(see mcp_tools.py). Compatible with containers/kubernetes-mcp-server and similar.
"""

from lib.helper_functions import get_logger

from plugins.mcp_integration.mcp_session import query_mcp_tool
from plugins.mcp_integration.mcp_tools import (
    TOOLS_HELM_INSTALL,
    TOOLS_HELM_LIST,
    TOOLS_HELM_UNINSTALL,
)

logger = get_logger()


def list_releases(
    mcp_url: str,
    namespace: str | None = None,
    all_namespaces: bool = True,
    helm_list_tool: str = "helm_list",
) -> str:
    """
    List Helm releases. Returns raw tool output (often YAML).

    Args:
        mcp_url: MCP server base URL.
        namespace: If set and all_namespaces is False, list only in this namespace.
        all_namespaces: If True, list across all namespaces.
        helm_list_tool: Preferred tool name (e.g. from config); snake_case params used for helm_list.
    """
    params_snake = {"all_namespaces": all_namespaces}
    if not all_namespaces and namespace:
        params_snake["namespace"] = namespace
    params_camel = {"allNamespaces": all_namespaces}
    if not all_namespaces and namespace:
        params_camel["namespace"] = namespace

    candidates = [helm_list_tool]
    for alt in TOOLS_HELM_LIST:
        if alt not in candidates:
            candidates.append(alt)

    last_error = None
    for tool_name in candidates:
        try:
            params = params_snake if tool_name == "helm_list" else params_camel
            return query_mcp_tool(mcp_url, tool_name, params) or "(no output)"
        except RuntimeError as e:
            last_error = e
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "The MCP server does not expose a Helm list tool. Tried: {}. ".format(", ".join(candidates))
        + (str(last_error) if last_error else "")
    )


def install(
    mcp_url: str,
    chart: str,
    namespace: str = "default",
    release_name: str | None = None,
) -> str:
    """
    Install a Helm chart. Returns raw tool output.

    Args:
        mcp_url: MCP server base URL.
        chart: Chart reference (e.g. nginx or bitnami/nginx).
        namespace: Target namespace.
        release_name: Optional release name.
    """
    last_error = None
    for tool_name in TOOLS_HELM_INSTALL:
        try:
            args = {"chart": chart, "namespace": namespace}
            if release_name:
                args["release"] = release_name
            if tool_name == "install_helm_chart":
                args = {"chart": chart, "namespace": namespace}
                if release_name:
                    args["name"] = release_name
            return query_mcp_tool(mcp_url, tool_name, args) or "Done."
        except RuntimeError as e:
            last_error = e
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Helm install is not available (tried: {}). {}".format(
            ", ".join(TOOLS_HELM_INSTALL), last_error or ""
        )
    )


def uninstall(
    mcp_url: str,
    release_name: str,
    namespace: str = "default",
) -> str:
    """
    Uninstall a Helm release. Returns raw tool output.

    Args:
        mcp_url: MCP server base URL.
        release_name: Name of the release.
        namespace: Namespace of the release.
    """
    last_error = None
    for tool_name in TOOLS_HELM_UNINSTALL:
        try:
            args = {"release": release_name, "namespace": namespace}
            if tool_name == "uninstall_helm_chart":
                args["name"] = release_name
            return query_mcp_tool(mcp_url, tool_name, args) or "Done."
        except RuntimeError as e:
            last_error = e
            if "unknown tool" in str(e).lower() or "not found" in str(e).lower():
                continue
            raise
    raise RuntimeError(
        "Helm uninstall is not available (tried: {}). {}".format(
            ", ".join(TOOLS_HELM_UNINSTALL), last_error or ""
        )
    )
