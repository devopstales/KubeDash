"""
MCP tool name candidates for Kubernetes and Helm operations.

Centralizes tool names so all k8s/helm operations try the same candidates
in a consistent order (compatible with containers/kubernetes-mcp-server and similar).
"""

# Kubernetes: list namespaces
TOOLS_LIST_NAMESPACES = ("namespaces_list",)

# Kubernetes: list pods in namespace
TOOLS_LIST_PODS = ("pods_list_in_namespace",)

# Kubernetes: list any resource (apiVersion + kind, optional namespace)
TOOLS_LIST_RESOURCE = ("resources_list",)

# Kubernetes: describe/get a single resource (pod or generic)
TOOLS_DESCRIBE_POD = ("describe_pod", "get_pod", "pod_describe", "describe_resource")
TOOLS_GET_RESOURCE = ("describe_resource", "get_resource", "resource_describe")

# Kubernetes: pod logs
TOOLS_POD_LOGS = ("pods_log", "pod_logs", "show_logs", "get_pod_logs", "get_logs_for_pod_and_container")

# Kubernetes: create namespace
TOOLS_CREATE_NAMESPACE = ("namespace_create", "create_namespace", "namespaces_create")

# Kubernetes: apply YAML (create or update)
TOOLS_APPLY = (
    "resources_create_or_update",
    "kubectl_apply",
    "apply_yaml",
    "apply_manifest",
    "apply",
    "resources_apply",
    "resource_apply",
    "apply_resource",
)
APPLY_PARAM_NAMES = (
    "resource",
    "resources",
    "yaml",
    "manifest",
    "content",
    "body",
    "document",
    "resourceYaml",
    "yamlContent",
)

# Kubernetes: delete resource
TOOLS_DELETE = ("resources_delete", "resource_delete", "delete_resource", "kubectl_delete")

# Kubernetes: create resource (simple, no YAML) – fallback when apply not available
TOOLS_CREATE_SIMPLE = ("resource_create", "create_resource", "kubectl_create")

# Kubernetes: update/patch resource (simple) – fallback
TOOLS_UPDATE_SIMPLE = ("resource_update", "kubectl_patch", "patch_resource")

# Helm: list releases
TOOLS_HELM_LIST = ("helm_list", "list_helm_releases")

# Helm: install chart
TOOLS_HELM_INSTALL = ("helm_install", "install_helm_chart", "helm_install_chart")

# Helm: uninstall release
TOOLS_HELM_UNINSTALL = ("helm_uninstall", "uninstall_helm_chart", "helm_uninstall_release")
