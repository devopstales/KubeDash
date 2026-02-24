"""
Build minimal Kubernetes resource YAML for MCP create/update operations.

Used by k8s_operations to generate manifests when the user asks to create or update
a resource (Deployment, ConfigMap, Pod, Service, Secret, etc.) without full YAML.
"""

import re


def extract_image_from_content(content: str) -> str | None:
    """Extract container image from phrases like 'with image nginx:1.14.2'. Returns None if not found."""
    if not content or not content.strip():
        return None
    t = content.strip()
    m = re.search(r"\b(?:with\s+)?image\s+([a-z0-9][a-z0-9.\-/:]*)", t, re.I)
    if m:
        return m.group(1).strip()
    return None


def extract_configmap_mount(content: str) -> tuple[str, str] | None:
    """Extract (configmap_name, mount_path) from phrases like 'mount the hello-world configmap to /usr/share/nginx/html'. Returns None if not found."""
    if not content or not content.strip():
        return None
    m = re.search(
        r"\bmount\s+(?:the\s+)?(?P<cm>[a-z0-9][a-z0-9\-.]*)\s+configmap\s+to\s+(?P<path>/[a-z0-9/_.\-]+)\b",
        content.strip(),
        re.I,
    )
    if m:
        return (m.group("cm").strip(), m.group("path").strip())
    m = re.search(
        r"\bmount\s+configmap\s+(?:the\s+)?(?P<cm>[a-z0-9][a-z0-9\-.]*)\s+to\s+(?P<path>/[a-z0-9/_.\-]+)\b",
        content.strip(),
        re.I,
    )
    if m:
        return (m.group("cm").strip(), m.group("path").strip())
    return None


def extract_file_from_content(content: str) -> str | None:
    """Extract filename from phrases like 'with file hello-world.html'. Returns None if not found."""
    if not content or not content.strip():
        return None
    m = re.search(r"\b(?:with\s+)?file\s+([a-zA-Z0-9][a-zA-Z0-9_.\-]*)", content.strip(), re.I)
    return m.group(1).strip() if m else None


def build_deployment_yaml(name: str, namespace: str, image: str = "nginx:latest") -> str:
    """Build a minimal Deployment YAML (apps/v1) with one container."""
    return """apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: %s
        image: %s
""" % (
        name,
        namespace,
        name,
        name,
        name,
        image,
    )


def build_deployment_yaml_with_configmap_volume(
    name: str,
    namespace: str,
    image: str = "nginx:latest",
    configmap_name: str | None = None,
    mount_path: str | None = None,
) -> str:
    """Build Deployment YAML (apps/v1) with optional ConfigMap volume mounted in the container."""
    volume_block = ""
    volume_mount_block = ""
    if configmap_name and mount_path:
        vol_name = configmap_name.replace(".", "-")[:63]
        volume_block = """
      volumes:
      - name: %s
        configMap:
          name: %s
""" % (vol_name, configmap_name)
        volume_mount_block = """
        volumeMounts:
        - name: %s
          mountPath: %s
""" % (vol_name, mount_path)
    return """apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: %s
        image: %s%s
""" % (
        name,
        namespace,
        name,
        name,
        name,
        image,
        volume_mount_block,
    ) + (volume_block if volume_block else "")


def build_configmap_yaml(name: str, namespace: str, data_keys: dict | None = None) -> str:
    """Build a minimal ConfigMap YAML (v1). data_keys is optional map of key -> value."""
    data = data_keys if isinstance(data_keys, dict) and data_keys else {}
    data_block = ""
    if data:
        for k, v in sorted(data.items()):
            if "\n" in str(v):
                data_block += "  %s: |\n    %s\n" % (k, str(v).replace("\n", "\n    "))
            else:
                data_block += "  %s: %s\n" % (k, repr(str(v)))
    else:
        data_block = "  {}"
    return """apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
data:
%s""" % (name, namespace, data_block)


def build_pod_yaml(name: str, namespace: str, image: str = "nginx:latest") -> str:
    """Build a minimal Pod YAML (v1) with one container."""
    return """apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: %s
    image: %s
""" % (name, namespace, name, image)


def build_secret_yaml(name: str, namespace: str) -> str:
    """Build a minimal Secret YAML (v1) with type Opaque and empty data."""
    return """apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data: {}
""" % (name, namespace)


def build_service_yaml(name: str, namespace: str, port: int = 80) -> str:
    """Build a minimal Service YAML (v1) ClusterIP with one port."""
    return """apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    app: %s
  ports:
  - port: %s
    targetPort: %s
    name: http
""" % (name, namespace, name, port, port)


def build_generic_resource_yaml(api_version: str, kind: str, name: str, namespace: str | None) -> str:
    """Build minimal YAML for any namespaced or cluster-scoped resource (metadata + empty spec)."""
    if kind == "Namespace" or (namespace is None or namespace == ""):
        return """apiVersion: %s
kind: %s
metadata:
  name: %s
spec: {}
""" % (api_version, kind, name)
    return """apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec: {}
""" % (api_version, kind, name, namespace)


def build_minimal_resource_yaml(
    api_version: str,
    kind: str,
    name: str,
    namespace: str,
    content: str = "",
    configmap_mount: tuple[str, str] | None = None,
) -> str | None:
    """
    Build minimal valid YAML for create/update. Returns None only for kinds we don't support.
    configmap_mount: (configmap_name, mount_path) for Deployment update.
    """
    image = extract_image_from_content(content) or ("nginx:1.14.2" if kind == "Deployment" else "nginx:latest")
    if kind == "Deployment":
        if configmap_mount:
            cm_name, mount_path = configmap_mount
            return build_deployment_yaml_with_configmap_volume(
                name, namespace, image, configmap_name=cm_name, mount_path=mount_path
            )
        return build_deployment_yaml(name, namespace, image)
    if kind == "ConfigMap":
        file_key = extract_file_from_content(content)
        data_keys = {file_key: ""} if file_key else None
        return build_configmap_yaml(name, namespace, data_keys)
    if kind == "Pod":
        return build_pod_yaml(name, namespace, image)
    if kind == "Secret":
        return build_secret_yaml(name, namespace)
    if kind == "Service":
        return build_service_yaml(name, namespace)
    if kind == "Namespace":
        return build_generic_resource_yaml(api_version, kind, name, None)
    return build_generic_resource_yaml(api_version, kind, name, namespace)
