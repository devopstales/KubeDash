from kubernetes import client, config
from kubernetes.client.rest import ApiException

from kubedash.lib.k8s.server import k8sClientConfigGet
from kubedash.lib.k8s.namespace import k8sListNamespaces

try:
    config.load_kube_config()
except:
    config.load_incluster_config()

core_api = client.CoreV1Api()
auth_api = client.AuthorizationV1Api()

def is_namespace_visible(namespace_obj, user, groups):
    k8sClientConfigGet('Admin', None)  # your setup
    
    # Representative resource-verbs to test:
    resource_verbs = [
        ("pods", "list"),
        ("deployments", "list"),
        ("secrets", "get"),
        ("configmaps", "get"),
    ]
    
    for resource, verb in resource_verbs:
        sar = client.V1SubjectAccessReview(
            spec=client.V1SubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(
                    namespace=namespace_obj.metadata.name,
                    verb=verb,
                    resource=resource
                ),
                user=user,
                groups=groups or []
            )
        )
        resp = auth_api.create_subject_access_review(sar)
        if resp.status.allowed:
            return True  # user has access to this namespace
    
    # No permission found
    return False

def to_project(namespace_obj, user, spec=None):
    project_onj = {
        "kind": "Project",
        "apiVersion": "devopstales.github.io/v1",
        "metadata": {
            "name": namespace_obj.metadata.name,
            "labels": namespace_obj.metadata.labels or {},
            "annotations": namespace_obj.metadata.annotations or {}
        }
    }
    if spec:
        project_onj["spec"] = spec
    else:
        project_onj["spec"] = {
            "description": f"Namespace {namespace_obj.metadata.name}",
            "owner": f"{user}"
        }
    return project_onj

def list_visible_projects(user, groups):
    """
    """
    allowed_ns_list = []
    k8sClientConfigGet('Admin', None)
    namespace_list, error = k8sListNamespaces('Admin', None)
    for ns_obj in namespace_list.items:
        if is_namespace_visible(ns_obj, user, groups):
            allowed_ns_list.append(ns_obj)
    
    # Convert to project ?
    ## Create If not Exists ??
    
    return allowed_ns_list

def get_project(name, user, groups):
    k8sClientConfigGet('Admin', None)
    if not is_namespace_visible(name, user, groups):
        return None, 401
    try:
        ns_obj = core_api.read_namespace(name)
        return to_project(ns_obj, user, None), 200
    except ApiException as e:
        if e.status == 404:
            return None, 404
        raise

def create_project(name, user, spec=None):
    k8sClientConfigGet('Admin', None)
    body = client.V1Namespace(
        metadata=client.V1ObjectMeta(name=name)
    )
    ns_obj = core_api.create_namespace(body)
    return to_project(ns_obj, user, spec)

def update_project(name, data, user, spec=None):
    k8sClientConfigGet('Admin', None)
    try:
        patch = {"metadata": data.get("metadata", {})}
        ns_obj = core_api.patch_namespace(name, patch)
        return to_project(ns_obj, user, spec)
    except ApiException as e:
        if e.status == 404:
            return None
        raise

def delete_project(name):
    k8sClientConfigGet('Admin', None)
    try:
        core_api.delete_namespace(name)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise
