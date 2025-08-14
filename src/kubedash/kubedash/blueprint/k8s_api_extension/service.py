from flask import current_app
from datetime import datetime, timezone

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




def format_age(ts: str) -> str:
    """Return human-readable age like '3y 2d' from RFC3339 timestamp."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    years, days = divmod(delta.days, 365)
    if years > 0:
        return f"{years}y{days}d"
    return f"{days}d"

def validate_user(request):
    # Get user identity
    user = request.headers.get("X-Remote-User") or request.headers.get("Impersonate-User")
    
    # Handle group headers properly
    groups = []
    group_header = request.headers.get("X-Remote-Group") or request.headers.get("Impersonate-Group")
    if group_header:
        groups = [g.strip() for g in group_header.split(',') if g.strip()]
    
    # Handle system components
    if not user and not groups:
        auth_header = request.headers.get("Authorization")
        if auth_header and ("system:serviceaccount" in auth_header or "system:kube-controller-manager" in auth_header):
            user = auth_header.split(":")[-1] if ":" in auth_header else auth_header
            groups = ["system:authenticated"]
    
    if not user and not groups:
        return {"message": "Authorization credentials required"}, 401
        
    return user, groups


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
    from datetime import timezone

    ts = namespace_obj.metadata.creation_timestamp
    creation_ts = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")    

    project_onj = {
        "kind": "Project",
        "apiVersion": "devopstales.github.io/v1",
        "metadata": {
            "name": namespace_obj.metadata.name,
            "labels": namespace_obj.metadata.labels or {},
            "annotations": namespace_obj.metadata.annotations or {},
            "creationTimestamp": creation_ts
        }, 
        "status": {
            "phase": namespace_obj.status.phase
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

    try:
        namespace_list, error = k8sListNamespaces('Admin', None)
        if error:
            raise Exception(f"Failed to list namespaces: {error}")
    except Exception as e:
        current_app.logger.error(f"Namespace listing failed: {str(e)}")
        return {"message": "Internal server error"}, 500

    for ns_obj in namespace_list.items:
        if is_namespace_visible(ns_obj, user, groups):
            allowed_ns_list.append(ns_obj)
    
    # Convert to project ?
    ## Create If not Exists ??
    
    return allowed_ns_list

def get_project(name, user, groups):
    k8sClientConfigGet('Admin', None)
    try:
        ns_obj = core_api.read_namespace(name)
        
        if not is_namespace_visible(ns_obj, user, groups):
            return None, 401
        
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
