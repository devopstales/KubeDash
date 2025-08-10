from kubernetes import client, config
from kubernetes.client.rest import ApiException

try:
    config.load_kube_config()
except:
    config.load_incluster_config()

core_api = client.CoreV1Api()
auth_api = client.AuthorizationV1Api()

def is_namespace_visible(namespace, user, groups):
    sar = client.V1SubjectAccessReview(
        spec=client.V1SubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=namespace,
                verb="get",
                resource="namespaces"
            ),
            user=user,
            groups=groups or []
        )
    )
    resp = auth_api.create_subject_access_review(sar)
    return resp.status.allowed

def to_project(namespace_obj):
    ns_name = namespace_obj.metadata.name
    return {
        "kind": "Project",
        "apiVersion": "mygroup.example.com/v1",
        "metadata": {
            "name": ns_name,
            "labels": namespace_obj.metadata.labels or {},
            "annotations": namespace_obj.metadata.annotations or {}
        },
        "spec": {
            "description": f"Namespace {ns_name}"
        }
    }

def list_visible_projects(user, groups):
    ns_list = core_api.list_namespace()
    return [
        to_project(ns)
        for ns in ns_list.items
        if is_namespace_visible(ns.metadata.name, user, groups)
    ]

def get_project(name, user, groups):
    if not is_namespace_visible(name, user, groups):
        return None
    try:
        ns = core_api.read_namespace(name)
        return to_project(ns)
    except ApiException as e:
        if e.status == 404:
            return None
        raise

def create_project(name):
    body = client.V1Namespace(
        metadata=client.V1ObjectMeta(name=name)
    )
    ns = core_api.create_namespace(body)
    return to_project(ns)

def update_project(name, data):
    try:
        patch = {"metadata": data.get("metadata", {})}
        ns = core_api.patch_namespace(name, patch)
        return to_project(ns)
    except ApiException as e:
        if e.status == 404:
            return None
        raise

def delete_project(name):
    try:
        core_api.delete_namespace(name)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise
