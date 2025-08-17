from flask import current_app
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from kubespace.k8s.server import k8sClientConfigGet
from kubespace.k8s.namespace import k8sListNamespaces

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
    error = None
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
        error = {"message": "Authorization credentials required"}, 401
        
    return user, groups, error


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

def to_space(namespace_obj, user, spec=None):
    from datetime import timezone

    ts = namespace_obj.metadata.creation_timestamp
    creation_ts = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Fields that should be moved from annotations to spec
    ANNOTATION_FIELDS = {'description', 'pipeline', 'repository', 'owner'}
    annotation_prefix = "metadata.k8s.io/"

    # Process annotations
    original_annotations = namespace_obj.metadata.annotations or {}
    filtered_annotations = {}
    extracted_spec_fields = {}

    for k, v in original_annotations.items():
        if k.startswith(annotation_prefix):
            field_name = k[len(annotation_prefix):]
            if field_name in ANNOTATION_FIELDS:
                extracted_spec_fields[field_name] = v
            # Else: drop the annotation
        else:
            filtered_annotations[k] = v

    # Initialize space object
    space_obj = {
        "kind": "Space",
        "apiVersion": "devopstales.github.io/v1",
        "metadata": {
            "name": namespace_obj.metadata.name,
            "labels": namespace_obj.metadata.labels or {},
            "annotations": filtered_annotations,
            "creationTimestamp": creation_ts
        },
        "status": {
            "phase": namespace_obj.status.phase
        }
    }

    # Build final spec
    default_spec = {
        "description": f"Namespace {namespace_obj.metadata.name}",
        "owner": f"{user}"
    }

    # Update with extracted annotation values
    for field in ANNOTATION_FIELDS:
        if field in extracted_spec_fields:
            default_spec[field] = extracted_spec_fields[field]

    # Use provided spec if exists, otherwise use default_spec
    if spec:
        # Merge with priority to provided spec values
        final_spec = {**default_spec, **spec}
        space_obj["spec"] = final_spec
    else:
        space_obj["spec"] = default_spec

    return space_obj


def list_visible_spaces(user, groups):
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
    
    return allowed_ns_list

def get_space(name, user, groups):
    k8sClientConfigGet('Admin', None)
    try:
        ns_obj = core_api.read_namespace(name)
        
        if not is_namespace_visible(ns_obj, user, groups):
            return None, 401
        
        return to_space(ns_obj, user, None), 200
    
    except ApiException as e:
        if e.status == 404:
            return None, 404
        raise

def create_space(name, user, spec=None):
    k8sClientConfigGet('Admin', None)
    
    # Fields that should be converted to annotations
    ANNOTATION_FIELDS = {'description', 'pipeline', 'repository', 'owner'}
    
    # Initialize dictionaries
    annotations = {}
    remaining_spec = {}
    
    if spec is not None:
        for key, value in spec.items():
            if key in ANNOTATION_FIELDS:
                # Convert to annotation
                annotation_key = f"metadata.k8s.io/{key}"
                annotations[annotation_key] = str(value)
            else:
                # Keep in spec
                remaining_spec[key] = value
    
    # Create namespace body
    ns_body = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=name,
            annotations=annotations if annotations else None
        )
    )
    
    print(annotations)
    print(remaining_spec)
    print(spec)
    
    # Create the namespace
    ns_obj = core_api.create_namespace(ns_body)
    
    # Convert to space format and return
    # Use remaining_spec if there were non-annotation fields, otherwise use original spec
    return to_space(ns_obj, user, remaining_spec if remaining_spec else spec)

def update_space(name, data, user, spec=None):
    k8sClientConfigGet('Admin', None)
    try:
        patch = {"metadata": data.get("metadata", {})}
        ns_obj = core_api.patch_namespace(name, patch)
        return to_space(ns_obj, user, spec)
    except ApiException as e:
        if e.status == 404:
            return None
        raise

def delete_space(name):
    k8sClientConfigGet('Admin', None)
    try:
        core_api.delete_namespace(name)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise
