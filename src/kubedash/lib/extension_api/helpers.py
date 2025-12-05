"""
Helper functions for Kubernetes Extension API Server.
"""

from datetime import datetime, timezone
from typing import List

##############################################################
## Constants
##############################################################

API_GROUP = "kubedash.devopstales.github.io"
API_VERSION = "v1"
API_GROUP_VERSION = f"{API_GROUP}/{API_VERSION}"

##############################################################
## Helper Functions
##############################################################

def get_resource_version() -> str:
    """
    Generate a resource version string.
    
    In a real implementation, this would be based on etcd revision
    or similar versioning mechanism.
    
    Returns:
        str: Resource version string
    """
    return str(int(datetime.now(timezone.utc).timestamp()))


def _get_resource_version(api_group_version: str = None) -> str:
    """
    Generate a resource version string (legacy compatibility).
    
    Args:
        api_group_version: Unused, kept for backward compatibility
        
    Returns:
        str: Resource version string
    """
    return get_resource_version()


def build_project_object(namespace_data: dict) -> dict:
    """
    Convert a Kubernetes namespace to a Project object.
    
    Args:
        namespace_data: Namespace data from Kubernetes API
            Expected keys: name, uid, created, labels, annotations, status, resource_version
        
    Returns:
        dict: Project object in Kubernetes API format
    """
    annotations = namespace_data.get("annotations", {})
    
    # Extract custom fields from annotations
    protected = annotations.get(f"{API_GROUP}/protected", "false").lower() == "true"
    owner = annotations.get("metadata.k8s.io/owner", "")
    repository = annotations.get("metadata.k8s.io/repository", "")
    pipeline = annotations.get("metadata.k8s.io/pipeline", "")
    
    return {
        "apiVersion": API_GROUP_VERSION,
        "kind": "Project",
        "metadata": {
            "name": namespace_data.get("name"),
            "uid": namespace_data.get("uid"),
            "creationTimestamp": namespace_data.get("created"),
            "labels": namespace_data.get("labels", {}),
            "annotations": annotations,
            "resourceVersion": namespace_data.get("resource_version", get_resource_version())
        },
        "spec": {
            "finalizers": ["kubernetes"],
            "protected": protected,
            "owner": owner,
            "repository": repository,
            "pipeline": pipeline
        },
        "status": {
            "phase": namespace_data.get("status", "Active"),
            "namespace": namespace_data.get("name")
        }
    }


def build_project_list(projects: List[dict]) -> dict:
    """
    Build a ProjectList object from a list of Project objects.
    
    Args:
        projects: List of Project objects
        
    Returns:
        dict: ProjectList object in Kubernetes API format
    """
    return {
        "kind": "ProjectList",
        "apiVersion": API_GROUP_VERSION,
        "metadata": {
            "resourceVersion": get_resource_version()
        },
        "items": projects
    }


def build_status_response(
    status: str,
    message: str,
    reason: str,
    code: int,
    details: dict = None
) -> dict:
    """
    Build a Kubernetes Status response object.
    
    Args:
        status: Status string ("Success" or "Failure")
        message: Human-readable message
        reason: Machine-readable reason (e.g., "NotFound", "Forbidden")
        code: HTTP status code
        details: Additional details dict
        
    Returns:
        dict: Status object in Kubernetes API format
    """
    response = {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": status,
        "message": message,
        "reason": reason,
        "code": code
    }
    
    if details:
        response["details"] = details
    
    return response


def build_not_found_response(resource_type: str, name: str) -> dict:
    """
    Build a NotFound Status response.
    
    Args:
        resource_type: The resource type (e.g., "projects")
        name: The resource name
        
    Returns:
        dict: NotFound Status object
    """
    return build_status_response(
        status="Failure",
        message=f'{resource_type}.{API_GROUP} "{name}" not found',
        reason="NotFound",
        code=404,
        details={
            "name": name,
            "group": API_GROUP,
            "kind": resource_type
        }
    )


def build_forbidden_response(resource_type: str, name: str, user: str) -> dict:
    """
    Build a Forbidden Status response.
    
    Args:
        resource_type: The resource type
        name: The resource name
        user: The username
        
    Returns:
        dict: Forbidden Status object
    """
    return build_status_response(
        status="Failure",
        message=f'{resource_type}.{API_GROUP} "{name}" is forbidden: User "{user}" cannot get resource "{resource_type}" in API group "{API_GROUP}"',
        reason="Forbidden",
        code=403,
        details={
            "name": name,
            "group": API_GROUP,
            "kind": resource_type
        }
    )


def build_unauthorized_response() -> dict:
    """
    Build an Unauthorized Status response.
    
    Returns:
        dict: Unauthorized Status object
    """
    return build_status_response(
        status="Failure",
        message="Unauthorized",
        reason="Unauthorized",
        code=401
    )
