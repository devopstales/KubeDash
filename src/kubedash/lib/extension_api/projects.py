"""
Projects module for Kubernetes Extension API Server.

This module handles Project resources, which are namespace-like resources
filtered by user permissions.
"""

from contextlib import nullcontext
from typing import List, Optional, Tuple

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode

from . import logger, tracer
from .authentication import AuthenticatedUser
from .authorization import (
    can_user_list_all_namespaces,
    check_namespace_access,
    filter_namespaces_by_permission
)
from .helpers import build_project_object, build_project_list, get_resource_version
from lib.k8s.server import k8sClientConfigGet

##############################################################
## Constants
##############################################################

API_GROUP = "kubedash.devopstales.github.io"
API_VERSION = "v1"
API_GROUP_VERSION = f"{API_GROUP}/{API_VERSION}"

# Resource to check for namespace access
# Users who can list pods in a namespace are considered to have access
ACCESS_CHECK_RESOURCE = "pods"
ACCESS_CHECK_VERB = "list"

##############################################################
## Project Functions
##############################################################

def list_all_namespaces() -> Tuple[List[dict], Optional[str]]:
    """
    List all namespaces from Kubernetes.
    
    Returns:
        Tuple[List[dict], Optional[str]]: List of namespace data dicts and error if any
    """
    with tracer.start_as_current_span("list-all-namespaces") if tracer else nullcontext() as span:
        try:
            k8sClientConfigGet("Admin", None)
            
            api = k8s_client.CoreV1Api()
            namespaces = api.list_namespace(_request_timeout=5)
            
            namespace_list = []
            for ns in namespaces.items:
                ns_data = {
                    "name": ns.metadata.name,
                    "uid": ns.metadata.uid,
                    "status": ns.status.phase,
                    "created": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None,
                    "labels": ns.metadata.labels or {},
                    "annotations": ns.metadata.annotations or {},  # Keep all annotations for custom fields
                    "resource_version": ns.metadata.resource_version,
                }
                namespace_list.append(ns_data)
            
            if tracer and span and span.is_recording():
                span.set_attribute("namespace.count", len(namespace_list))
            
            return namespace_list, None
            
        except ApiException as e:
            logger.error(f"Failed to list namespaces: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"List namespaces failed: {e.reason}"))
            return [], f"ApiException: {e.reason}"
        except Exception as e:
            logger.error(f"Failed to list namespaces: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return [], str(e)


def get_namespace(name: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Get a specific namespace from Kubernetes.
    
    Args:
        name: The namespace name
        
    Returns:
        Tuple[Optional[dict], Optional[str]]: Namespace data dict and error if any
    """
    with tracer.start_as_current_span(
        "get-namespace",
        attributes={"namespace.name": name}
    ) if tracer else nullcontext() as span:
        try:
            k8sClientConfigGet("Admin", None)
            
            api = k8s_client.CoreV1Api()
            ns = api.read_namespace(name, _request_timeout=5)
            
            ns_data = {
                "name": ns.metadata.name,
                "uid": ns.metadata.uid,
                "status": ns.status.phase,
                "created": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None,
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},  # Keep all annotations for custom fields
                "resource_version": ns.metadata.resource_version,
            }
            
            return ns_data, None
            
        except ApiException as e:
            if e.status == 404:
                return None, "NotFound"
            logger.error(f"Failed to get namespace {name}: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Get namespace failed: {e.reason}"))
            return None, f"ApiException: {e.reason}"
        except Exception as e:
            logger.error(f"Failed to get namespace {name}: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return None, str(e)


def list_projects(
    user: AuthenticatedUser,
    label_selector: str = None,
    field_selector: str = None,
    limit: int = None
) -> Tuple[dict, Optional[str]]:
    """
    List projects (namespaces filtered by user permissions).
    
    Args:
        user: The authenticated user
        label_selector: Label selector for filtering
        field_selector: Field selector for filtering
        limit: Maximum number of results
        
    Returns:
        Tuple[dict, Optional[str]]: ProjectList object and error if any
    """
    with tracer.start_as_current_span(
        "list-projects",
        attributes={
            "user": user.username,
            "label_selector": label_selector or "",
        }
    ) if tracer else nullcontext() as span:
        
        # Log user info for debugging
        logger.debug(f"Listing projects for user: {user.username}, groups: {user.groups}")
        
        # Get all namespaces first
        namespaces, error = list_all_namespaces()
        if error:
            logger.error(f"Failed to list namespaces: {error}")
            return build_project_list([]), error
        
        logger.debug(f"Found {len(namespaces)} total namespaces")
        
        # Check if user is cluster admin (can list all namespaces)
        is_cluster_admin = can_user_list_all_namespaces(user)
        logger.debug(f"User {user.username} is_cluster_admin: {is_cluster_admin}")
        
        if is_cluster_admin:
            # User can see all namespaces
            logger.debug(f"User {user.username} is cluster admin, showing all {len(namespaces)} namespaces")
            allowed_namespaces = namespaces
        else:
            # Filter namespaces by permission
            logger.debug(f"Filtering namespaces for user {user.username} (non-admin)")
            namespace_names = [ns["name"] for ns in namespaces]
            allowed_ns_names = filter_namespaces_by_permission(
                user,
                namespace_names,
                verb=ACCESS_CHECK_VERB,
                resource=ACCESS_CHECK_RESOURCE
            )
            allowed_namespaces = [ns for ns in namespaces if ns["name"] in allowed_ns_names]
            logger.debug(f"User {user.username} allowed namespaces: {len(allowed_ns_names)}/{len(namespace_names)}")
        
        # Apply label selector filter if provided
        if label_selector:
            allowed_namespaces = _filter_by_labels(allowed_namespaces, label_selector)
        
        # Apply limit if provided
        if limit and limit > 0:
            allowed_namespaces = allowed_namespaces[:limit]
        
        if tracer and span and span.is_recording():
            span.set_attribute("project.count", len(allowed_namespaces))
            span.set_attribute("user.is_cluster_admin", is_cluster_admin)
        
        # Convert to Project objects
        projects = [build_project_object(ns) for ns in allowed_namespaces]
        
        return build_project_list(projects), None


def get_project(user: AuthenticatedUser, name: str) -> Tuple[Optional[dict], Optional[str], int]:
    """
    Get a specific project by name.
    
    Args:
        user: The authenticated user
        name: The project/namespace name
        
    Returns:
        Tuple[Optional[dict], Optional[str], int]: Project object, error message, and HTTP status code
    """
    with tracer.start_as_current_span(
        "get-project",
        attributes={
            "user": user.username,
            "project.name": name,
        }
    ) if tracer else nullcontext() as span:
        
        # Get the namespace
        ns_data, error = get_namespace(name)
        
        if error == "NotFound":
            return None, f'projects.{API_GROUP} "{name}" not found', 404
        
        if error:
            return None, error, 500
        
        # Check if user has access to this namespace
        is_cluster_admin = can_user_list_all_namespaces(user)
        
        if not is_cluster_admin:
            has_access = check_namespace_access(
                user,
                name,
                verb=ACCESS_CHECK_VERB,
                resource=ACCESS_CHECK_RESOURCE
            )
            
            if not has_access:
                logger.debug(f"User {user.username} denied access to project {name}")
                if tracer and span and span.is_recording():
                    span.set_attribute("authz.denied", True)
                # Return 404 instead of 403 to not leak namespace existence
                return None, f'projects.{API_GROUP} "{name}" not found', 404
        
        if tracer and span and span.is_recording():
            span.set_attribute("authz.allowed", True)
        
        project = build_project_object(ns_data)
        return project, None, 200


def create_project(
    user: AuthenticatedUser,
    name: str,
    protected: bool,
    owner: str = None,
    labels: dict = None,
    repository: str = None,
    pipeline: str = None
) -> Tuple[Optional[dict], Optional[str], int]:
    """
    Create a new project (namespace).
    
    Args:
        user: The authenticated user
        name: The project/namespace name (required)
        protected: Whether the project is protected (required)
        owner: Owner name (optional, defaults to authenticated user's username)
        labels: Optional labels for the namespace
        repository: Optional repository URL
        pipeline: Optional pipeline URL
        
    Returns:
        Tuple[Optional[dict], Optional[str], int]: Project object, error message, and HTTP status code
    """
    # Validate required fields
    if protected is None:
        return None, "spec.protected is required", 400
    
    # If owner is not provided, use the authenticated user's username
    if not owner or not owner.strip():
        owner = user.username
        logger.debug(f"Owner not provided, using authenticated user: {owner}")
    with tracer.start_as_current_span(
        "create-project",
        attributes={
            "user": user.username,
            "project.name": name,
        }
    ) if tracer else nullcontext() as span:
        
        # Check if user can create namespaces
        try:
            k8sClientConfigGet("Admin", None)
            
            # Check authorization using SubjectAccessReview
            from .authorization import check_namespace_access
            sar = k8s_client.V1SubjectAccessReview(
                spec=k8s_client.V1SubjectAccessReviewSpec(
                    user=user.username,
                    groups=user.groups,
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        verb="create",
                        resource="namespaces",
                        group=""
                    )
                )
            )
            
            auth_api = k8s_client.AuthorizationV1Api()
            auth_result = auth_api.create_subject_access_review(sar, _request_timeout=5)
            
            if not auth_result.status.allowed:
                logger.warning(f"User {user.username} is not authorized to create namespaces")
                if tracer and span and span.is_recording():
                    span.set_attribute("authz.denied", True)
                return None, f'User "{user.username}" cannot create projects', 403
                
        except ApiException as e:
            logger.error(f"Authorization check failed: {e.status} - {e.reason}")
            return None, f"Authorization check failed: {e.reason}", 500
        
        # Check if namespace already exists
        existing_ns, error = get_namespace(name)
        if existing_ns:
            return None, f'projects.{API_GROUP} "{name}" already exists', 409
        
        # Build annotations
        annotations = {}
        if owner:
            annotations["metadata.k8s.io/owner"] = owner
        if protected:
            annotations[f"{API_GROUP}/protected"] = "true"
        if repository:
            annotations["metadata.k8s.io/repository"] = repository
        if pipeline:
            annotations["metadata.k8s.io/pipeline"] = pipeline
        
        # Add created-by annotation
        annotations[f"{API_GROUP}/created-by"] = user.username
        
        # Build labels
        ns_labels = labels or {}
        ns_labels["kubernetes.io/metadata.name"] = name
        
        try:
            k8sClientConfigGet("Admin", None)
            
            api = k8s_client.CoreV1Api()
            
            # Create namespace
            namespace = k8s_client.V1Namespace(
                metadata=k8s_client.V1ObjectMeta(
                    name=name,
                    labels=ns_labels,
                    annotations=annotations if annotations else None
                )
            )
            
            result = api.create_namespace(namespace, _request_timeout=5)
            
            logger.info(f"Project {name} created by {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("project.created", True)
            
            # Build and return the project object
            ns_data = {
                "name": result.metadata.name,
                "uid": result.metadata.uid,
                "status": result.status.phase,
                "created": result.metadata.creation_timestamp.isoformat() if result.metadata.creation_timestamp else None,
                "labels": result.metadata.labels or {},
                "annotations": result.metadata.annotations or {},
                "resource_version": result.metadata.resource_version,
            }
            
            project = build_project_object(ns_data)
            return project, None, 201
            
        except ApiException as e:
            if e.status == 409:
                return None, f'projects.{API_GROUP} "{name}" already exists', 409
            logger.error(f"Failed to create namespace {name}: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Create namespace failed: {e.reason}"))
            return None, f"Failed to create project: {e.reason}", e.status or 500
        except Exception as e:
            logger.error(f"Failed to create namespace {name}: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return None, str(e), 500


def update_project(
    user: AuthenticatedUser,
    name: str,
    owner: str = None,
    protected: bool = None,
    labels: dict = None,
    repository: str = None,
    pipeline: str = None
) -> Tuple[Optional[dict], Optional[str], int]:
    """
    Update an existing project (namespace).
    
    Args:
        user: The authenticated user
        name: The project/namespace name
        owner: New owner name (optional)
        protected: New protected status (optional)
        labels: New labels (optional, will merge with existing)
        repository: New repository URL (optional)
        pipeline: New pipeline URL (optional)
        
    Returns:
        Tuple[Optional[dict], Optional[str], int]: Project object, error message, and HTTP status code
    """
    with tracer.start_as_current_span(
        "update-project",
        attributes={
            "user": user.username,
            "project.name": name,
        }
    ) if tracer else nullcontext() as span:
        
        # Check if namespace exists
        existing_ns, error = get_namespace(name)
        if error == "NotFound":
            return None, f'projects.{API_GROUP} "{name}" not found', 404
        if error:
            return None, error, 500
        
        # Check if user can update namespaces
        try:
            k8sClientConfigGet("Admin", None)
            
            # Check authorization
            sar = k8s_client.V1SubjectAccessReview(
                spec=k8s_client.V1SubjectAccessReviewSpec(
                    user=user.username,
                    groups=user.groups,
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        namespace=name,
                        verb="update",
                        resource="namespaces",
                        group=""
                    )
                )
            )
            
            auth_api = k8s_client.AuthorizationV1Api()
            auth_result = auth_api.create_subject_access_review(sar, _request_timeout=5)
            
            if not auth_result.status.allowed:
                logger.warning(f"User {user.username} is not authorized to update namespace {name}")
                if tracer and span and span.is_recording():
                    span.set_attribute("authz.denied", True)
                return None, f'User "{user.username}" cannot update project "{name}"', 403
                
        except ApiException as e:
            logger.error(f"Authorization check failed: {e.status} - {e.reason}")
            return None, f"Authorization check failed: {e.reason}", 500
        
        try:
            k8sClientConfigGet("Admin", None)
            api = k8s_client.CoreV1Api()
            
            # Get current namespace
            ns = api.read_namespace(name, _request_timeout=5)
            
            # Update annotations
            annotations = ns.metadata.annotations or {}
            if owner is not None:
                annotations["metadata.k8s.io/owner"] = owner
            if protected is not None:
                annotations[f"{API_GROUP}/protected"] = "true" if protected else "false"
            if repository is not None:
                annotations["metadata.k8s.io/repository"] = repository
            if pipeline is not None:
                annotations["metadata.k8s.io/pipeline"] = pipeline
            
            # Update labels if provided
            ns_labels = ns.metadata.labels or {}
            if labels:
                ns_labels.update(labels)
            
            # Patch the namespace
            body = {
                "metadata": {
                    "annotations": annotations,
                    "labels": ns_labels
                }
            }
            
            result = api.patch_namespace(name, body, _request_timeout=5)
            
            logger.info(f"Project {name} updated by {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("project.updated", True)
            
            # Build and return the project object
            ns_data = {
                "name": result.metadata.name,
                "uid": result.metadata.uid,
                "status": result.status.phase,
                "created": result.metadata.creation_timestamp.isoformat() if result.metadata.creation_timestamp else None,
                "labels": result.metadata.labels or {},
                "annotations": result.metadata.annotations or {},
                "resource_version": result.metadata.resource_version,
            }
            
            project = build_project_object(ns_data)
            return project, None, 200
            
        except ApiException as e:
            if e.status == 404:
                return None, f'projects.{API_GROUP} "{name}" not found', 404
            logger.error(f"Failed to update namespace {name}: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Update namespace failed: {e.reason}"))
            return None, f"Failed to update project: {e.reason}", e.status or 500
        except Exception as e:
            logger.error(f"Failed to update namespace {name}: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return None, str(e), 500


def delete_project(
    user: AuthenticatedUser,
    name: str
) -> Tuple[Optional[dict], Optional[str], int]:
    """
    Delete a project (namespace).
    
    Args:
        user: The authenticated user
        name: The project/namespace name to delete
        
    Returns:
        Tuple[Optional[dict], Optional[str], int]: Status object, error message, and HTTP status code
    """
    with tracer.start_as_current_span(
        "delete-project",
        attributes={
            "user": user.username,
            "project.name": name,
        }
    ) if tracer else nullcontext() as span:
        
        # Check if namespace exists and get its data
        existing_ns, error = get_namespace(name)
        if error == "NotFound":
            return None, f'projects.{API_GROUP} "{name}" not found', 404
        if error:
            return None, error, 500
        
        # Check if project is protected
        annotations = existing_ns.get("annotations", {})
        is_protected = annotations.get(f"{API_GROUP}/protected", "false").lower() == "true"
        
        if is_protected:
            logger.warning(f"Attempt to delete protected project {name} by {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("project.protected", True)
            return None, f'Project "{name}" is protected and cannot be deleted', 403
        
        # Check if user can delete namespaces
        try:
            k8sClientConfigGet("Admin", None)
            
            # Check authorization
            sar = k8s_client.V1SubjectAccessReview(
                spec=k8s_client.V1SubjectAccessReviewSpec(
                    user=user.username,
                    groups=user.groups,
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        verb="delete",
                        resource="namespaces",
                        group=""
                    )
                )
            )
            
            auth_api = k8s_client.AuthorizationV1Api()
            auth_result = auth_api.create_subject_access_review(sar, _request_timeout=5)
            
            if not auth_result.status.allowed:
                logger.warning(f"User {user.username} is not authorized to delete namespaces")
                if tracer and span and span.is_recording():
                    span.set_attribute("authz.denied", True)
                return None, f'User "{user.username}" cannot delete projects', 403
                
        except ApiException as e:
            logger.error(f"Authorization check failed: {e.status} - {e.reason}")
            return None, f"Authorization check failed: {e.reason}", 500
        
        try:
            k8sClientConfigGet("Admin", None)
            api = k8s_client.CoreV1Api()
            
            # Delete the namespace
            api.delete_namespace(name, _request_timeout=5)
            
            logger.info(f"Project {name} deleted by {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("project.deleted", True)
            
            # Return success status
            return {
                "kind": "Status",
                "apiVersion": "v1",
                "metadata": {},
                "status": "Success",
                "message": f'project "{name}" deleted',
                "code": 200
            }, None, 200
            
        except ApiException as e:
            if e.status == 404:
                return None, f'projects.{API_GROUP} "{name}" not found', 404
            logger.error(f"Failed to delete namespace {name}: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Delete namespace failed: {e.reason}"))
            return None, f"Failed to delete project: {e.reason}", e.status or 500
        except Exception as e:
            logger.error(f"Failed to delete namespace {name}: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return None, str(e), 500


##############################################################
## Helper Functions
##############################################################

def _filter_by_labels(namespaces: List[dict], label_selector: str) -> List[dict]:
    """
    Filter namespaces by label selector.
    
    Supports simple equality selectors like "key=value" or "key!=value".
    Multiple selectors can be comma-separated.
    
    Args:
        namespaces: List of namespace data dicts
        label_selector: Label selector string
        
    Returns:
        List[dict]: Filtered namespaces
    """
    if not label_selector:
        return namespaces
    
    filtered = []
    selectors = label_selector.split(',')
    
    for ns in namespaces:
        labels = ns.get("labels", {})
        matches = True
        
        for selector in selectors:
            selector = selector.strip()
            
            if '!=' in selector:
                key, value = selector.split('!=', 1)
                if labels.get(key.strip()) == value.strip():
                    matches = False
                    break
            elif '=' in selector:
                key, value = selector.split('=', 1)
                if labels.get(key.strip()) != value.strip():
                    matches = False
                    break
            else:
                # Existence check
                if selector not in labels:
                    matches = False
                    break
        
        if matches:
            filtered.append(ns)
    
    return filtered
