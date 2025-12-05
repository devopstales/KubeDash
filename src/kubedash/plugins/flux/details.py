"""
FluxCD Object Details Module

Provides functions to fetch single Flux objects with enriched data including
Kubernetes events and detailed status conditions.
"""

from logging import getLogger
from typing import Optional, Tuple, List, Dict, Any

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException
from lib.k8s.server import k8sClientConfigGet
from lib.helper_functions import ErrorHandler

logger = getLogger(__name__)

##############################################################
# FluxCD Object Type Definitions
##############################################################

FLUX_OBJECT_TYPES = {
    # Sources
    "GitRepository": {
        "group": "source.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "gitrepositories",
        "category": "source"
    },
    "HelmRepository": {
        "group": "source.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "helmrepositories",
        "category": "source"
    },
    "OCIRepository": {
        "group": "source.toolkit.fluxcd.io",
        "version": "v1beta2",
        "plural": "ocirepositories",
        "category": "source"
    },
    "Bucket": {
        "group": "source.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "buckets",
        "category": "source"
    },
    "HelmChart": {
        "group": "source.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "helmcharts",
        "category": "source"
    },
    # Reconcilers
    "Kustomization": {
        "group": "kustomize.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "kustomizations",
        "category": "reconciler"
    },
    "HelmRelease": {
        "group": "helm.toolkit.fluxcd.io",
        "version": "v2",
        "plural": "helmreleases",
        "category": "reconciler"
    },
    # Notifications
    "Alert": {
        "group": "notification.toolkit.fluxcd.io",
        "version": "v1beta3",
        "plural": "alerts",
        "category": "notification"
    },
    "Provider": {
        "group": "notification.toolkit.fluxcd.io",
        "version": "v1beta3",
        "plural": "providers",
        "category": "notification"
    },
    "Receiver": {
        "group": "notification.toolkit.fluxcd.io",
        "version": "v1",
        "plural": "receivers",
        "category": "notification"
    },
}


##############################################################
# Single Object Fetch
##############################################################

def FluxObjectGet(
    kind: str,
    name: str,
    namespace: str,
    username_role: str,
    user_token: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch a single Flux object by kind, name, and namespace.
    
    Args:
        kind: The Flux object kind (e.g., "GitRepository", "Kustomization")
        name: The name of the object
        namespace: The namespace of the object
        username_role: User role for authorization
        user_token: User token for authentication
        
    Returns:
        Tuple of (object_dict, error_message)
        - On success: (object_dict, None)
        - On error: (None, error_message)
    """
    if kind not in FLUX_OBJECT_TYPES:
        return None, f"Unknown Flux object kind: {kind}"
    
    obj_type = FLUX_OBJECT_TYPES[kind]
    
    k8sClientConfigGet(username_role, user_token)
    crd_api = k8s_client.CustomObjectsApi()
    
    try:
        obj = crd_api.get_namespaced_custom_object(
            group=obj_type["group"],
            version=obj_type["version"],
            namespace=namespace,
            plural=obj_type["plural"],
            name=name,
            _request_timeout=5
        )
        return obj, None
    except ApiException as error:
        if error.status == 404:
            return None, f"{kind} '{name}' not found in namespace '{namespace}'"
        ErrorHandler(logger, error, f"get {kind} {name}")
        return None, f"Failed to get {kind} '{name}': {error.reason}"
    except Exception as error:
        ErrorHandler(logger, error, f"get {kind} {name}")
        return None, f"Failed to connect to Kubernetes: {str(error)}"


##############################################################
# Kubernetes Events for Flux Objects
##############################################################

def FluxObjectEvents(
    kind: str,
    name: str,
    namespace: str,
    username_role: str,
    user_token: str,
    limit: int = 50
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Fetch Kubernetes events related to a Flux object.
    
    Args:
        kind: The Flux object kind
        name: The name of the object
        namespace: The namespace of the object
        username_role: User role for authorization
        user_token: User token for authentication
        limit: Maximum number of events to return
        
    Returns:
        Tuple of (events_list, error_message)
        - On success: (events_list, None)
        - On error: ([], error_message)
    """
    k8sClientConfigGet(username_role, user_token)
    core_api = k8s_client.CoreV1Api()
    
    try:
        # Field selector to filter events by involved object
        field_selector = f"involvedObject.name={name},involvedObject.kind={kind}"
        
        events = core_api.list_namespaced_event(
            namespace=namespace,
            field_selector=field_selector,
            limit=limit,
            _request_timeout=5
        )
        
        # Convert to list of dicts and sort by last timestamp (newest first)
        event_list = []
        for event in events.items:
            event_dict = {
                "type": event.type,
                "reason": event.reason,
                "message": event.message,
                "count": event.count or 1,
                "first_timestamp": event.first_timestamp.isoformat() if event.first_timestamp else None,
                "last_timestamp": event.last_timestamp.isoformat() if event.last_timestamp else None,
                "source": event.source.component if event.source else None,
                "reporting_controller": getattr(event, 'reporting_controller', None),
            }
            event_list.append(event_dict)
        
        # Sort by last_timestamp descending (newest first)
        event_list.sort(
            key=lambda x: x.get("last_timestamp") or x.get("first_timestamp") or "",
            reverse=True
        )
        
        return event_list, None
        
    except ApiException as error:
        ErrorHandler(logger, error, f"get events for {kind} {name}")
        return [], f"Failed to get events: {error.reason}"
    except Exception as error:
        ErrorHandler(logger, error, f"get events for {kind} {name}")
        return [], f"Failed to connect to Kubernetes: {str(error)}"


##############################################################
# Get Object with Events (Combined)
##############################################################

def FluxObjectGetWithEvents(
    kind: str,
    name: str,
    namespace: str,
    username_role: str,
    user_token: str
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    """
    Fetch a Flux object along with its Kubernetes events.
    
    Args:
        kind: The Flux object kind
        name: The name of the object
        namespace: The namespace of the object
        username_role: User role for authorization
        user_token: User token for authentication
        
    Returns:
        Tuple of (object_dict, events_list, error_message)
    """
    obj, obj_error = FluxObjectGet(kind, name, namespace, username_role, user_token)
    
    if obj_error:
        return None, [], obj_error
    
    events, events_error = FluxObjectEvents(kind, name, namespace, username_role, user_token)
    
    # Return object even if events fetch failed
    return obj, events, events_error


##############################################################
# Parse Status Conditions
##############################################################

def parse_conditions(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse and format status conditions from a Flux object.
    
    Args:
        obj: The Flux object dictionary
        
    Returns:
        List of condition dictionaries with formatted data
    """
    conditions = []
    status = obj.get("status", {})
    raw_conditions = status.get("conditions", [])
    
    for cond in raw_conditions:
        conditions.append({
            "type": cond.get("type", "Unknown"),
            "status": cond.get("status", "Unknown"),
            "reason": cond.get("reason", ""),
            "message": cond.get("message", ""),
            "last_transition_time": cond.get("lastTransitionTime", ""),
            "observed_generation": cond.get("observedGeneration"),
        })
    
    return conditions


##############################################################
# Get Source Reference Info
##############################################################

def get_source_ref(obj: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Extract source reference from a Flux object (Kustomization or HelmRelease).
    
    Args:
        obj: The Flux object dictionary
        
    Returns:
        Dict with kind, name, namespace of the source, or None
    """
    kind = obj.get("kind")
    spec = obj.get("spec", {})
    metadata = obj.get("metadata", {})
    
    if kind == "Kustomization":
        source_ref = spec.get("sourceRef", {})
        if source_ref:
            return {
                "kind": source_ref.get("kind"),
                "name": source_ref.get("name"),
                "namespace": source_ref.get("namespace", metadata.get("namespace")),
            }
    
    elif kind == "HelmRelease":
        chart = spec.get("chart", {})
        chart_spec = chart.get("spec", {})
        source_ref = chart_spec.get("sourceRef", {})
        if source_ref:
            return {
                "kind": source_ref.get("kind"),
                "name": source_ref.get("name"),
                "namespace": source_ref.get("namespace", metadata.get("namespace")),
            }
    
    return None


##############################################################
# Get Ready Status
##############################################################

def get_ready_status(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get the ready status from a Flux object's conditions.
    
    Args:
        obj: The Flux object dictionary
        
    Returns:
        Dict with ready status info: {ready: bool, reason: str, message: str}
    """
    conditions = obj.get("status", {}).get("conditions", [])
    
    for cond in conditions:
        if cond.get("type") == "Ready":
            return {
                "ready": cond.get("status") == "True",
                "reason": cond.get("reason", ""),
                "message": cond.get("message", ""),
            }
    
    return {
        "ready": False,
        "reason": "Unknown",
        "message": "No Ready condition found",
    }


##############################################################
# Get Last Applied Revision
##############################################################

def get_last_applied_revision(obj: Dict[str, Any]) -> Optional[str]:
    """
    Get the last applied revision from a Flux object's status.
    
    Args:
        obj: The Flux object dictionary
        
    Returns:
        The last applied revision string, or None
    """
    status = obj.get("status", {})
    
    # For sources, check artifact
    artifact = status.get("artifact", {})
    if artifact:
        return artifact.get("revision")
    
    # For Kustomizations/HelmReleases
    return status.get("lastAppliedRevision") or status.get("lastAttemptedRevision")
