"""
FluxCD WebSocket Module

Provides real-time updates for Flux objects via WebSocket connections.
Uses Flask-SocketIO for bidirectional communication.
"""

import functools
import logging
from typing import Dict, Any, Optional
import time

from flask import session
from flask_login import current_user
from flask_socketio import disconnect, join_room, leave_room

from lib.components import socketio
from lib.helper_functions import get_logger
from lib.sso import get_user_token

from .sources import (
    FluxGitRepositoryGet, FluxHelmRepositoryGet, 
    FluxOCIRepositoryGet, FluxBucketRepositoryGet
)
from .kustomizations import FluxKustomizationGet
from .helm_releases import FluxHelmReleaseGet
from .notifications import (
    FluxAlertNotificationGet, FluxProviderNotificationGet, 
    FluxReceiverNotificationGet
)
from .graph import build_flux_graph, get_graph_stats

##############################################################
# Variables
##############################################################

logger = get_logger()

# Suppress noisy socketio logs
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

# Track active subscriptions per session
# Key: session_id, Value: {"namespace": str, "interval": int}
active_subscriptions: Dict[str, Dict[str, Any]] = {}

# Namespace for Flux WebSocket events
FLUX_NAMESPACE = "/flux"


##############################################################
# Authentication Decorator
##############################################################

def authenticated_only(f):
    """Decorator to ensure user is authenticated for WebSocket events."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.warning("Unauthenticated WebSocket connection attempt to Flux namespace")
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped


##############################################################
# WebSocket Event Handlers
##############################################################

@socketio.on("connect", namespace=FLUX_NAMESPACE)
@authenticated_only
def flux_connect():
    """
    Handle client connection to Flux WebSocket namespace.
    """
    logger.debug(f"Client connected to Flux WebSocket: {current_user.username}")
    socketio.emit(
        "connected", 
        {"message": "Connected to Flux updates"}, 
        namespace=FLUX_NAMESPACE
    )


@socketio.on("disconnect", namespace=FLUX_NAMESPACE)
def flux_disconnect():
    """
    Handle client disconnection from Flux WebSocket namespace.
    Clean up any active subscriptions.
    """
    session_id = session.get("_id", "unknown")
    if session_id in active_subscriptions:
        del active_subscriptions[session_id]
    logger.debug(f"Client disconnected from Flux WebSocket")


@socketio.on("flux_subscribe", namespace=FLUX_NAMESPACE)
@authenticated_only
def handle_flux_subscribe(data: Dict[str, Any]):
    """
    Subscribe to Flux object updates for a specific namespace.
    
    Args:
        data: Dictionary containing:
            - namespace: The Kubernetes namespace to watch
            - interval: (optional) Update interval in seconds (default: 10)
    """
    namespace = data.get("namespace", "default")
    interval = data.get("interval", 10)
    
    # Validate interval (min 5 seconds, max 60 seconds)
    interval = max(5, min(60, interval))
    
    session_id = session.get("_id", str(id(session)))
    
    # Store subscription info
    active_subscriptions[session_id] = {
        "namespace": namespace,
        "interval": interval,
        "user_role": session.get("user_role"),
    }
    
    # Join a room for this namespace
    room = f"flux:{namespace}"
    join_room(room)
    
    logger.info(f"User subscribed to Flux updates for namespace: {namespace}")
    
    # Send initial data
    socketio.start_background_task(
        _send_flux_update,
        session_id,
        namespace,
        session.get("user_role"),
        get_user_token(session)
    )
    
    # Start background update task
    socketio.start_background_task(
        _flux_update_loop,
        session_id,
        namespace,
        interval,
        session.get("user_role"),
        get_user_token(session)
    )


@socketio.on("flux_unsubscribe", namespace=FLUX_NAMESPACE)
@authenticated_only
def handle_flux_unsubscribe(data: Dict[str, Any]):
    """
    Unsubscribe from Flux object updates.
    
    Args:
        data: Dictionary containing:
            - namespace: The Kubernetes namespace to stop watching
    """
    namespace = data.get("namespace", "default")
    session_id = session.get("_id", str(id(session)))
    
    # Remove subscription
    if session_id in active_subscriptions:
        del active_subscriptions[session_id]
    
    # Leave the room
    room = f"flux:{namespace}"
    leave_room(room)
    
    logger.info(f"User unsubscribed from Flux updates for namespace: {namespace}")
    
    socketio.emit(
        "flux_unsubscribed",
        {"namespace": namespace},
        namespace=FLUX_NAMESPACE
    )


@socketio.on("flux_refresh", namespace=FLUX_NAMESPACE)
@authenticated_only
def handle_flux_refresh(data: Dict[str, Any]):
    """
    Request an immediate refresh of Flux data.
    
    Args:
        data: Dictionary containing:
            - namespace: The Kubernetes namespace to refresh
    """
    namespace = data.get("namespace", "default")
    
    socketio.start_background_task(
        _send_flux_update,
        session.get("_id", str(id(session))),
        namespace,
        session.get("user_role"),
        get_user_token(session)
    )


##############################################################
# Background Tasks
##############################################################

def _flux_update_loop(
    session_id: str,
    namespace: str,
    interval: int,
    user_role: str,
    user_token: str
):
    """
    Background task that periodically sends Flux updates.
    
    Args:
        session_id: The session ID for the subscription
        namespace: The Kubernetes namespace
        interval: Update interval in seconds
        user_role: User role for authorization
        user_token: User token for authentication
    """
    while session_id in active_subscriptions:
        sub = active_subscriptions.get(session_id, {})
        
        # Check if subscription is still valid and for the same namespace
        if sub.get("namespace") != namespace:
            break
        
        # Wait for the interval
        time.sleep(interval)
        
        # Check again after sleep
        if session_id not in active_subscriptions:
            break
        
        # Send update
        _send_flux_update(session_id, namespace, user_role, user_token)


def _send_flux_update(
    session_id: str,
    namespace: str,
    user_role: str,
    user_token: str
):
    """
    Fetch Flux objects and send update to the client.
    
    Args:
        session_id: The session ID for the subscription
        namespace: The Kubernetes namespace
        user_role: User role for authorization
        user_token: User token for authentication
    """
    try:
        # Fetch all Flux objects
        flux_objects = _fetch_all_flux_objects(namespace, user_role, user_token)
        
        # Build graph data
        graph_data = build_flux_graph(flux_objects)
        stats = get_graph_stats(graph_data)
        
        # Build summary for quick status display
        summary = _build_summary(flux_objects)
        
        # Send to room
        room = f"flux:{namespace}"
        socketio.emit(
            "flux_update",
            {
                "namespace": namespace,
                "timestamp": time.time(),
                "objects": flux_objects,
                "graph": graph_data,
                "stats": stats,
                "summary": summary,
            },
            room=room,
            namespace=FLUX_NAMESPACE
        )
        
    except Exception as error:
        logger.error(f"Error sending Flux update: {error}")
        socketio.emit(
            "flux_error",
            {"message": str(error), "namespace": namespace},
            namespace=FLUX_NAMESPACE
        )


def _fetch_all_flux_objects(
    namespace: str,
    user_role: str,
    user_token: str
) -> Dict[str, Any]:
    """
    Fetch all Flux objects from the cluster.
    
    Args:
        namespace: The Kubernetes namespace
        user_role: User role for authorization
        user_token: User token for authentication
        
    Returns:
        Dictionary of Flux objects by type
    """
    flux_objects = {}
    
    try:
        flux_objects["HelmReleases"] = FluxHelmReleaseGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["HelmReleases"] = []
    
    try:
        flux_objects["Kustomizations"] = FluxKustomizationGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["Kustomizations"] = []
    
    try:
        flux_objects["GitRepositories"] = FluxGitRepositoryGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["GitRepositories"] = []
    
    try:
        flux_objects["HelmRepositories"] = FluxHelmRepositoryGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["HelmRepositories"] = []
    
    try:
        flux_objects["OCIRepositories"] = FluxOCIRepositoryGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["OCIRepositories"] = []
    
    try:
        flux_objects["Buckets"] = FluxBucketRepositoryGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["Buckets"] = []
    
    try:
        flux_objects["Alerts"] = FluxAlertNotificationGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["Alerts"] = []
    
    try:
        flux_objects["Providers"] = FluxProviderNotificationGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["Providers"] = []
    
    try:
        flux_objects["Receivers"] = FluxReceiverNotificationGet(user_role, user_token, namespace) or []
    except Exception:
        flux_objects["Receivers"] = []
    
    return flux_objects


def _build_summary(flux_objects: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a summary of Flux objects status.
    
    Args:
        flux_objects: Dictionary of Flux objects by type
        
    Returns:
        Summary dictionary with counts and status breakdown
    """
    summary = {
        "total": 0,
        "ready": 0,
        "not_ready": 0,
        "suspended": 0,
        "by_kind": {}
    }
    
    for kind, objects in flux_objects.items():
        if not objects:
            continue
        
        kind_summary = {
            "total": len(objects),
            "ready": 0,
            "not_ready": 0,
            "suspended": 0,
        }
        
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            
            summary["total"] += 1
            
            # Check suspended
            if obj.get("spec", {}).get("suspend", False):
                summary["suspended"] += 1
                kind_summary["suspended"] += 1
                continue
            
            # Check Ready condition
            conditions = obj.get("status", {}).get("conditions", [])
            is_ready = False
            for cond in conditions:
                if cond.get("type") == "Ready":
                    is_ready = cond.get("status") == "True"
                    break
            
            if is_ready:
                summary["ready"] += 1
                kind_summary["ready"] += 1
            else:
                summary["not_ready"] += 1
                kind_summary["not_ready"] += 1
        
        summary["by_kind"][kind] = kind_summary
    
    return summary
