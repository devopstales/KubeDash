#!/usr/bin/env python3
"""
FluxCD Plugin for KubeDash

Provides visualization and management of FluxCD GitOps objects including:
- Sources: GitRepository, HelmRepository, OCIRepository, Bucket
- Reconcilers: Kustomization, HelmRelease
- Notifications: Alert, Provider, Receiver
"""

import json

from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespaceListGet

from .helm_releases import FluxHelmReleaseGet
from .kustomizations import FluxKustomizationGet
from .notifications import FluxAlertNotificationGet, FluxProviderNotificationGet, FluxReceiverNotificationGet
from .sources import FluxBucketRepositoryGet, FluxGitRepositoryGet, FluxHelmRepositoryGet, FluxOCIRepositoryGet
from .actions import SuspendAction, ResumeAction, SyncAction
from .details import (
    FluxObjectGet, FluxObjectGetWithEvents, 
    parse_conditions, get_source_ref, get_ready_status, get_last_applied_revision,
    FLUX_OBJECT_TYPES
)
from .graph import build_flux_graph, get_graph_stats

# Import websocket handlers to register them
from . import websocket  # noqa: F401


##############################################################
## Variables
##############################################################

flux_bp = Blueprint("flux", __name__, url_prefix="/plugins",
    template_folder="templates")
logger = get_logger()


##############################################################
# Main Flux Objects List View
##############################################################

@flux_bp.route("/flux", methods=['GET', 'POST'])
@login_required
def get_flux_objects():
    """
    Main Flux objects list view.
    Displays all Flux objects in a tabbed interface.
    """
    selected = None
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
            
    flux_objects = _fetch_all_flux_objects(user_token)
    
    # Build graph data for the connections tab
    graph_data = build_flux_graph(flux_objects)
    graph_stats = get_graph_stats(graph_data)
       
    return render_template("flux_objects.html.j2",
        namespaces=namespace_list,
        selected=selected,
        flux_objects=flux_objects,
        graph_data=json.dumps(graph_data),
        graph_stats=graph_stats,
        ns_select=session.get('ns_select', 'default'),
    )


##############################################################
# Detail View Route
##############################################################

@flux_bp.route("/flux/detail/<kind>/<namespace>/<name>", methods=['GET'])
@login_required
def get_flux_detail(kind: str, namespace: str, name: str):
    """
    Detail view for a single Flux object.
    Shows full object details, conditions, and events.
    
    Args:
        kind: The Flux object kind (e.g., GitRepository, Kustomization)
        namespace: The Kubernetes namespace
        name: The object name
    """
    user_token = get_user_token(session)
    
    # Validate kind
    if kind not in FLUX_OBJECT_TYPES:
        return render_template("errors/404.html.j2", 
            message=f"Unknown Flux object kind: {kind}"), 404
    
    # Fetch the object with events
    obj, events, error = FluxObjectGetWithEvents(
        kind=kind,
        name=name,
        namespace=namespace,
        username_role=session['user_role'],
        user_token=user_token
    )
    
    if error and obj is None:
        return render_template("errors/404.html.j2", 
            message=error), 404
    
    # Parse additional info
    conditions = parse_conditions(obj) if obj else []
    source_ref = get_source_ref(obj) if obj else None
    ready_status = get_ready_status(obj) if obj else {"ready": False, "reason": "Unknown", "message": ""}
    last_revision = get_last_applied_revision(obj) if obj else None
    
    # Get object type info
    obj_type = FLUX_OBJECT_TYPES.get(kind, {})
    
    return render_template("flux_detail.html.j2",
        flux_object=obj,
        kind=kind,
        name=name,
        namespace=namespace,
        conditions=conditions,
        events=events,
        source_ref=source_ref,
        ready_status=ready_status,
        last_revision=last_revision,
        obj_type=obj_type,
        ns_select=namespace,
    )


##############################################################
# Graph Data API Endpoint
##############################################################

@flux_bp.route("/flux/api/graph", methods=['GET'])
@login_required
def get_flux_graph_data():
    """
    API endpoint to get graph data for visualization.
    Returns JSON data for Cytoscape.js.
    """
    user_token = get_user_token(session)
    namespace = request.args.get('namespace', session.get('ns_select', 'default'))
    
    # Temporarily set ns_select for fetching
    original_ns = session.get('ns_select')
    session['ns_select'] = namespace
    
    flux_objects = _fetch_all_flux_objects(user_token)
    
    # Restore original ns_select
    if original_ns:
        session['ns_select'] = original_ns
    
    graph_data = build_flux_graph(flux_objects)
    stats = get_graph_stats(graph_data)
    
    return jsonify({
        "graph": graph_data,
        "stats": stats,
        "namespace": namespace,
    })


##############################################################
# Object Summary API Endpoint
##############################################################

@flux_bp.route("/flux/api/summary", methods=['GET'])
@login_required
def get_flux_summary():
    """
    API endpoint to get a summary of Flux objects.
    Returns counts and status breakdown.
    """
    user_token = get_user_token(session)
    namespace = request.args.get('namespace', session.get('ns_select', 'default'))
    
    # Temporarily set ns_select for fetching
    original_ns = session.get('ns_select')
    session['ns_select'] = namespace
    
    flux_objects = _fetch_all_flux_objects(user_token)
    
    # Restore original ns_select
    if original_ns:
        session['ns_select'] = original_ns
    
    summary = {
        "namespace": namespace,
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
    
    return jsonify(summary)


##############################################################
# Suspend, Resume, Sync Actions
##############################################################

@flux_bp.route("/flux/suspend", methods=['POST'])
@login_required
def flux_suspend():
    """
    Suspend action for Flux objects.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        SuspendAction(flux_object, session['user_role'], user_token)
        
        # Check if this came from detail view
        if request.form.get('return_to_detail'):
            return redirect(url_for('flux.get_flux_detail',
                kind=flux_object.get('kind'),
                namespace=flux_object.get('metadata', {}).get('namespace'),
                name=flux_object.get('metadata', {}).get('name')
            ))
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))
    

@flux_bp.route("/flux/resume", methods=['POST'])
@login_required
def flux_resume():
    """
    Resume action for Flux objects.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        ResumeAction(flux_object, session['user_role'], user_token)
        
        # Check if this came from detail view
        if request.form.get('return_to_detail'):
            return redirect(url_for('flux.get_flux_detail',
                kind=flux_object.get('kind'),
                namespace=flux_object.get('metadata', {}).get('namespace'),
                name=flux_object.get('metadata', {}).get('name')
            ))
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))
    

@flux_bp.route("/flux/sync", methods=['POST'])
@login_required
def flux_sync():
    """
    Sync action for Flux objects.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        SyncAction(flux_object, session['user_role'], user_token)
        
        # Check if this came from detail view
        if request.form.get('return_to_detail'):
            return redirect(url_for('flux.get_flux_detail',
                kind=flux_object.get('kind'),
                namespace=flux_object.get('metadata', {}).get('namespace'),
                name=flux_object.get('metadata', {}).get('name')
            ))
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))


##############################################################
# Helper Functions
##############################################################

def _fetch_all_flux_objects(user_token: str) -> dict:
    """
    Fetch all Flux objects from the cluster.
    
    Args:
        user_token: User token for authentication
        
    Returns:
        Dictionary of Flux objects by type
    """
    user_role = session['user_role']
    ns_select = session.get('ns_select', 'default')
    
    flux_objects = {}
    
    try:
        flux_objects["HelmReleases"] = FluxHelmReleaseGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["HelmReleases"] = []
    
    try:
        flux_objects["Kustomizations"] = FluxKustomizationGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["Kustomizations"] = []
    
    try:
        flux_objects["Alerts"] = FluxAlertNotificationGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["Alerts"] = []
    
    try:
        flux_objects["Providers"] = FluxProviderNotificationGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["Providers"] = []
    
    try:
        flux_objects["Receivers"] = FluxReceiverNotificationGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["Receivers"] = []
    
    try:
        flux_objects["Buckets"] = FluxBucketRepositoryGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["Buckets"] = []
    
    try:
        flux_objects["GitRepositories"] = FluxGitRepositoryGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["GitRepositories"] = []
    
    try:
        flux_objects["HelmRepositories"] = FluxHelmRepositoryGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["HelmRepositories"] = []
    
    try:
        flux_objects["OCIRepositories"] = FluxOCIRepositoryGet(user_role, user_token, ns_select) or []
    except Exception:
        flux_objects["OCIRepositories"] = []
    
    return flux_objects
