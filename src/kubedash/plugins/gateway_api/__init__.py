#!/usr/bin/env python3
"""
Gateway API Plugin for KubeDash

This plugin provides visibility into Kubernetes Gateway API resources,
including GatewayClasses, Gateways, HTTPRoutes, and other route types.

Routes:
- /plugins/gateway-api: Main view with tabs for all resources
- /plugins/gateway-api/gateway/<ns>/<name>: Gateway detail view
- /plugins/gateway-api/httproute/<ns>/<name>: HTTPRoute detail view
"""

import json

from flask import Blueprint, redirect, render_template, request, session, url_for
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .functions import (
    check_gateway_api_installed,
    GatewayApiGetGatewayClasses,
    GatewayApiGetGatewayClass,
    GatewayApiGetGateways,
    GatewayApiGetGateway,
    GatewayApiGetHTTPRoutes,
    GatewayApiGetHTTPRoute,
    GatewayApiGetGRPCRoutes,
    GatewayApiGetTCPRoutes,
    GatewayApiGetTLSRoutes,
    GatewayApiGetReferenceGrants,
    GatewayApiGetBackendTLSPolicies,
    GatewayApiGetEvents,
)

##############################################################
## Variables
##############################################################

gateway_api_bp = Blueprint(
    "gateway_api",
    __name__,
    url_prefix="/plugins",
    template_folder="templates"
)
logger = get_logger()

##############################################################
# Main Gateway API View
##############################################################

@gateway_api_bp.route("/gateway-api", methods=['GET', 'POST'])
@login_required
def gateway_api():
    """Main Gateway API view with tabs for all resource types."""
    user_token = get_user_token(session)
    active_tab = request.args.get('tab', 'gatewayclasses')
    
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')
    
    # Get namespace list
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if error:
        namespace_list = []
    
    # Check if Gateway API is installed
    gateway_api_status = check_gateway_api_installed(session['user_role'], user_token)
    
    # Fetch all resource types
    gateway_classes = []
    gateways = []
    httproutes = []
    grpcroutes = []
    tcproutes = []
    tlsroutes = []
    referencegrants = []
    backendtlspolicies = []
    
    if gateway_api_status.get('installed', False):
        # Always fetch GatewayClasses (cluster-scoped)
        gateway_classes = GatewayApiGetGatewayClasses(session['user_role'], user_token)
        
        # Fetch namespaced resources based on selected namespace
        ns = session.get('ns_select', 'default')
        
        gateways = GatewayApiGetGateways(session['user_role'], user_token, ns)
        httproutes = GatewayApiGetHTTPRoutes(session['user_role'], user_token, ns)
        
        # Fetch experimental resources if available
        if 'grpcroutes' in gateway_api_status.get('experimental', []):
            grpcroutes = GatewayApiGetGRPCRoutes(session['user_role'], user_token, ns)
        if 'tcproutes' in gateway_api_status.get('experimental', []):
            tcproutes = GatewayApiGetTCPRoutes(session['user_role'], user_token, ns)
        if 'tlsroutes' in gateway_api_status.get('experimental', []):
            tlsroutes = GatewayApiGetTLSRoutes(session['user_role'], user_token, ns)
        if 'backendtlspolicies' in gateway_api_status.get('experimental', []):
            backendtlspolicies = GatewayApiGetBackendTLSPolicies(session['user_role'], user_token, ns)
        
        # ReferenceGrants (standard v1)
        if 'referencegrants' in gateway_api_status.get('standard', []):
            referencegrants = GatewayApiGetReferenceGrants(session['user_role'], user_token, ns)
    
    return render_template(
        'gateway-api.html.j2',
        namespaces=namespace_list,
        gateway_api_status=gateway_api_status,
        gateway_classes=gateway_classes,
        gateways=gateways,
        httproutes=httproutes,
        grpcroutes=grpcroutes,
        tcproutes=tcproutes,
        tlsroutes=tlsroutes,
        referencegrants=referencegrants,
        backendtlspolicies=backendtlspolicies,
        active_tab=active_tab,
    )


##############################################################
# GatewayClass Detail View
##############################################################

@gateway_api_bp.route("/gateway-api/gatewayclass/<name>", methods=['GET'])
@login_required
def gatewayclass_detail(name):
    """GatewayClass detail view."""
    user_token = get_user_token(session)
    
    gateway_class = GatewayApiGetGatewayClass(session['user_role'], user_token, name)
    
    if not gateway_class:
        return redirect(url_for('gateway_api.gateway_api'))
    
    # Get gateways using this class
    all_gateways = GatewayApiGetGateways(session['user_role'], user_token, None)
    using_gateways = [gw for gw in all_gateways if gw.get('gateway_class') == name]
    
    # Get events (GatewayClass is cluster-scoped, so namespace is None)
    # Use UID if available for more precise matching
    uid = gateway_class.get('raw', {}).get('metadata', {}).get('uid') if gateway_class else None
    events, _ = GatewayApiGetEvents('GatewayClass', name, None, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'gatewayclass-detail.html.j2',
        gateway_class=gateway_class,
        using_gateways=using_gateways,
        events=events,
    )


##############################################################
# Gateway Detail View
##############################################################

@gateway_api_bp.route("/gateway-api/gateway/<namespace>/<name>", methods=['GET'])
@login_required
def gateway_detail(namespace, name):
    """Gateway detail view."""
    user_token = get_user_token(session)
    
    gateway = GatewayApiGetGateway(session['user_role'], user_token, namespace, name)
    
    if not gateway:
        return redirect(url_for('gateway_api.gateway_api'))
    
    # Get HTTPRoutes attached to this gateway
    all_httproutes = GatewayApiGetHTTPRoutes(session['user_role'], user_token, None)
    attached_httproutes = []
    for route in all_httproutes:
        for gw in route.get('gateways', []):
            if gw == f"{namespace}/{name}" or gw.endswith(f"/{name}"):
                attached_httproutes.append(route)
                break
    
    # Get events - use UID if available for more precise matching
    uid = gateway.get('raw', {}).get('metadata', {}).get('uid') if gateway else None
    events, _ = GatewayApiGetEvents('Gateway', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'gateway-detail.html.j2',
        gateway=gateway,
        attached_httproutes=attached_httproutes,
        events=events,
    )


##############################################################
# HTTPRoute Detail View
##############################################################

@gateway_api_bp.route("/gateway-api/httproute/<namespace>/<name>", methods=['GET'])
@login_required
def httproute_detail(namespace, name):
    """HTTPRoute detail view."""
    user_token = get_user_token(session)
    
    httproute = GatewayApiGetHTTPRoute(session['user_role'], user_token, namespace, name)
    
    if not httproute:
        return redirect(url_for('gateway_api.gateway_api'))
    
    # Get events - use UID if available for more precise matching
    uid = httproute.get('raw', {}).get('metadata', {}).get('uid') if httproute else None
    events, _ = GatewayApiGetEvents('HTTPRoute', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'httproute-detail.html.j2',
        httproute=httproute,
        events=events,
    )


##############################################################
# API Endpoints for AJAX calls (optional)
##############################################################

@gateway_api_bp.route("/gateway-api/api/gateways", methods=['GET'])
@login_required
def api_gateways():
    """API endpoint to get gateways for a specific namespace."""
    user_token = get_user_token(session)
    namespace = request.args.get('namespace', session.get('ns_select', 'default'))
    
    gateways = GatewayApiGetGateways(session['user_role'], user_token, namespace)
    
    return {"gateways": gateways}


@gateway_api_bp.route("/gateway-api/api/httproutes", methods=['GET'])
@login_required
def api_httproutes():
    """API endpoint to get HTTPRoutes for a specific namespace."""
    user_token = get_user_token(session)
    namespace = request.args.get('namespace', session.get('ns_select', 'default'))
    
    httproutes = GatewayApiGetHTTPRoutes(session['user_role'], user_token, namespace)
    
    return {"httproutes": httproutes}
