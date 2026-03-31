#!/usr/bin/env python3

import ast

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .helper import (bgpadvertisementsTest, bgppeersTest, ipaddresspoolTest,
                     l2advertisementsTest)

##############################################################
## variables
##############################################################

external_loadbalancer_bp = Blueprint("external_loadbalancer", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# exLB Routes
##############################################################

@external_loadbalancer_bp.route('/external-loadbalancer', methods=['GET', 'POST'])
@login_required
def external_loadbalancer():
    """
    External LoadBalancer list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure and provides namespaces.
    """
    from lib.helper_functions import validate_namespace, validate_no_path_traversal
    
    selected = None
    selected_type = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        # Validate namespace to prevent path traversal and injection
        if request.form.get('ns_select', None):
            namespace = request.form.get('ns_select', '').strip()
            if namespace:
                is_valid, error_msg = validate_namespace(namespace)
                if is_valid:
                    session['ns_select'] = namespace
                else:
                    from flask import flash
                    flash(f"Invalid namespace: {error_msg}", "danger")
        
        # Validate selected and object_type parameters
        selected = request.form.get('selected', '').strip()
        if selected:
            is_valid_sel, error_msg_sel = validate_no_path_traversal(selected)
            if not is_valid_sel:
                from flask import flash
                flash(f"Invalid selection: {error_msg_sel}", "danger")
                selected = ''
        
        selected_type = request.form.get('object_type', '').strip()
        if selected_type:
            is_valid_type, error_msg_type = validate_no_path_traversal(selected_type)
            if not is_valid_type:
                from flask import flash
                flash(f"Invalid object type: {error_msg_type}", "danger")
                selected_type = ''

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    return render_template(
        'external-loadbalancer.html.j2',
        namespaces = namespaces,
        selected=selected,
        selected_type=selected_type,
    )

@external_loadbalancer_bp.route('/external-loadbalancer/data', methods=['GET', 'POST'])
@login_required
def external_loadbalancer_data():
    """
    External LoadBalancer detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    from lib.helper_functions import validate_namespace, validate_no_path_traversal
    from flask import flash
    
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        # Validate namespace
        ns_select = request.form.get('ns_select', '').strip()
        if ns_select:
            is_valid_ns, error_msg_ns = validate_namespace(ns_select)
            if is_valid_ns:
                session['ns_select'] = ns_select
            else:
                flash(f"Invalid namespace: {error_msg_ns}", "danger")
                ns_select = ''
        
        # Validate selected parameter
        selected = request.form.get('selected', '').strip()
        if selected:
            is_valid_sel, error_msg_sel = validate_no_path_traversal(selected)
            if not is_valid_sel:
                flash(f"Invalid selection: {error_msg_sel}", "danger")
                selected = ''
        
        # Validate object_type parameter
        object_type = request.form.get('object_type', '').strip()
        if object_type:
            is_valid_type, error_msg_type = validate_no_path_traversal(object_type)
            if not is_valid_type:
                flash(f"Invalid object type: {error_msg_type}", "danger")
                object_type = ''
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        if object_type:
            params['object_type'] = object_type
        if ns_select:
            params['namespace'] = ns_select
        # Note: object_data is complex, so we'll use sessionStorage on client side
        
        # Redirect to GET request with query parameters
        return redirect(url_for('.external_loadbalancer_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from sessionStorage
    return render_template('external-loadbalancer-data.html.j2', namespaces=namespaces)
