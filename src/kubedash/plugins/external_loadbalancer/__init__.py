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
    selected = None
    selected_type = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        selected_type = request.form.get('object_type')

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
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        object_type = request.form.get('object_type')
        ns_select = request.form.get('ns_select')
        
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
