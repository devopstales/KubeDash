#!/usr/bin/env python3

import ast

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .functions import (CertificateRequestsGet, CertificatesGet,
                        ClusterIssuerGet, IssuerGet)

##############################################################
## variables
##############################################################

cert_manager_bp = Blueprint("cert_manager", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# Cert-Manager Routes
##############################################################

@cert_manager_bp.route('/cert-manager', methods=['GET', 'POST'])
@login_required
def cert_manager():
    """
    Cert-Manager list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure and provides namespaces.
    """
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    return render_template(
        'cert-manager.html.j2',
        namespaces = namespaces,
        selected = selected,
    )

@cert_manager_bp.route('/cert-manager/data', methods=['GET', 'POST'])
@login_required
def cert_manager_data():
    """
    Cert-Manager detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        object_data_str = request.form.get('object_data')
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
        return redirect(url_for('.cert_manager_data', **params))
    
    # Get namespaces for topbar selector (if needed for namespaced resources)
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from sessionStorage
    return render_template('cert-manager-data.html.j2', namespaces=namespaces)
