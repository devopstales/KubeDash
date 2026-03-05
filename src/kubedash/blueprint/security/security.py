from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.other import k8sPriorityClassList
from lib.k8s.security import k8sPolicyListGet, k8sSecretListGet
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

security_bp = Blueprint("security", __name__, url_prefix="/security")
logger = get_logger()

##############################################################
# Security
##############################################################
## Secrets
##############################################################

@security_bp.route("/secret", methods=['GET', 'POST'])
@login_required
def secrets():
    """
    Secrets list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('security.secrets', **params))
        return redirect(url_for('security.secrets'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/security/secrets
    return render_template('security/secret.html.j2', namespaces=namespaces)

@security_bp.route('/secret/data', methods=['GET', 'POST'])
@login_required
def secrets_data():
    """
    Secret detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/security/secrets/<name>
    return render_template('security/secret-data.html.j2', namespaces=namespaces)
    
##############################################################
## Network Policies
##############################################################

@security_bp.route('/network-policy', methods=['GET', 'POST'])
@login_required
def policies_list():
    """
    Network Policies list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('security.policies_list', **params))
        return redirect(url_for('security.policies_list'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/security/network-policies
    return render_template('security/network-policy.html.j2', namespaces=namespaces)

@security_bp.route('/network-policy/data', methods=['GET', 'POST'])
@login_required
def policies_data():
    """
    Network Policy detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/security/network-policies/<name>
    return render_template('security/network-policy-data.html.j2', namespaces=namespaces)

##############################################################
## PriorityClass
##############################################################
@security_bp.route('/priorityclass', methods=['GET', 'POST'])
@login_required
def priorityclass_list():
    """
    Priority Classes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('security.priorityclass_list', **params))
        return redirect(url_for('security.priorityclass_list'))

    # Template now loads data via JavaScript from /api/v1/other-resources/priority-classes
    return render_template('security/priority-class.html.j2')

@security_bp.route('/priorityclass/data', methods=['GET', 'POST'])
@login_required
def priorityclass_data():
    """
    Priority Class detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/priority-classes/<name>
    return render_template('security/priority-class-data.html.j2')
