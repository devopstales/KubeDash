from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.network import (k8sIngressClassListGet, k8sIngressListGet,
                             k8sPodSelectorListGet, k8sServiceListGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

network_bp = Blueprint("network", __name__, url_prefix="/network")
logger = get_logger()

##############################################################
# Network
##############################################################
## Ingress (Combined Ingress and IngressClass)
##############################################################

@network_bp.route("/ingress", methods=['GET', 'POST'])
@login_required
def ingresses():
    """
    Main Ingress view with tabs for Ingress and IngressClass resources.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    from lib.helper_functions import validate_namespace, validate_no_path_traversal
    
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        # Validate namespace to prevent path traversal and injection
        if 'ns_select' in request.form:
            namespace = request.form.get('ns_select', '').strip()
            if namespace:
                is_valid, error_msg = validate_namespace(namespace)
                if is_valid:
                    session['ns_select'] = namespace
                else:
                    flash(f"Invalid namespace: {error_msg}", "danger")
        
        # Validate active_tab parameter
        active_tab = request.form.get('active_tab', '').strip()
        if active_tab:
            is_valid_tab, error_msg_tab = validate_no_path_traversal(active_tab)
            if not is_valid_tab:
                flash(f"Invalid tab selection: {error_msg_tab}", "danger")
                active_tab = ''

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/network/ingress and /api/v1/network/ingress-classes
    return render_template('network/ingress.html.j2', namespaces=namespaces)

@network_bp.route("/ingress-class", methods=['GET', 'POST'])
@login_required
def ingresses_class():
    """
    IngressClasses list page.
    
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
            return redirect(url_for('.ingresses_class', **params))
        return redirect(url_for('.ingresses_class'))

    # Template now loads data via JavaScript from /api/v1/network/ingress-classes
    return render_template('network/ingress-class.html.j2')

@network_bp.route('/ingress/data', methods=['GET', 'POST'])
@login_required
def ingresses_data():
    """
    Ingress detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    from lib.helper_functions import validate_namespace, validate_k8s_resource_name
    
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        # Validate ingress name
        i_name = request.form.get('i_name', '').strip()
        if i_name:
            is_valid_name, error_msg_name = validate_k8s_resource_name(i_name, "ingress")
            if not is_valid_name:
                flash(f"Invalid ingress name: {error_msg_name}", "danger")
                i_name = ''
        
        # Validate namespace
        ns_select = request.form.get('ns_select', '').strip()
        if ns_select:
            is_valid_ns, error_msg_ns = validate_namespace(ns_select)
            if not is_valid_ns:
                flash(f"Invalid namespace: {error_msg_ns}", "danger")
                ns_select = ''
        
        # Build query parameters
        params = {}
        if i_name:
            params['i_name'] = i_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('.ingresses_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/network/ingress/<name>
    return render_template('network/ingress-data.html.j2', namespaces=namespaces)

@network_bp.route('/ingress-class/data', methods=['GET', 'POST'])
@login_required
def ingresses_class_data():
    """
    IngressClass detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        ic_name = request.form.get('ic_name')
        
        # Build query parameters
        params = {}
        if ic_name:
            params['ic_name'] = ic_name
        
        # Redirect to GET request with query parameters
        return redirect(url_for('.ingresses_class_data', **params))

    # Template now loads data via JavaScript from /api/v1/network/ingress-classes/<name>
    # Note: IngressClasses are cluster-scoped, so no namespace selector needed
    return render_template('network/ingress-class-data.html.j2')

##############################################################
# Service
##############################################################

@network_bp.route("/service", methods=['GET', 'POST'])
@login_required
def services():
    """
    Services list page.
    
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
            return redirect(url_for('.services', **params))
        return redirect(url_for('.services'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/network/services
    return render_template('network/service.html.j2', namespaces=namespaces)

@network_bp.route('/service/data', methods=['GET', 'POST'])
@login_required
def services_data():
    """
    Service detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if service_name:
            params['service_name'] = service_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('.services_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/network/services/<name>
    return render_template('network/service-data.html.j2', namespaces=namespaces)
