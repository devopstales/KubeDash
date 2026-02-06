from math import e
from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import (k8sClusterRoleBindingListGet, k8sRoleGet,
                              k8sClusterRoleListGet, k8sClusterRoleGet, 
                              k8sRoleBindingListGet,
                              k8sRoleListGet, k8sSaListGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

cluster_permission_bp = Blueprint("cluster_permission", __name__, url_prefix="/cluster-permission")
logger = get_logger()

##############################################################
## cluster-permission Pages
##############################################################
## Service Account
##############################################################

@cluster_permission_bp.route("/service-account", methods=['GET', 'POST'])
@login_required
def service_accounts():
    """
    Service Accounts list page.
    
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
            return redirect(url_for('cluster_permission.service_accounts', **params))
        return redirect(url_for('cluster_permission.service_accounts'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/rbac/service-accounts
    return render_template('cluster-permission/service-account.html.j2', namespaces=namespaces)


##############################################################
##  Role
##############################################################

@cluster_permission_bp.route("/role", methods=['GET', 'POST'])
@login_required
def roles():
    """
    Roles list page.
    
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
            return redirect(url_for('cluster_permission.roles', **params))
        return redirect(url_for('cluster_permission.roles'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/rbac/roles
    return render_template('cluster-permission/role.html.j2', namespaces=namespaces)

@cluster_permission_bp.route("/role/data", methods=['GET', 'POST'])
@login_required
def role_data():
    """
    Role detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect to GET with query parameters
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        r_name = request.form.get('r_name')
        namespace = request.form.get('ns_select', session.get('ns_select', 'default'))
        if r_name:
            return redirect(url_for('cluster_permission.role_data', r_name=r_name, namespace=namespace))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/rbac/roles/<name>
    return render_template('cluster-permission/role-data.html.j2', namespaces=namespaces)
    
##############################################################
##  Role Binding
##############################################################

@cluster_permission_bp.route("/role-binding", methods=['GET', 'POST'])
@login_required
def role_bindings():
    """
    Role Bindings list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected') or request.form.get('rb_name')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('cluster_permission.role_bindings', **params))
        return redirect(url_for('cluster_permission.role_bindings'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/rbac/role-bindings
    return render_template('cluster-permission/role-binding.html.j2', namespaces=namespaces)

##############################################################
## Cluster Role
##############################################################

@cluster_permission_bp.route("/cluster-role", methods=['GET', 'POST'])
@login_required
def cluster_roles():
    """
    Cluster Roles list page.
    
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
            return redirect(url_for('cluster_permission.cluster_roles', **params))
        return redirect(url_for('cluster_permission.cluster_roles'))

    # Cluster roles are cluster-scoped, no namespace selector needed
    # Template now loads data via JavaScript from /api/v1/rbac/cluster-roles
    return render_template('cluster-permission/cluster-role.html.j2')

@cluster_permission_bp.route("/cluster-role/data", methods=['GET', 'POST'])
@login_required
def cluster_role_data():
    """
    Cluster Role detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect to GET with query parameters
    if request.method == 'POST':
        cr_name = request.form.get('cr_name')
        if cr_name:
            return redirect(url_for('cluster_permission.cluster_role_data', cr_name=cr_name))

    # Cluster roles are cluster-scoped, no namespace selector needed
    # Template now loads data via JavaScript from /api/v1/rbac/cluster-roles/<name>
    return render_template('cluster-permission/cluster-role-data.html.j2')
    
##############################################################
## Cluster Role Bindings
##############################################################

@cluster_permission_bp.route("/cluster-role-binding", methods=["GET", "POST"])
@login_required
def cluster_role_bindings():
    """
    Cluster Role Bindings list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        selected = request.form.get('selected') or request.form.get('crb_name')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('cluster_permission.cluster_role_bindings', **params))
        return redirect(url_for('cluster_permission.cluster_role_bindings'))

    # Cluster role bindings are cluster-scoped, no namespace selector needed
    # Template now loads data via JavaScript from /api/v1/rbac/cluster-role-bindings
    return render_template('cluster-permission/cluster-role-binding.html.j2')


