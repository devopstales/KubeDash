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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/rbac/service-accounts
    return render_template('cluster-permission/service-account.html.j2')


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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/rbac/roles
    return render_template('cluster-permission/role.html.j2')

@cluster_permission_bp.route("/role/data", methods=['GET', 'POST'])
@login_required
def role_data():
    """
    Role detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        r_name = request.form.get('r_name')

    # Template now loads data via JavaScript from /api/v1/rbac/roles/<name>
    return render_template('cluster-permission/role-data.html.j2')
    
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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('rb_name')

    # Template now loads data via JavaScript from /api/v1/rbac/role-bindings
    return render_template('cluster-permission/role-binding.html.j2')

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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected')

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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        cr_name = request.form.get('cr_name')

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
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        crb_name = request.form.get('crb_name')

    # Template now loads data via JavaScript from /api/v1/rbac/cluster-role-bindings
    return render_template('cluster-permission/cluster-role-binding.html.j2')


