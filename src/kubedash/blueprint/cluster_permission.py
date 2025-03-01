from flask import Blueprint, render_template, session, request, redirect, url_for
from flask_login import login_required

from lib.sso import get_user_token
from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet 
from lib.k8s.security import k8sSaListGet, k8sRoleListGet, k8sRoleBindingListGet, \
    k8sClusterRoleListGet, k8sClusterRoleBindingListGet

##############################################################
## Helpers
##############################################################

cluster_permission = Blueprint("cluster_permission", __name__, url_prefix="/cluster-permission")
logger = get_logger()

##############################################################
## cluster-permission Pages
##############################################################
## Service Account
##############################################################

@cluster_permission.route("/service-account", methods=['GET', 'POST'])
@login_required
def service_accounts():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        service_accounts = k8sSaListGet(session['user_role'], user_token, session['ns_select'])
    else:
        service_accounts = list()

    return render_template(
        'cluster-permission/service-account.html.j2',
        selected = selected,
        service_accounts = service_accounts,
        namespaces = namespace_list,
    )


##############################################################
##  Role
##############################################################

@cluster_permission.route("/role", methods=['GET', 'POST'])
@login_required
def roles():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        roles = k8sRoleListGet(session['user_role'], user_token, session['ns_select'])
    else:
        roles = list()

    return render_template(
        'cluster-permission/role.html.j2',
        selected = selected,
        roles = roles,
        namespaces = namespace_list,
    )

@cluster_permission.route("/role/data", methods=['GET', 'POST'])
@login_required
def role_data():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        r_name = request.form.get('r_name')
        
        user_token = get_user_token(session)
        
        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            roles = k8sRoleListGet(session['user_role'], user_token, session['ns_select'])
        else:
            roles = list()

        return render_template(
            'cluster-permission/role-data.html.j2',
            namespace_list = namespace_list,
            roles = roles,
            r_name = r_name,
        )
    else:
        return redirect(url_for('auth.login'))
    
##############################################################
##  Role Binding
##############################################################

@cluster_permission.route("/role-binding", methods=['GET', 'POST'])
@login_required
def role_bindings():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('rb_name')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        role_bindings, error = k8sRoleBindingListGet(session['user_role'], user_token, session['ns_select'])
    else:
        role_bindings = list()

    return render_template(
        'cluster-permission/role-binding.html.j2',
        role_bindings = role_bindings,
        namespaces = namespace_list,
        selected = selected,
    )

##############################################################
## Cluster Role
##############################################################

@cluster_permission.route("/cluster-role", methods=['GET', 'POST'])
@login_required
def cluster_roles():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)

    return render_template(
        'cluster-permission/cluster-role.html.j2',
        cluster_roles = cluster_roles,
        selected = selected,
    )

@cluster_permission.route("/cluster-role/data", methods=['GET', 'POST'])
@login_required
def cluster_role_data():
    if request.method == 'POST':
        cr_name = request.form.get('cr_name')
        user_token = get_user_token(session)
        cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)


        return render_template(
            'cluster-permission/cluster-role-data.html.j2',
            cluster_roles = cluster_roles,
            cr_name = cr_name,
        )
    else:
        return redirect(url_for('auth.login'))
    
##############################################################
## Cluster Role Bindings
##############################################################

@cluster_permission.route("/cluster-role-binding", methods=["GET", "POST"])
@login_required
def cluster_role_bindings():
    crb_name = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        crb_name = request.form.get('crb_name')

    cluster_role_bindings, error = k8sClusterRoleBindingListGet(session['user_role'], user_token)
    return render_template(
        'cluster-permission/cluster-role-binding.html.j2',
        cluster_role_bindings = cluster_role_bindings,
        crb_name = crb_name,
    )


