from flask import Blueprint, request, session,render_template, redirect, url_for, flash
from flask_login import login_required
from werkzeug.security import check_password_hash


from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sCreateUser, k8sServerContextsList, \
    k8sUserPriviligeList, k8sClusterRoleBindingAdd, k8sRoleBindingAdd, k8sUserRoleTemplateListGet, \
    k8sUserClusterRoleTemplateListGet, k8sClusterRoleBindingGroupGet, k8sRoleBindingGroupGet, \
    k8sSaListGet, k8sRoleListGet, k8sRoleBindingListGet, k8sClusterRoleListGet, k8sClusterRoleBindingListGet

from lib_functions.helper_functions import get_logger, email_check
from lib_functions.user import User, UsersRoles, Role, \
    UserUpdate, UserCreate, UserDelete, UserUpdatePassword, \
    SSOGroupsList, SSOGroupsMemberList,  \
    KubectlConfigStore

##############################################################
## Helpers
##############################################################

accounts = Blueprint("accounts", __name__)
logger = get_logger()

##############################################################
## Users
##############################################################
## Users and Privileges
##############################################################

@accounts.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session['username']
    user = User.query.filter_by(username=username).first()
    user_role = UsersRoles.query.filter_by(user_id=user.id).first()
    role = Role.query.filter_by(id=user_role.role_id).first()

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        if check_password_hash(user.password_hash, old_password):
            updated = UserUpdatePassword(username, new_password)
            if updated:
                flash("User Updated Successfully", "success")
            else:
                flash("Can't update user", "danger")
        else:
            flash("Wrong Current Password", "danger")

    return render_template(
        'user-profile.html.j2',
        user = user,
        user_role = role.name,
    )

@accounts.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        type = request.form['type']
        if type != "Local":
            private_key_base64, user_certificate_base64 = k8sCreateUser(username)
            KubectlConfigStore(username, type, private_key_base64, user_certificate_base64)

        UserUpdate(username, role, type)
        flash("User Updated Successfully", "success")

    users = User.query
    user_role = UsersRoles.query
    roles = Role.query
    k8s_contect_list = k8sServerContextsList()

    return render_template(
        'users.html.j2',
        users = users,
        user_role = user_role,
        roles = roles,
        k8s_contect_list = k8s_contect_list,
    )

@accounts.route('/users/add', methods=['GET', 'POST'])
@login_required
def users_add():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        type = request.form['type']
        password = request.form['password']
        email = request.form['email']

        email_test = bool(email_check(email))
        if not email_test:
            flash("Email is not valid", "danger")
            return redirect(url_for('accounts.users'))
        
        elif not len(password) >= 8:
            flash("Password must be 8 character in length", "danger")
            return redirect(url_for('accounts.users'))
        else:
            if type != "Local":
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, type, private_key_base64, user_certificate_base64)

            UserCreate(username, password, email, type, role, None)
            flash("User Created Successfully", "success")
            return redirect(url_for('accounts.users'))
    else:
        return redirect(url_for('accounts.login'))
    
@accounts.route('/users/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('accounts.users'))
    else:
        return redirect(url_for('accounts.login'))
    
@accounts.route('/users/privileges', methods=['POST'])
@login_required
def users_privilege_list():
    if request.method == 'POST':
        username = request.form['username']
        user_token = get_user_token(session)
        user_cluster_roles, user_roles = k8sUserPriviligeList(session['user_role'], user_token, username)
        return render_template(
            'user-privileges.html.j2',
            username = username,
            user_cluster_roles = user_cluster_roles,
            user_roles = user_roles,
        )
    else:
        return redirect(url_for('accounts.login'))

@accounts.route('/users/privileges/edit', methods=['POST'])
@login_required
def users_privileges_edit():
    if request.method == 'POST':
        username = request.form['username']

        user_cluster_role = request.form.get('user_cluster_role')
        user_namespaced_role_1 = request.form.get('user_namespaced_role_1')
        user_all_namespaces_1 = request.form.get('user_all_namespaces_1')
        user_namespaces_1 = request.form.getlist('user_namespaces_1')
        user_namespaced_role_2 = request.form.get('user_namespaced_role_2')
        user_all_namespaces_2 = request.form.get('user_all_namespaces_2')
        user_namespaces_2 = request.form.getlist('user_namespaces_2')

        if user_cluster_role:
            k8sClusterRoleBindingAdd(user_cluster_role, username, None)

        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, user_namespaces_1, user_all_namespaces_1)

        if user_namespaced_role_2:
            if user_all_namespaces_2:
                k8sRoleBindingAdd(user_namespaced_role_2, username, None, None, user_all_namespaces_2)
            else:
                k8sRoleBindingAdd(user_namespaced_role_2, username, None, user_namespaces_2, user_all_namespaces_2)

        user_token = get_user_token(session)

        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
            user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
        else:
            user_role_template_list = []
            user_clusterRole_template_list = []

        if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
            from lib_functions.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'user-privilege-edit.html.j2',
            username = username,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )
    else:
        return redirect(url_for('accounts.login'))

##############################################################
## Groups
##############################################################

@accounts.route("/groups", methods=['GET', 'POST'])
@login_required
def groups():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    groupe_list = SSOGroupsList()

    return render_template(
        'groups.html.j2',
        selected = selected,
        groupe_list = groupe_list,
    )

@accounts.route("/groups/privilege", methods=['GET', 'POST'])
@login_required
def groups_privilege():
    user_token = get_user_token(session)

    if request.method == 'POST':
        group_name = request.form['group_name']

    groupe_member_list = SSOGroupsMemberList(group_name)
    group_cluster_role_binding = k8sClusterRoleBindingGroupGet(group_name, session['user_role'], user_token)
    group_role_binding = k8sRoleBindingGroupGet(group_name, session['user_role'], user_token)

    return render_template(
        'group-privileges.html.j2',
        group_name = group_name,
        groupe_member_list = groupe_member_list,
        group_role_binding = group_role_binding,
        group_cluster_role_binding = group_cluster_role_binding,
    )

@accounts.route("/groups/privilege/edit", methods=['POST'])
@login_required
def groups_mapping():
    if request.method == 'POST':
        group_name = request.form['group_name']

        user_cluster_role = request.form.get('user_cluster_role')
        user_namespaced_role_1 = request.form.get('user_namespaced_role_1')
        user_all_namespaces_1 = request.form.get('user_all_namespaces_1')
        user_namespaces_1 = request.form.getlist('user_namespaces_1')
        user_namespaced_role_2 = request.form.get('user_namespaced_role_2')
        user_all_namespaces_2 = request.form.get('user_all_namespaces_2')
        user_namespaces_2 = request.form.getlist('user_namespaces_2')

        if user_cluster_role:
            k8sClusterRoleBindingAdd(user_cluster_role, None, group_name)

        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, None, group_name, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, None, group_name, user_namespaces_1, user_all_namespaces_1)

        if user_namespaced_role_2:
            if user_all_namespaces_2:
                k8sRoleBindingAdd(user_namespaced_role_2, None, group_name, None, user_all_namespaces_2)
            else:
                k8sRoleBindingAdd(user_namespaced_role_2, None, group_name, user_namespaces_2, user_all_namespaces_2)

        user_token = get_user_token(session)

        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
            user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
        else:
            user_role_template_list = []
            user_clusterRole_template_list = []

        if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
            from lib_functions.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'group-privilege-edit.html.j2',
            group_name = group_name,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )
    else:
        return redirect(url_for('accounts.login'))

##############################################################
## Service Account
##############################################################

@accounts.route("/service-accounts", methods=['GET', 'POST'])
@login_required
def service_accounts():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        service_accounts = k8sSaListGet(session['user_role'], user_token, session['ns_select'])
    else:
        service_accounts = list()

    return render_template(
        'service-accounts.html.j2',
        selected = selected,
        service_accounts = service_accounts,
        namespaces = namespace_list,
    )

##############################################################
##  Role
##############################################################

@accounts.route("/roles", methods=['GET', 'POST'])
@login_required
def roles():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        roles = k8sRoleListGet(session['user_role'], user_token, session['ns_select'])
    else:
        roles = list()

    return render_template(
        'roles.html.j2',
        selected = selected,
        roles = roles,
        namespaces = namespace_list,
    )

@accounts.route("/roles/data", methods=['GET', 'POST'])
@login_required
def role_data():
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        r_name = request.form.get('r_name')
        
        user_token = get_user_token(session)
        
        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            roles = k8sRoleListGet(session['user_role'], user_token, session['ns_select'])
        else:
            roles = list()

        return render_template(
            'role-data.html.j2',
            namespace_list = namespace_list,
            roles = roles,
            r_name = r_name,
        )
    else:
        return redirect(url_for('accounts.login'))
    
##############################################################
##  Role Binding
##############################################################

@accounts.route("/role-bindings", methods=['GET', 'POST'])
@login_required
def role_bindings():
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        rb_name = request.form.get('rb_name')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        role_bindings, error = k8sRoleBindingListGet(session['user_role'], user_token, session['ns_select'])
    else:
        role_bindings = list()

    return render_template(
        'role-bindings.html.j2',
        role_bindings = role_bindings,
        namespaces = namespace_list,
        rb_name = rb_name,
    )

##############################################################
## Cluster Role
##############################################################

@accounts.route("/cluster-roles", methods=['GET', 'POST'])
@login_required
def cluster_roles():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)

    return render_template(
        'cluster-roles.html.j2',
        cluster_roles = cluster_roles,
        selected = selected,
    )

@accounts.route("/cluster-roles/data", methods=['GET', 'POST'])
@login_required
def cluster_role_data():
    if request.method == 'POST':
        cr_name = request.form.get('cr_name')
        user_token = get_user_token(session)
        cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)


        return render_template(
            'cluster-role-data.html.j2',
            cluster_roles = cluster_roles,
            cr_name = cr_name,
        )
    else:
        return redirect(url_for('accounts.login'))
    
##############################################################
## Cluster Role Bindings
##############################################################

@accounts.route("/cluster-role-bindings", methods=["GET", "POST"])
@login_required
def cluster_role_bindings():
    crb_name = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        crb_name = request.form.get('crb_name')

    cluster_role_bindings, error = k8sClusterRoleBindingListGet(session['user_role'], user_token)
    return render_template(
        'cluster-role-bindings.html.j2',
        cluster_role_bindings = cluster_role_bindings,
        crb_name = crb_name,
    )
