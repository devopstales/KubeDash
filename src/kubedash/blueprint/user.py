from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required
from werkzeug.security import check_password_hash

from lib.helper_functions import email_check, get_logger
from lib.k8s.certificate import k8sCreateUser
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import (k8sClusterRoleBindingAdd,
                              k8sClusterRoleBindingGroupGet, k8sRoleBindingAdd,
                              k8sRoleBindingGroupGet,
                              k8sUserClusterRoleTemplateListGet,
                              k8sUserPriviligeList, k8sUserRoleTemplateListGet)
from lib.k8s.server import k8sServerContextsList
from lib.sso import get_user_token
from lib.user import (KubectlConfigStore, Role, SSOGroupsList,
                      SSOGroupsMemberList, User, UserCreate, UserDelete,
                      UsersRoles, UserUpdate, UserUpdatePassword)

##############################################################
## Helpers
##############################################################

users = Blueprint("users", __name__, url_prefix="/user")
logger = get_logger()

##############################################################
## Users
##############################################################
## Users and Privileges
##############################################################

@users.route('/info', methods=['GET', 'POST'])
@login_required
def userinfo():
    username = session['user_name']
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
        'users/userinfo.html.j2',
        user = user,
        user_role = role.name,
    )

@users.route('/list', methods=['GET', 'POST'])
@login_required
def users_list():
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
        'users/user.html.j2',
        users = users,
        user_role = user_role,
        roles = roles,
        k8s_contect_list = k8s_contect_list,
    )

@users.route('/add', methods=['GET', 'POST'])
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
            return redirect(url_for('users.users_list'))
        
        elif not len(password) >= 8:
            flash("Password must be 8 character in length", "danger")
            return redirect(url_for('users.users_list'))
        else:
            if type != "Local":
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, type, private_key_base64, user_certificate_base64)

            UserCreate(username, password, email, type, role, None)
            flash("User Created Successfully", "success")
            return redirect(url_for('users.users_list'))
    else:
        return redirect(url_for('auth.login'))
    
@users.route('/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('users.users_list'))
    else:
        return redirect(url_for('auth.login'))
    
@users.route('/privilege', methods=['POST'])
@login_required
def users_privilege_list():
    if request.method == 'POST':
        username = request.form['username']
        user_token = get_user_token(session)
        user_cluster_roles, user_roles = k8sUserPriviligeList(session['user_role'], user_token, username)
        return render_template(
            'users/privilege.html.j2',
            username = username,
            user_cluster_roles = user_cluster_roles,
            user_roles = user_roles,
        )
    else:
        return redirect(url_for('auth.login'))

@users.route('/privilege/edit', methods=['GET', 'POST'])
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
            from lib.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'users/privilege-edit.html.j2',
            username = username,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )
    else:
        print(session)
        username = session['user_name']
        user_token = get_user_token(session)
        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        
        if not error:
            user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
            user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
        else:
            user_role_template_list = []
            user_clusterRole_template_list = []

        if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
            from lib.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'users/privilege-edit.html.j2',
            username = username,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )

##############################################################
## Groups
##############################################################

@users.route("/group", methods=['GET', 'POST'])
@login_required
def groups():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    groupe_list = SSOGroupsList()

    return render_template(
        'users/group.html.j2',
        selected = selected,
        groupe_list = groupe_list,
    )

@users.route("/group/privilege", methods=['GET', 'POST'])
@login_required
def groups_privilege():
    user_token = get_user_token(session)

    if request.method == 'POST':
        group_name = request.form['group_name']

    groupe_member_list = SSOGroupsMemberList(group_name)
    group_cluster_role_binding = k8sClusterRoleBindingGroupGet(group_name, session['user_role'], user_token)
    group_role_binding = k8sRoleBindingGroupGet(group_name, session['user_role'], user_token)

    return render_template(
        'users/group-privileges.html.j2',
        group_name = group_name,
        groupe_member_list = groupe_member_list,
        group_role_binding = group_role_binding,
        group_cluster_role_binding = group_cluster_role_binding,
    )

@users.route("/group/privilege/edit", methods=['POST'])
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
            from lib.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'users/group-privilege-edit.html.j2',
            group_name = group_name,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )
    else:
        return redirect(url_for('auth.login'))
