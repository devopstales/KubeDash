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

users_bp = Blueprint("users", __name__, url_prefix="/user")
logger = get_logger()

##############################################################
## Users
##############################################################
## Users and Privileges
##############################################################

@users_bp.route('/info', methods=['GET', 'POST'])
@login_required
def userinfo():
    """
    User info page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/users/info
    # Password updates are handled via /api/v1/users/<username>/password
    return render_template('users/userinfo.html.j2')

@users_bp.route('/list', methods=['GET', 'POST'])
@login_required
def users_list():
    """
    User list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility (form submissions)
    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        user_type = request.form.get('type')
               
        if username and role and user_type:
            if user_type != "Local":
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, user_type, private_key_base64, user_certificate_base64)

            UserUpdate(username, role, user_type)
            flash("User Updated Successfully", "success")

    # Template now loads data via JavaScript from /api/v1/users
    return render_template('users/user.html.j2')

@users_bp.route('/add', methods=['GET', 'POST'])
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
    
@users_bp.route('/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('users.users_list'))
    else:
        return redirect(url_for('auth.login'))
    
@users_bp.route('/privilege', methods=['GET', 'POST'])
@login_required
def users_privilege_list():
    """
    User privileges list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/users/<username>/privileges
    return render_template('users/privilege.html.j2')

@users_bp.route('/privilege/edit', methods=['GET', 'POST'])
@login_required
def users_privileges_edit():
    """
    User privileges edit page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # If POST request, extract username and redirect with it as query parameter
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            return redirect(url_for('users.users_privileges_edit', username=username))
    
    # Template now loads data via JavaScript from /api/v1/users/privileges/templates
    # Form submissions are handled via /api/v1/users/<username>/privileges
    return render_template('users/privilege-edit.html.j2')

##############################################################
## Groups
##############################################################

@users_bp.route("/group", methods=['GET', 'POST'])
@login_required
def groups():
    """
    SSO Groups list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/users/sso/groups
    return render_template('users/group.html.j2')

@users_bp.route("/group/privilege", methods=['GET', 'POST'])
@login_required
def groups_privilege():
    """
    Group privileges page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/users/groups/<group_name>/privileges
    return render_template('users/group-privilege.html.j2')

@users_bp.route("/group/privilege/edit", methods=['GET', 'POST'])
@login_required
def groups_mapping():
    """
    Group privileges edit page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # If POST request, extract group_name and redirect with it as query parameter
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if group_name:
            return redirect(url_for('users.groups_mapping', group_name=group_name))
    
    # Template now loads data via JavaScript from /api/v1/users/privileges/templates
    # Form submissions are handled via /api/v1/users/groups/<group_name>/privileges
    return render_template('users/group-privilege-edit.html.j2')
