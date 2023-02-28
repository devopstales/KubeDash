from flask import Blueprint, jsonify, render_template, session, flash, redirect, url_for, \
    request
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash

from functions.sso import SSOSererGet, get_auth_server_info
from functions.user import User, UsersRoles, Role, email_check, UserUpdate, UserCreate, UserDelete
from functions.k8s import *

main = Blueprint("main", __name__)

##############################################################
## health
##############################################################

@main.route('/ping', methods=['GET'])
def test():
    return 'pong'

@main.route('/health', methods=['GET'])
def health():
    resp = jsonify(health="healthy")
    resp.status_code = 200
    return resp

@main.errorhandler(404)
def page_not_found(e):
    return render_template('404.html.j2'), 404

##############################################################
## Login
##############################################################

@main.route('/')
def login():
        is_sso_enabled = False
        is_ldap_enabled = False
        authorization_url = None

        ssoServer = SSOSererGet()
        if ssoServer is not None:
            auth_server_info, oauth = get_auth_server_info()
            if auth_server_info is not None:
                auth_url = auth_server_info["authorization_endpoint"]
                authorization_url, state = oauth.authorization_url(
                    auth_url,
                    access_type="offline",  # not sure if it is actually always needed,
                                            # may be a cargo-cult from Google-based example
                )       
                session['oauth_state'] = state
                is_sso_enabled = True
            else:
                is_sso_enabled = False
                flash('Cannot connect to identity provider!', "warning")

        if "username" in session:
            return redirect(url_for('main.dashboard'))
        else:
            return render_template(
                'login.html.j2',
                sso_enabled = is_sso_enabled,
                ldap_enabled = is_ldap_enabled,
                auth_url = authorization_url
            )
        
@main.route('/', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username, user_type = "Local").first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password_hash, password):
        flash('Please check your login details and try again.', "warning")
        return redirect(url_for('main.login')) # if user doesn't exist or password is wrong, reload the page
    else:
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()
        login_user(user, remember=remember)
        session['username'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"
        return redirect(url_for('main.dashboard'))


@main.route('/logout')
@login_required
def logout():
    logout_user()
    if "username" in session:
        session.pop('username', None)
    if "oauth_token" in session:
        session.pop('oauth_token')
    session.clear()
    return redirect(url_for('main.login'))

##############################################################
## Dashboard
##############################################################

@main.route('/dashboard')
@login_required
def dashboard():
    cluster_metrics = k8sGetNodeMetric()
    return render_template(
        'dashboard.html.j2',
        cluster_metrics = cluster_metrics
    )

##############################################################
## Users and Privileges
##############################################################

@main.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        UserUpdate(username, role)
        flash("User Updated Successfully", "success")

    users = User.query

    return render_template(
        'users.html.j2',
        users = users,
    )

@main.route('/users/add', methods=['GET', 'POST'])
@login_required
def users_add():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        email = request.form['email']

        email_test = bool(email_check(email))
        if not email_test:
            flash("Email is not valid", "danger")
            return redirect(url_for('main.users'))
        
        elif not len(password) >= 8:
            flash("Password must be 8 character in length", "danger")
            return redirect(url_for('main.users'))
        else:
            UserCreate(username, password, email, "Local", None, role)
            flash("User Created Successfully", "success")
            return redirect(url_for('main.users'))
    else:
        return redirect(url_for('main.login'))
    
@main.route('/users/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('main.users'))
    else:
        return redirect(url_for('main.login'))
    
@main.route('/users/privilege', methods=['POST'])
@login_required
def users_privilege():
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
            k8sClusterRoleBindingAdd(user_cluster_role, username)

        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, username, user_namespaces_1, user_all_namespaces_1)

        if user_namespaced_role_2:
            print("0: %s" % user_namespaces_2) # debug 0
            if user_all_namespaces_2:
                k8sRoleBindingAdd(user_namespaced_role_2, username, None, user_all_namespaces_2)
            else:
                k8sRoleBindingAdd(user_namespaced_role_2, username, user_namespaces_2, user_all_namespaces_2)

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            user_role_template_list = k8sUserRoleTemplateListGet(session['user_role'], user_token)
            user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(session['user_role'], user_token)
        else:
            user_role_template_list = []
            user_clusterRole_template_list = []

        if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
            from functions.k8s import k8sClusterRolesAdd
            k8sClusterRolesAdd()

        return render_template(
            'user-privilege.html.j2',
            username = username,
            user_role_template_list = user_role_template_list,
            namespace_list = namespace_list,
            user_clusterRole_template_list = user_clusterRole_template_list,
        )
    else:
        return redirect(url_for('main.login'))