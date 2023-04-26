import requests, json, yaml, logging, functools
from flask import Blueprint, jsonify, render_template, session, flash, redirect, url_for, request, Response
from flask_login import login_user, login_required, logout_user, current_user
from flask_socketio import disconnect
from werkzeug.security import check_password_hash
from itsdangerous import base64_encode, base64_decode

from functions.helper_functions import get_logger, email_check
from functions.sso import SSOSererGet, get_auth_server_info, SSOServerUpdate, SSOServerCreate
from functions.user import User, UsersRoles, Role, UserUpdate, UserCreate, UserDelete, \
    SSOUserCreate, SSOTokenUpdate, SSOTokenGet, UserUpdatePassword, KubectlConfigStore, KubectlConfig
from functions.k8s import *
from functions.registry import *

from functions.components import tracer, socketio
from threading import Lock
from opentelemetry.trace.status import Status, StatusCode


##############################################################
## Helpers
##############################################################

routes = Blueprint("routes", __name__)
logger = get_logger(__name__)

thread = None
thread_lock = Lock()

def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

##############################################################
## health
##############################################################

@routes.route('/ping', methods=['GET'])
def test():
    with tracer.start_as_current_span("ping-pong", 
                                        attributes={ 
                                            "http.route": "/ping",
                                            "http.method": "GET",
                                        }
                                    ) if tracer else nullcontext() as span:
        return 'pong'

@routes.route('/health', methods=['GET'])
def health():
    resp = jsonify(health="healthy")
    resp.status_code = 200
    return resp

@routes.errorhandler(404)
def page_not_found(e):
    return render_template('404.html.j2'), 404

@routes.errorhandler(400)
def page_not_found(e):
    logger.error(e.description)
    return render_template(
        '400.html.j2',
        description = e.description,
        ), 400

@routes.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = request.root_url.rstrip(request.root_url[-1])
    return response
##############################################################
## Login
##############################################################

@routes.route('/')
def login():
        is_sso_enabled = False
        is_ldap_enabled = False
        authorization_url = None

        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            remote_addr = request.remote_addr
        else:
            remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

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
                logger.error('Cannot connect to identity provider!')

        if "username" in session:
            username = session["username"]
            k8sConfig = k8sServerConfigGet()
            if k8sConfig is None:
                logger.error("Kubectl Integration is not configured.")
            else:
                logger.info("Kubectl Integration is configured.")
                k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
                try:
                    i = requests.get('http://%s:8080/info' % remote_addr)
                    info = i.json()
                    if info["message"] == "kdlogin":
                        user = User.query.filter_by(username=username, user_type = "OpenID").first()
                        user2 = KubectlConfig.query.filter_by(name=session['username']).first()
                        if is_sso_enabled and user:
                            token = eval(SSOTokenGet(username))
                            x = requests.post('http://%s:8080/' % remote_addr, json={
                                    "username": username,
                                    "context": k8sConfig.k8s_context,
                                    "server": k8sConfig.k8s_server_url,
                                    "certificate-authority-data": k8s_server_ca,
                                    "client-id": ssoServer.client_id,
                                    "id-token": token.get("id_token"),
                                    "refresh-token": token.get("refresh_token"),
                                    "idp-issuer-url": ssoServer.oauth_server_uri,
                                    "client_secret": ssoServer.client_secret,
                                }
                            )
                        elif user2:
                            user_private_key = str(base64_decode(user2.private_key), 'UTF-8')
                            user_certificate = str(base64_decode(user2.user_certificate), 'UTF-8')
                            x = requests.post('http://%s:8080/' % remote_addr, json={
                                    "username": username,
                                    "context": k8sConfig.k8s_context,
                                    "server": k8sConfig.k8s_server_url,
                                    "certificate-authority-data": k8s_server_ca,
                                    "user-private-key": user_private_key,
                                    "user-certificate": user_certificate,
                                }
                            )
                        logger.info("Config sent to client")
                        logger.info("Answer from clinet: %s" % x.text)
                except:
                    pass
            return redirect(url_for('routes.cluster_metrics'))
        else:
            return render_template(
                'login.html.j2',
                sso_enabled = is_sso_enabled,
                ldap_enabled = is_ldap_enabled,
                auth_url = authorization_url
            )
        
@routes.route('/', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        remote_addr = request.remote_addr
    else:
        remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

    user = User.query.filter(User.username == username, User.user_type != "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=username).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password_hash, password):
        flash('Please check your login details and try again.', "warning")
        return redirect(url_for('routes.login')) # if user doesn't exist or password is wrong, reload the page
    else:
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()
        login_user(user, remember=remember)
        session['username'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"

        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            logger.error ("Kubectl Integration is not configured.")
        else:
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            try:
                i = requests.get('http://%s:8080/info' % remote_addr)
                info = i.json()
                if info["message"] == "kdlogin" and user2:
                    user_private_key = str(base64_decode(user2.private_key), 'UTF-8')
                    user_certificate = str(base64_decode(user2.user_certificate), 'UTF-8')
                    x = requests.post('http://%s:8080/' % remote_addr, json={
                            "username": username,
                            "context": k8sConfig.k8s_context,
                            "server": k8sConfig.k8s_server_url,
                            "certificate-authority-data": k8s_server_ca,
                            "user-private-key": user_private_key,
                            "user-certificate": user_certificate,
                        }
                    )
                    logger.info("Config sent to client")
                    logger.info("Answer from clinet: %s" % x.text)
            except:
                pass

        return redirect(url_for('routes.cluster_metrics'))


@routes.route('/logout')
@login_required
def logout():
    logout_user()
    if "username" in session:
        session.pop('username', None)
    if "oauth_token" in session:
        session.pop('oauth_token')
    session.clear()
    return redirect(url_for('routes.login'))

##############################################################
## Dashboard
##############################################################
## Cluster Metrics
##############################################################

@routes.route('/cluster-metrics')
@login_required
def cluster_metrics():
    with tracer.start_as_current_span("workload-map", 
                                        attributes={ 
                                            "http.route": "/cluster-metrics",
                                            "http.method": request.method,
                                        }
                                    ) if tracer else nullcontext() as span:
        cluster_metrics = k8sGetClusterMetric()
        username = session['username']
        user = User.query.filter_by(username="admin", user_type = "Local").first()
        if username == "admin" and check_password_hash(user.password_hash, "admin"):
            flash('<a href="/profile">You should change the default password!</a>', "warning")
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "warning",
                    "log.message": "You should change the default password!",
                })
        return render_template(
            'cluster-metrics.html.j2',
            cluster_metrics = cluster_metrics
        )

@routes.route('/workload-map', methods=['GET', 'POST'])
@login_required
def workloads():
    with tracer.start_as_current_span("workload-map", 
                                        attributes={ 
                                            "http.route": "/workload-map",
                                            "http.method": request.method,
                                        }
                                    ) if tracer else nullcontext() as span:
        if request.method == 'POST':
            session['ns_select'] = request.form.get('ns_select')
            if tracer and span.is_recording():
                span.set_attribute("namespace.selected", request.form.get('ns_select'))


        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            nodes, edges = k8sGetPodMap(session['user_role'], user_token, session['ns_select'])
        else:
            nodes = []
            edges = []

        if tracer and span.is_recording():
            span.set_attribute("workloads.nodes", nodes)
            span.set_attribute("workloads.edges", edges)

        return render_template(
            'workloads.html.j2',
            namespaces = namespace_list,
            nodes = nodes,
            edges = edges,
        )

##############################################################
## Users and Privileges
##############################################################

@routes.route('/profile', methods=['GET', 'POST'])
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
        'profile.html.j2',
        user = user,
        user_role = role.name,
    )

@routes.route('/users', methods=['GET', 'POST'])
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

@routes.route('/users/add', methods=['GET', 'POST'])
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
            return redirect(url_for('routes.users'))
        
        elif not len(password) >= 8:
            flash("Password must be 8 character in length", "danger")
            return redirect(url_for('routes.users'))
        else:
            if type != "Local":
                private_key_base64, user_certificate_base64 = k8sCreateUser(username)
                KubectlConfigStore(username, type, private_key_base64, user_certificate_base64)

            UserCreate(username, password, email, type, role, None)
            flash("User Created Successfully", "success")
            return redirect(url_for('routes.users'))
    else:
        return redirect(url_for('routes.login'))
    
@routes.route('/users/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('routes.users'))
    else:
        return redirect(url_for('routes.login'))
    
@routes.route('/users/privileges', methods=['POST'])
@login_required
def users_privilege_list():
    if request.method == 'POST':
        username = request.form['username']
        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None
        user_cluster_roles, user_roles = k8sUserPriviligeList(session['user_role'], user_token, username)
        return render_template(
            'user-privileges.html.j2',
            username = username,
            user_cluster_roles = user_cluster_roles,
            user_roles = user_roles,
        )
    else:
        return redirect(url_for('routes.login'))

@routes.route('/users/privileges/edit', methods=['POST'])
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
            k8sClusterRoleBindingAdd(user_cluster_role, username)

        if user_namespaced_role_1:
            if user_all_namespaces_1:
                k8sRoleBindingAdd(user_namespaced_role_1, username, None, user_all_namespaces_1)
            else:
                k8sRoleBindingAdd(user_namespaced_role_1, username, user_namespaces_1, user_all_namespaces_1)

        if user_namespaced_role_2:
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
        return redirect(url_for('routes.login'))

##############################################################
## SSO Settings
##############################################################

@routes.route('/sso-config', methods=['GET', 'POST'])
@login_required
def sso_config():
    if request.method == 'POST':
        oauth_server_uri = request.form['oauth_server_uri']
        client_id = request.form['client_id']
        client_secret = request.form['client_secret']
        base_uri = request.form['base_uri']
        if not base_uri:
            base_uri = request.root_url.rstrip(request.root_url[-1])
        scope = request.form.getlist('scope')
        while("" in scope):
            scope.remove("")

        request_type = request.form['request_type']
        if request_type == "edit":
            oauth_server_uri_old = request.form['oauth_server_uri_old']
            SSOServerUpdate(oauth_server_uri_old, oauth_server_uri, client_id, client_secret, base_uri, scope)
        elif request_type == "create":
            SSOServerCreate(oauth_server_uri, client_id, client_secret, base_uri, scope)

        flash("SSO Server Updated Successfully", "success")
        return render_template(
            'sso.html.j2',
            oauth_server_uri = oauth_server_uri,
            client_id = client_id,
            client_secret = client_secret,
            base_uri = base_uri,
            scope = scope,
        )
    else:
        ssoServer = SSOSererGet()
        if ssoServer is None:
            return render_template(
                'sso.html.j2',
                base_uri = request.root_url.rstrip(request.root_url[-1]),
                scope = [
                    "openid",          # mandatory for OpenIDConnect auth
                    "email",           # smallest and most consistent scope and claim
                    "offline_access",  # needed to actually ask for refresh_token
                    "good-service",
                    "profile",
                ]
            )
        else:
            return render_template(
                'sso.html.j2',
                oauth_server_uri = ssoServer.oauth_server_uri,
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                base_uri = ssoServer.base_uri,
                scope  = ssoServer.scope,
            )
        
@routes.route("/callback", methods=["GET"])
def callback():
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            flash('Access denied.', "danger")
        else:
            flash('Error encountered.', "danger")
    ssoServer = SSOSererGet()
    if ('code' not in request.args and 'state' not in request.args) or not ssoServer:
        return redirect(url_for('routes.login'))
    else:
        auth_server_info, oauth = get_auth_server_info()
        token_url = auth_server_info["token_endpoint"]
        userinfo_url = auth_server_info["userinfo_endpoint"]

        token = oauth.fetch_token(
            token_url,
            authorization_response = request.url,
            client_secret = ssoServer.client_secret,
            timeout = 60,
            verify = False,
        )
        user_data = oauth.get(
            userinfo_url,
            timeout = 60,
            verify = False,
        ).json()

        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            remote_addr = request.remote_addr
        else:
            remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

## Kubectl config
        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            logger.error ("Kubectl Integration is not configured.")
        else:
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            try:
                i = requests.get('http://%s:8080/info' % remote_addr)
                info = i.json()
                if info["message"] == "kdlogin":
                    x = requests.post('http://%s:8080/' % remote_addr, json={
                            "username": user_data["preferred_username"],
                            "context": k8sConfig.k8s_context,
                            "server": k8sConfig.k8s_server_url,
                            "certificate-authority-data": k8s_server_ca,
                            "client-id": ssoServer.client_id,
                            "id-token": token.get("id_token"),
                            "refresh-token": token.get("refresh_token"),
                            "idp-issuer-url": ssoServer.oauth_server_uri,
                            "client_secret": ssoServer.client_secret,
                        }
                    )
                    logger.info("Config sent to client")
                    logger.info("Answer from clinet: %s" % x.text)
            except:
                pass

        email = user_data['email']
        username = user_data["preferred_username"]
        user_token = json.dumps(token)
        user = User.query.filter_by(username=username).first()

        if user is None:
            SSOUserCreate(username, email, user_token, "OpenID")
            user = User.query.filter_by(username=username, user_type = "OpenID").first()
        else:
            SSOTokenUpdate(username, user_token)

        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()

        session['oauth_token'] = token
        session['refresh_token'] = token.get("refresh_token")
        session['username'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"

        login_user(user)
        return redirect(url_for('routes.cluster_metrics'))
    
##############################################################
## Kubectl config
##############################################################

@routes.route('/kdlogin')
def index():
    auth_server_info, oauth = get_auth_server_info()
    auth_url = auth_server_info["authorization_endpoint"]

    authorization_url, state = oauth.authorization_url(
        auth_url,
        access_type="offline",  # not sure if it is actually always needed,
                                # may be a cargo-cult from Google-based example
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@routes.route('/cluster-config', methods=['GET', 'POST'])
@login_required
def k8s_config():
    if request.method == 'POST':
        request_type = request.form['request_type']
        if request_type == "create":
            k8s_server_url = request.form['k8s_server_url']
            k8s_context = request.form['k8s_context']
            k8s_server_ca = str(base64_encode(request.form['k8s_server_ca'].strip()), 'UTF-8')

            k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca)
            flash("Kubernetes Config Updated Successfully", "success")
        elif request_type == "edit":
            k8s_server_url = request.form['k8s_server_url']
            k8s_context = request.form['k8s_context']
            k8s_context_old = request.form['k8s_context_old']
            k8s_server_ca = base64_encode(request.form['k8s_server_ca'].strip())

            k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca)
            flash("Kubernetes Config Updated Successfully", "success")
        elif request_type == "delete":
            k8s_context = request.form['k8s_context']
            k8sServerDelete(k8s_context)

    k8s_servers, k8s_config_list_length = k8sServerConfigList()

    return render_template(
        'clusters.html.j2',
        k8s_servers = k8s_servers,
        k8s_config_list_length = k8s_config_list_length,
    )

@routes.route('/export')
@login_required
def export():
    user = User.query.filter_by(username=session['username'], user_type = "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=session['username']).first()
    k8sConfig = k8sServerConfigGet()
    if k8sConfig:
        k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
        if user:
            ssoServer = SSOSererGet()
            redirect_uri = ssoServer.base_uri+"/callback"
            auth_server_info, oauth = get_auth_server_info()

            token_url = auth_server_info["token_endpoint"]
            token = oauth.refresh_token(
                token_url = token_url,
                refresh_token = session['refresh_token'],
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                verify=False,
                timeout=60,
            )

            userinfo_url = auth_server_info["userinfo_endpoint"]
            user_data = oauth.get(
                userinfo_url,
                timeout=60,
                verify=False,
            ).json()

            return render_template(
                'export.html.j2',
                base_uri = ssoServer.base_uri,
                preferred_username = user_data["preferred_username"],
                redirect_uri = redirect_uri,
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                id_token = token["id_token"],
                refresh_token = token.get("refresh_token"),
                oauth_server_uri = ssoServer.oauth_server_uri,
                context = k8sConfig.k8s_context,
                k8s_server_url = k8sConfig.k8s_server_url,
                k8s_server_ca = k8s_server_ca
            )
        elif user2:
            return render_template(
                'export.html.j2',
                preferred_username = user2.name,
                context = k8sConfig.k8s_context,
                k8s_server_url = k8sConfig.k8s_server_url,
                k8s_server_ca = k8s_server_ca,
                k8s_user_private_key = user2.private_key,
                k8s_user_certificate = user2.user_certificate,
            )
        else:
            return render_template(
                'export.html.j2',
                preferred_username = session['username'],
                username_role = session['user_role']
            )
    else:
        flash("Kubernetes Cluster is not Configured.", "danger")
        return render_template(
            'export.html.j2',
            preferred_username = session['username'],
            username_role = session['user_role']
        )



@routes.route("/get-file")
@login_required
def get_file():
    user = User.query.filter_by(username=session['username'], user_type = "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=session['username']).first()
    k8sConfig = k8sServerConfigGet()
    kube_cluster = {
        "certificate-authority-data": k8sConfig.k8s_server_ca,
        "server": k8sConfig.k8s_server_url
    }
    kube_context = {
        "cluster": k8sConfig.k8s_context,
        "user": k8sConfig.k8s_context,
    }
    
    if user:
        ssoServer = SSOSererGet()
        auth_server_info, oauth = get_auth_server_info()
        token_url = auth_server_info["token_endpoint"]
        verify = False

        token = oauth.refresh_token(
            token_url = token_url,
            refresh_token = session['refresh_token'],
            client_id = ssoServer.client_id,
            client_secret = ssoServer.client_secret,
            verify = verify,
            timeout = 60,
        )

        kube_user = {
                "auth-provider": {
                    "name": "oidc",
                    "config": {
                        "client-id": ssoServer.client_id,
                        "idp-issuer-url": ssoServer.oauth_server_uri,
                        "id-token": token["id_token"],
                        "refresh-token": token.get("refresh_token"),
                    }
                }
            }
        if ssoServer.client_secret:
            kube_user["auth-provider"]["config"]["client-secret"] = ssoServer.client_secret
        if verify:
            kube_user["auth-provider"]["config"]["idp-certificate-authority"] = verify

        config_snippet = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "name": k8sConfig.k8s_context,
                "cluster": kube_cluster
            }],
            "contexts": [{
                "name": k8sConfig.k8s_context,
                "context": kube_context
            }],
            "current-context": k8sConfig.k8s_context,
            "preferences": {},
            "users": [{
                "name": k8sConfig.k8s_context,
                "user": kube_user
            }]
        }
    elif user2:
        kube_user = {
            "client-certificate-data": user2.user_certificate,
            "client-key-data": user2.private_key,
        }
        config_snippet = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "name": k8sConfig.k8s_context,
                "cluster": kube_cluster
            }],
            "contexts": [{
                "name": k8sConfig.k8s_context,
                "context": kube_context
            }],
            "current-context": k8sConfig.k8s_context,
            "preferences": {},
            "users": [{
                "name": k8sConfig.k8s_context,
                "user": kube_user
            }]
        }

    return Response(
            yaml.safe_dump(config_snippet),
            mimetype="text/yaml",
            headers={
                "Content-Disposition":
                "attachment;filename=kubecfg.yaml"
            }
    )

##############################################################
## Cluster
##############################################################
## Nodes
##############################################################

@routes.route("/nodes", methods=['GET', 'POST'])
@login_required
def nodes():
    selected = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    node_data = k8sNodesListGet(session['user_role'], user_token)
    cluster_metrics = k8sGetClusterMetric()

    return render_template(
        'nodes.html.j2',
        nodes = node_data,
        selected = selected,
        cluster_metrics = cluster_metrics,
    )

@routes.route('/nodes/data', methods=['GET', 'POST'])
@login_required
def nodes_data():
    if request.method == 'POST':
        no_name = request.form.get('no_name')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        node_data = k8sNodeGet(session['user_role'], user_token, no_name)
        node_metrics = k8sGetNodeMetric(no_name)

        return render_template(
            'node-data.html.j2',
            no_name = no_name,
            node_data = node_data,
            node_metrics = node_metrics,
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Namespaces
##############################################################

@routes.route("/namespaces")
@login_required
def namespaces():
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list = k8sNamespacesGet(session['user_role'], user_token)

    return render_template(
        'namespaces.html.j2',
        namespace_list = namespace_list,
    )

@routes.route("/namespaces/create", methods=['GET', 'POST'])
@login_required
def namespaces_create():
    if request.method == 'POST':
        namespace = request.form['namespace']

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        k8sNamespaceCreate(session['user_role'], user_token, namespace)
        return redirect(url_for('routes.namespaces'))
    else:
        return redirect(url_for('routes.namespaces'))
    
@routes.route("/namespaces/delete", methods=['GET', 'POST'])
@login_required
def namespaces_delete():
    if request.method == 'POST':
        namespace = request.form['namespace']

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        k8sNamespaceDelete(session['user_role'], user_token, namespace)
        return redirect(url_for('routes.namespaces'))
    else:
        return redirect(url_for('routes.namespaces'))

##############################################################
## Workloads
##############################################################
## Statefullsets
##############################################################

@routes.route("/statefulsets", methods=['GET', 'POST'])
@login_required
def statefulsets():
    selected = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        statefulset_list = k8sStatefulSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        statefulset_list = []

    return render_template(
        'statefulsets.html.j2',
        selected = selected,
        statefulsets = statefulset_list,
        namespaces = namespace_list,
    )

##############################################################
## Daemonsets
##############################################################

@routes.route("/daemonsets", methods=['GET', 'POST'])
@login_required
def daemonsets():
    selected = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        daemonset_list = k8sDaemonSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        daemonset_list = []

    return render_template(
        'daemonsets.html.j2',
        daemonsets = daemonset_list,
        namespaces = namespace_list,
        selected = selected,
    )

##############################################################
## Deployments
##############################################################

@routes.route("/deployments", methods=['GET', 'POST'])
@login_required
def deployments():
    selected = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        deployments_list = k8sDeploymentsGet(session['user_role'], user_token, session['ns_select'])
    else:
        deployments_list = []

    return render_template(
        'deployments.html.j2',
        selected = selected,
        deployments = deployments_list,
        namespaces = namespace_list,
    )

##############################################################
## ReplicaSets
##############################################################

@routes.route("/replicasets", methods=['GET', 'POST'])
@login_required
def replicasets():
    selected = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        replicaset_list = k8sReplicaSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        replicaset_list = []

    return render_template(
        'replicasets.html.j2',
        replicasets = replicaset_list,
        namespaces = namespace_list,
        selected = selected,
    )

##############################################################
## Pods
##############################################################

@routes.route("/pods", methods=['GET', 'POST'])
@login_required
def pods():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')

    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_report, pod_list = k8sPodListVulnsGet(session['user_role'], user_token, session['ns_select'])
    else:
        pod_list = []
        has_report = None

    return render_template(
        'pods.html.j2',
        pods = pod_list,
        has_report = has_report,
        namespaces = namespace_list,
    )

@routes.route('/pods/data', methods=['GET', 'POST'])
@login_required
def pods_data():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        session['ns_select'] = request.form.get('ns_select')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        pod_data = k8sPodGet(session['user_role'], user_token, session['ns_select'], po_name)
        has_report, pod_vulns = k8sPodVulnsGet(session['user_role'], user_token, session['ns_select'], po_name)

        return render_template(
            'pod-data.html.j2',
            po_name = po_name,
            pod_data = pod_data,
            has_report = has_report,
            pod_vulns = pod_vulns,
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Pod Logs
##############################################################

logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

@routes.route('/pods/logs', methods=['POST'])
@login_required
def pods_logs():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        return render_template(
            'pod-logs.html.j2', 
            po_name=session['po_name'], 
            async_mode=socketio.async_mode
        )
    else:
        return redirect(url_for('routes.login'))

@socketio.on("connect", namespace="/log")
@authenticated_only
def connect():
    socketio.emit('response', {'data': 'Connected'}, namespace="/log")

@socketio.on("message", namespace="/log")
@authenticated_only
def message(data):
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(k8sPodLogsStream, session['user_role'], user_token, session['ns_select'], data)

##############################################################
## Pod Exec
##############################################################

@routes.route('/pods/exec', methods=['POST'])
@login_required
def pods_exec():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        return render_template(
            'pod-exec.html.j2', 
            po_name = request.form.get('po_name'),
            async_mode = socketio.async_mode
        )
    else:
        return redirect(url_for('routes.login'))

@socketio.on("connect", namespace="/exec")
@authenticated_only
def connect():
    socketio.emit("response", {"output":  'Connected' + "\r\n"}, namespace="/exec")

@socketio.on("message", namespace="/exec")
@authenticated_only
def message(data):
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    global wsclient
    wsclient = k8sPodExecSocket(session['user_role'], user_token, session['ns_select'], data)

    global thread
    with thread_lock:
        if thread is None:
            socketio.start_background_task(k8sPodExecStream, wsclient)

@socketio.on("exec-input", namespace="/exec")
@authenticated_only
def exec_input(data):
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    wsclient.write_stdin(data["input"].encode())

##############################################################
## Security
##############################################################
## Service Account
##############################################################

@routes.route("/service-accounts", methods=['GET', 'POST'])
@login_required
def service_accounts():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
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

@routes.route("/roles", methods=['GET', 'POST'])
@login_required
def roles():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
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

@routes.route("/roles/data", methods=['GET', 'POST'])
@login_required
def role_data():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        r_name = request.form.get('r_name')
        
        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None
        
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
        return redirect(url_for('routes.login'))
    
##############################################################
##  Role Binding
##############################################################

@routes.route("/role-bindings", methods=['GET', 'POST'])
@login_required
def role_bindings():
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        role_bindings = k8sRoleBindingListGet(session['user_role'], user_token, session['ns_select'])
    else:
        role_bindings = list()

    return render_template(
        'role-bindings.html.j2',
        role_bindings = role_bindings,
        namespaces = namespace_list,
    )

##############################################################
## Cluster Role
##############################################################

@routes.route("/cluster-roles", methods=['GET', 'POST'])
@login_required
def cluster_roles():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)

    return render_template(
        'cluster-roles.html.j2',
        cluster_roles = cluster_roles,
        selected = selected,
    )

@routes.route("/cluster-roles/data", methods=['GET', 'POST'])
@login_required
def cluster_role_data():
    if request.method == 'POST':
        cr_name = request.form.get('cr_name')
        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None
        cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)


        return render_template(
            'cluster-role-data.html.j2',
            cluster_roles = cluster_roles,
            cr_name = cr_name,
        )
    else:
        return redirect(url_for('routes.login'))
    
##############################################################
## Cluster Role Bindings
##############################################################

@routes.route("/cluster-role-bindings")
@login_required
def cluster_role_bindings():
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    cluster_role_bindings = k8sClusterRoleBindingListGet(session['user_role'], user_token)
    return render_template(
        'cluster-role-bindings.html.j2',
        cluster_role_bindings = cluster_role_bindings,
    )

##############################################################
## Cluster Role Bindings
##############################################################

@routes.route("/secrets", methods=['GET', 'POST'])
@login_required
def secrets():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
    else:
        secrets = list()

    return render_template(
        'secrets.html.j2',
        secrets = secrets,
        namespaces = namespace_list,
        selected = selected,
    )

@routes.route('/secrets/data', methods=['GET', 'POST'])
@login_required
def secrets_data():
    if request.method == 'POST':
        secret_name = request.form.get('secret_name')
        session['ns_select'] = request.form.get('ns_select')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
        for secret in secrets:
            if secret["name"] == secret_name:
                secret_data = secret

        return render_template(
            'secret-data.html.j2',
            secret_data = secret_data,
            namespace = session['ns_select'],
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
# Network
##############################################################
## Ingress Class
##############################################################

@routes.route("/ingress-class", methods=['GET', 'POST'])
@login_required
def ingresses_class():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    ingresses_classes = k8sIngressClassListGet(session['user_role'], user_token)

    return render_template(
        'ingress-classes.html.j2',
        ingresses_classes = ingresses_classes,
        selected = selected,
    )

@routes.route('/ingress-class/data', methods=['GET', 'POST'])
@login_required
def ingresses_class_data():
    if request.method == 'POST':
        ic_name = request.form.get('ic_name')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        ingresses_classes = k8sIngressClassListGet(session['user_role'], user_token)
        for ic in ingresses_classes:
            if ic["name"] == ic_name:
                ic_data = ic

        return render_template(
            'ingress-class-data.html.j2',
            ic_data = ic_data
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Ingresses
##############################################################

@routes.route("/ingress", methods=['GET', 'POST'])
@login_required
def ingresses():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    ingresses = k8sIngressListGet(session['user_role'], user_token, session['ns_select'])

    return render_template(
        'ingress.html.j2',
        namespaces = namespace_list,
        ingresses = ingresses,
        selected = selected,
    )

@routes.route('/ingress/data', methods=['GET', 'POST'])
@login_required
def ingresses_data():
    if request.method == 'POST':

        i_name = request.form.get('i_name')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        ingresses = k8sIngressListGet(session['user_role'], user_token, session['ns_select'])
        for i in ingresses:
            if i["name"] == i_name:
                i_data = i

        return render_template(
            'ingress-data.html.j2',
            i_data = i_data
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
# Service
##############################################################

@routes.route("/services", methods=['GET', 'POST'])
@login_required
def services():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    services = k8sServiceListGet(session['user_role'], user_token, session['ns_select'])

    return render_template(
      'services.html.j2',
        services = services,
        namespaces = namespace_list,
        selected = selected,
    )

@routes.route('/services/data', methods=['GET', 'POST'])
@login_required
def services_data():
    pod_list = None
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        session['ns_select'] = request.form.get('ns_select')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        services = k8sServiceListGet(session['user_role'], user_token, session['ns_select'])
        for service in services:
            if service["name"] == service_name:
                service_data = service
        if service_data["selector"]:
            pod_list = k8sPodSelectorListGet(session['user_role'], user_token, session['ns_select'], service_data["selector"])

        return render_template(
          'service-data.html.j2',
            service_data = service_data,
            namespace = session['ns_select'],
            pod_list = pod_list,
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Storage
##############################################################
## Stotage Class
##############################################################

@routes.route("/storage-class", methods=['GET', 'POST'])
@login_required
def storage_class():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    storage_classes = k8sStorageClassListGet(session['user_role'], user_token)

    return render_template(
        'storage-classes.html.j2',
        storage_classes = storage_classes,
        selected = selected,
    )

@routes.route('/storage-class/data', methods=['GET', 'POST'])
@login_required
def storage_class_data():
    if request.method == 'POST':
        sc_name = request.form.get('sc_name')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        storage_classes = k8sStorageClassListGet(session['user_role'], user_token)
        for sc in storage_classes:
            if sc["name"] == sc_name:
                sc_data = sc

        return render_template(
            'storage-class-data.html.j2',
            sc_data = sc_data
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Persistent Volume Claim
##############################################################

@routes.route("/pvc", methods=['GET', 'POST'])
@login_required
def pvc():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        pvc_list = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, session['ns_select'])
        pvc_metrics = k8sPVCMetric(session['ns_select'])
    else:
        pvc_list = list()
        pvc_metrics = list()

    return render_template(
        'pvc.html.j2',
        pvc_list = pvc_list,
        pvc_metrics = pvc_metrics,
        namespaces = namespace_list,
        selected = selected,
    )

@routes.route('/pvc/data', methods=['GET', 'POST'])
@login_required
def pvc_data():
    if request.method == 'POST':
        selected = request.form.get('selected')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        if not error:
            pvc_list = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, session['ns_select'])
            for pvc in pvc_list:
                if pvc["name"] == selected:
                    pvc_data = pvc
        else:
            pvc_data = list()

        return render_template(
            'pvc-data.html.j2',
            pvc_data = pvc_data,
            namespace = session['ns_select'],
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## Persistent Volume
##############################################################

@routes.route("/pv", methods=['GET', 'POST'])
@login_required
def pv():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    pv_list = k8sPersistentVolumeListGet(session['user_role'], user_token, session['ns_select'])
      
    return render_template(
        'pv.html.j2',
        pv_list = pv_list,
        selected = selected,
        namespaces = namespace_list,
    )

@routes.route('/pv/data', methods=['GET', 'POST'])
@login_required
def pv_data():
    pv_data = None
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        pv_list = k8sPersistentVolumeListGet(session['user_role'], user_token, session['ns_select'])
        for pv in pv_list:
            if pv["name"] == selected:
                pv_data = pv

        return render_template(
            'pv-data.html.j2',
            pv_data = pv_data,
            namespace = session['ns_select'],
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## ConfigMap
##############################################################

@routes.route("/configmaps", methods=['GET', 'POST'])
@login_required
def configmap():
    selected = None
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        configmaps = k8sConfigmapListGet(session['user_role'], user_token, session['ns_select'])
    else:
        configmaps = list()

    return render_template(
        'configmaps.html.j2',
        configmaps = configmaps,
        namespaces = namespace_list,
        selected = selected,
    )

@routes.route('/configmaps/data', methods=['GET', 'POST'])
@login_required
def configmap_data():
    if request.method == 'POST':
        configmap_name = request.form.get('configmap_name')
        session['ns_select'] = request.form.get('ns_select')

        if session['user_type'] == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        configmaps = k8sConfigmapListGet(session['user_role'], user_token, session['ns_select'])
        for configmap in configmaps:
            if configmap["name"] == configmap_name:
                configmap_data = configmap

        return render_template(
            'configmap-data.html.j2',
            configmap_data = configmap_data,
            namespace = session['ns_select'],
        )
    else:
        return redirect(url_for('routes.login'))

##############################################################
## OCI Registry
##############################################################

@routes.route("/registry", methods=['GET', 'POST'])
@login_required
def registry():
    selected = None
    registry_server_auth_user = None
    registry_server_auth_pass = None
    registry_server_auth = False
    if request.method == 'POST':
        selected = request.form.get('selected')
        request_type = request.form['request_type']
        if request_type == "create":
            registry_server_tls = request.form.get('registry_server_tls_register_value') in ['True']
            insecure_tls = request.form.get('insecure_tls_register_value') in ['True']
            registry_server_url = request.form.get('registry_server_url')
            registry_server_port = request.form.get('registry_server_port')
            if request.form.get('registry_server_auth_user') and request.form.get('registry_server_auth_pass'):
                registry_server_auth_user = request.form.get('registry_server_auth_user')
                registry_server_auth_pass = request.form.get('registry_server_auth_pass') # bas64 encoded
                registry_server_auth = True

            RegistryServerCreate(registry_server_url, registry_server_port, registry_server_auth, 
                        registry_server_tls, insecure_tls, registry_server_auth_user, 
                        registry_server_auth_pass)
            flash("Registry Created Successfully", "success")
        elif request_type == "edit":
            registry_server_tls = request.form.get('registry_server_tls_edit_value') in ['True']
            insecure_tls = request.form.get('insecure_tls_edit_value') in ['True']
            registry_server_url = request.form.get('registry_server_url')
            registry_server_url_old = request.form.get('registry_server_url_old')
            registry_server_port = request.form.get('registry_server_port')
            registry_server_auth = request.form.get('registry_server_auth')
            if request.form.get('registry_server_auth_user') and request.form.get('registry_server_auth_pass'):
                registry_server_auth_user = request.form.get('registry_server_auth_user')
                registry_server_auth_pass = request.form.get('registry_server_auth_pass')
                registry_server_auth = True

            RegistryServerUpdate(registry_server_url, registry_server_url_old, registry_server_port, 
                        registry_server_auth, registry_server_tls, insecure_tls, registry_server_auth_user, 
                        registry_server_auth_pass)
            flash("Registry Updated Successfully", "success")
        elif request_type == "delete":
            registry_server_url = request.form.get('registry_server_url')

            RegistryServerDelete(registry_server_url)
            flash("Registry Deleted Successfully", "success")

    registries = RegistryServerListGet()

    return render_template(
      'registry.html.j2',
        registries = registries,
        selected = selected,
    )

@routes.route("/image/list", methods=['GET', 'POST'])
@login_required
def image_list():
    selected = None
    if request.method == 'POST':
        selected = request.form.get('selected')
        session['registry_server_url'] = request.form.get('registry_server_url')

    image_list = RegistryGetRepositories(session['registry_server_url'])

    return render_template(
        'registry-image-list.html.j2',
        image_list = image_list,
        selected = selected,
    )
    
@routes.route("/image/tags", methods=['GET', 'POST'])
@login_required
def image_tags():
    selected = None
    if request.method == 'POST':
        selected = request.form.get('selected')
        if 'image_name' in request.form:
            session['image_name'] = request.form.get('image_name')

    tag_list = RegistryGetTags(session['registry_server_url'], session['image_name'])

    return render_template(
        'registry-image-tag-list.html.j2',
        tag_list = tag_list,
        selected = selected,
        image_name = session['image_name'],
    )

@routes.route("/image/tag/delete", methods=['GET', 'POST'])
@login_required
def image_tag_delete():
    if request.method == 'POST':
        tag_name = request.form.get('tag_name')
        image_name = request.form.get('image_name')
        RegistryDeleteTag(session['registry_server_url'], image_name, tag_name)
        return redirect(url_for('routes.image_tags'), code=307)
    else:
        return redirect(url_for('routes.login'))

@routes.route("/image/data", methods=['GET', 'POST'])
@login_required
def image_data():
    if request.method == 'POST':
        if 'tag_name' in request.form:
            session['tag_name'] = request.form.get('tag_name')

    tag_data = RegistryGetManifest(session['registry_server_url'], session['image_name'], session['tag_name'])

    return render_template(
        'registry-image-tag-data.html.j2',
        tag_data = tag_data,
        image_name = session['image_name'],
        tag_name = session['tag_name'],
    )



"""
image: Image name, Format, Tags, Architecture
tags:  Tag name, Size, LAyers, Created
tag data: Entrypoint, Labels, ExposedPorts,
---
image: Image name, Format, Tags, Architecture
tags:  Tag name, Size, pull command, Vulnability, Signed, Author, Created

"""

##############################################################
## Helm Charts
##############################################################

@routes.route('/charts', methods=['GET', 'POST'])
@login_required
def charts():
    if session['user_type'] == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')


    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_chart, chart_list = k8sHelmChartListGet(session['ns_select'], user_token, session['ns_select'])
    else:
        chart_list = []
        has_chart = None

    return render_template(
        'charts.html.j2',
        namespaces = namespace_list,
        has_chart = has_chart,
        chart_list = chart_list,
    )
