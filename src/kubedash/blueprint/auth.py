import requests
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required, login_user, logout_user
from itsdangerous import base64_decode
from opentelemetry import trace
from werkzeug.security import check_password_hash

from lib.helper_functions import get_logger
from lib.k8s.server import k8sServerConfigGet
from lib.sso import SSOSererGet, get_auth_server_info
from lib.user import KubectlConfig, Role, SSOTokenGet, User, UsersRoles

##############################################################
## Helpers
##############################################################

auth = Blueprint("auth", __name__)
logger = get_logger()

tracer = trace.get_tracer(__name__)

##############################################################
## Login
##############################################################


@auth.route('/')
@tracer.start_as_current_span("/")
def login():
    span = trace.get_current_span()
    is_sso_enabled = False
    is_ldap_enabled = False
    authorization_url = None

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        remote_addr = request.remote_addr
    else:
        remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

    if tracer and span.is_recording():
        span.set_attribute("http.route", "/")
        span.set_attribute("http.method", request.method)
        
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
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "info",
                    "log.message": "SSO is enabled",
                })
                span.set_attribute("sso.state", session['oauth_state'])
                span.set_attribute("sso.auth.url", auth_url)
                span.set_attribute("sso.authorization.url", authorization_url)
        else:
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "error",
                    "log.message": "Cannot connect to identity provider!",
                })
            is_sso_enabled = False
            logger.error("Cannot connect to identity provider!")
            flash('Cannot connect to identity provider!', "error")
    else:
        if tracer and span.is_recording():
            span.add_event("log", {
                "log.severity": "error",
                "log.message": "SSO Integration is not configured.",
            })
        logger.warning("SSO Integration is not configured.")

    if "user_name" in session:
        username = session["user_name"]
        k8sConfig = k8sServerConfigGet()

        if tracer and span.is_recording():
            span.set_attribute("user.name", session['user_name'])
            span.set_attribute("user.type", session['user_type'])
            span.set_attribute("user.role", session['user_role'])

        if k8sConfig is None:
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "error",
                    "log.message": "Kubectl Integration is not configured.",
                })
            logger.error("Kubectl Integration is not configured.")
        else:
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "error",
                    "log.message": "Kubectl Integration is configured.",
                })
            logger.info("Kubectl Integration is configured.")
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            try:
                i = requests.get('http://%s:8080/info' % remote_addr)
                info = i.json()
                if info["message"] == "kdlogin":
                    # start a separate tracer
                    user = User.query.filter_by(username=username, user_type = "OpenID").first()
                    user2 = KubectlConfig.query.filter_by(name=session['user_name']).first()
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
        return redirect(url_for('dashboard.cluster_metrics'))
    else:
        if tracer and span.is_recording():
            span.set_attribute("http.route", "/")
            span.set_attribute("http.method", request.method)
            span.set_attribute("user.name", session['user_name'])
            span.set_attribute("user.type", session['user_type'])
            span.set_attribute("user.role", session['user_role'])
        return render_template(
            'auth/login.html.j2',
            sso_enabled = is_sso_enabled,
            ldap_enabled = is_ldap_enabled,
            auth_url = authorization_url
        )
        
@auth.route('/', methods=['POST'])
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
        return redirect(url_for('.login')) # if user doesn't exist or password is wrong, reload the page
    else:
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()
        login_user(user, remember=remember)
        session['user_name'] = username
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

        return redirect(url_for('dashboard.cluster_metrics'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    if "user_name" in session:
        session.pop('user_name', None)
    if "oauth_token" in session:
        session.pop('oauth_token')
    session.clear()
    return redirect(url_for('.login'))
