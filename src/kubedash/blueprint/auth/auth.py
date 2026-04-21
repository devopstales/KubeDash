import requests
from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_login import login_required, login_user, logout_user
from itsdangerous import base64_decode
from werkzeug.security import check_password_hash

from lib.audit import log_audit_event
from lib.helper_functions import get_logger, is_safe_url
from lib.k8s.server import k8sServerConfigGet
from lib.kdlogin_push import (client_ip_for_kdlogin_push,
                              try_push_cert_kubeconfig_to_kdlogin)
from lib.oauth_pkce import generate_pkce_pair
from lib.sso import SSOSererGet, get_auth_server_info
from lib.user import KubectlConfig, Role, User, UsersRoles

##############################################################
## Helpers
##############################################################

auth_bp = Blueprint("auth", __name__)
logger = get_logger()

from lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()

##############################################################
## Login
##############################################################


@auth_bp.route('/')
@tracer.start_as_current_span("/")
def login():
    span = trace.get_current_span()
    is_sso_enabled = False
    is_ldap_enabled = False
    authorization_url = None

    remote_addr = client_ip_for_kdlogin_push(request)

    if tracer and span.is_recording():
        span.set_attribute("http.route", "/")
        span.set_attribute("http.method", request.method)
        
    ssoServer = SSOSererGet()
    if ssoServer is not None:
        auth_server_info, oauth = get_auth_server_info()
        if auth_server_info is not None:
            auth_url = auth_server_info["authorization_endpoint"]
            code_verifier, code_challenge = generate_pkce_pair()
            session["oauth_code_verifier"] = code_verifier
            authorization_url, state = oauth.authorization_url(
                auth_url,
                access_type="offline",
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )
            session['oauth_state'] = state
            is_sso_enabled = True
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "info",
                    "log.message": "SSO is enabled",
                })
                span.set_attribute("sso.state", session['oauth_state'])
                span.set_attribute("sso.auth_bp.url", auth_url)
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
                    "log.severity": "info",
                    "log.message": "Kubectl Integration is configured.",
                })
            logger.info("Kubectl Integration is configured.")
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            user2 = KubectlConfig.query.filter_by(name=session['user_name']).first()
            if user2:
                try:
                    user_private_key = str(base64_decode(user2.private_key), 'UTF-8')
                    user_certificate = str(base64_decode(user2.user_certificate), 'UTF-8')
                    body = {
                        "username": username,
                        "context": k8sConfig.k8s_context,
                        "server": k8sConfig.k8s_server_url,
                        "certificate-authority-data": k8s_server_ca,
                        "user-private-key": user_private_key,
                        "user-certificate": user_certificate,
                    }
                    r = try_push_cert_kubeconfig_to_kdlogin(
                        current_app, remote_addr, body
                    )
                    if r.success:
                        logger.info("Config sent to kdlogin (cert)")
                except Exception as e:
                    if tracer and span.is_recording():
                        span.add_event("log", {
                            "log.severity": "error",
                            "log.message": "kdlogin cert push failed.",
                        })
                    logger.error("kdlogin cert push failed: %s", e)
        return redirect(url_for('dashboard.cluster_metrics'))
    else:
        if tracer and span.is_recording():
            span.set_attribute("http.route", "/")
            span.set_attribute("http.method", request.method)
        
        return render_template(
            'auth/login.html.j2',
            sso_enabled = is_sso_enabled,
            ldap_enabled = is_ldap_enabled,
            auth_url = authorization_url
        )
        
@auth_bp.route('/', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    remote_addr = client_ip_for_kdlogin_push(request)

    # Use SQLAlchemy ORM filter which automatically uses parameterized queries (SQL injection safe)
    # The username parameter is safely bound as a parameter, not concatenated into SQL
    user = User.query.filter(User.username == username, User.user_type != "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=username).first()
    
    span = trace.get_current_span()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password_hash, password):
        log_audit_event(
            user_id=username or "unknown",
            action="login",
            resource="session",
            result="failure",
            trace_id=getattr(g, "correlation_id", None),
        )
        flash('Please check your login details and try again.', "warning")
        return redirect(url_for('.login')) # if user doesn't exist or password is wrong, reload the page
    else:
        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        
        # Fix: Auto-assign Admin role to default admin user if no role exists
        if not user_role and username == 'admin' and user.user_type == 'Local':
            from lib.user import RoleCreate, db
            admin_role = Role.query.filter_by(name='Admin').first()
            if not admin_role:
                RoleCreate('Admin')
                admin_role = Role.query.filter_by(name='Admin').first()
            if admin_role:
                user.roles.append(admin_role)
                user_role = UsersRoles.query.filter_by(user_id=user.id).first()
                db.session.commit()
                logger.info(f"Auto-assigned Admin role to default admin user")
        
        if not user_role:
            flash('User role not assigned. Please contact administrator.', "danger")
            logger.error(f"User {username} has no role assigned")
            return redirect(url_for('.login'))
        role = Role.query.filter_by(id=user_role.role_id).first()
        if not role:
            flash('Invalid role configuration. Please contact administrator.', "danger")
            logger.error(f"User {username} has invalid role_id {user_role.role_id}")
            return redirect(url_for('.login'))
        login_user(user, remember=remember)
        session['user_name'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"

        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "error",
                    "log.message": "Kubectl Integration is not configured.",
                })
            logger.error ("Kubectl Integration is not configured.")
        else:
            if tracer and span.is_recording():
                span.add_event("log", {
                    "log.severity": "info",
                    "log.message": "Kubectl Integration is configured.",
                })
            logger.info("Kubectl Integration is configured.")
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            if user2:
                try:
                    user_private_key = str(base64_decode(user2.private_key), 'UTF-8')
                    user_certificate = str(base64_decode(user2.user_certificate), 'UTF-8')
                    body = {
                        "username": username,
                        "context": k8sConfig.k8s_context,
                        "server": k8sConfig.k8s_server_url,
                        "certificate-authority-data": k8s_server_ca,
                        "user-private-key": user_private_key,
                        "user-certificate": user_certificate,
                    }
                    r = try_push_cert_kubeconfig_to_kdlogin(
                        current_app, remote_addr, body
                    )
                    if r.success:
                        logger.info("Config sent to kdlogin (cert)")
                except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
                    logger.debug("No kdlogin client detected (connection refused/timeout)")
                except Exception as e:
                    if not request.args.get('next'):
                        if tracer and span.is_recording():
                            span.add_event("log", {
                                "log.severity": "error",
                                "log.message": f"kdlogin cert push: {str(e)}",
                            })
                        logger.error(f"kdlogin cert push: {str(e)}")


        log_audit_event(
            user_id=username,
            action="login",
            resource="session",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
        )
        next_url = request.args.get('next')
        if not next_url or not is_safe_url(next_url, request):  # <-- Security check!
            next_url = url_for('dashboard.cluster_metrics')  # Default fallback
        return redirect(next_url)  # <-- Redirect to 'next' or dashboard

@auth_bp.route('/logout')
@login_required
def logout():
    user_id = session.get("user_name", "unknown")
    logout_user()
    if "user_name" in session:
        session.pop('user_name', None)
    if "oauth_token" in session:
        session.pop('oauth_token')
    session.clear()
    log_audit_event(
        user_id=user_id,
        action="logout",
        resource="session",
        result="success",
        trace_id=getattr(g, "correlation_id", None),
    )
    return redirect(url_for('.login'))
