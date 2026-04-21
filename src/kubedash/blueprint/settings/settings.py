import json
import secrets
from ipaddress import ip_address as _validate_ip
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import yaml
from flask import (Blueprint, Response, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from flask_login import login_required, login_user
from itsdangerous import base64_decode, base64_encode

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.k8s.server import (k8sServerConfigCreate, k8sServerConfigDelete,
                            k8sServerConfigGet, k8sServerConfigList,
                            k8sServerConfigUpdate)
from lib.kdlogin_exchange import (
    SESSION_KDLOGIN_CODE_FROM_HANDOFF,
    SESSION_KDLOGIN_CODE_SHOW,
    SESSION_KDLOGIN_HANDOFF_ID,
    pop_kdlogin_handoff_payload,
    store_kdlogin_config_payload,
    store_kdlogin_handoff_payload,
)
from lib.kdlogin_push import (KDLOGIN_FLOW_KDLOGIN, SESSION_KDLOGIN_CLIENT_HOST,
                              SESSION_KDLOGIN_CLIENT_PORT, SESSION_OIDC_CLIENT_FLOW,
                              client_ip_for_kdlogin_push, http_url_host_for_browser_handoff,
                              resolve_kdlogin_listen_port, try_push_kubeconfig_to_kdlogin)
from lib.oauth_pkce import generate_pkce_pair
from lib.sso import (SSOSererGet, SSOServerCreate, SSOServerUpdate,
                     get_auth_server_info, oauth_tls_verify_value)
from lib.user import (KubectlConfig, Role, SSOGroupCreateFromList,
                      SSOGroupsUpdateFromList, SSOTokenUpdate, SSOUserCreate,
                      User, UsersRoles)

##############################################################
## Helpers
##############################################################


def _redact_oauth_callback_url(url: str) -> str:
    """OAuth callback URL safe for logs (code/state values redacted)."""
    p = urlparse(url)
    q = [
        (k, "<redacted>" if k in ("code", "state") else v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
    ]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


settings_bp = Blueprint("settings", __name__, url_prefix="/settings")
sso_bp = Blueprint("sso", __name__)
logger = get_logger()

from lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()

##############################################################
## SSO Settings
##############################################################

@settings_bp.route('/sso-config', methods=['GET', 'POST'])
@login_required
def sso_config():
    """
    SSO configuration page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/settings/sso
    return render_template('settings/sso-config.html.j2')

##############################################################
## Cluster Status
##############################################################

@settings_bp.route('/cluster-status')
@login_required
def cluster_status():
    """
    Cluster status page.
    
    Displays deployment mode, leader status, and cluster configuration.
    Data is loaded client-side via JavaScript API calls to /api/cluster/status.
    """
    return render_template('settings/cluster-status.html.j2')
        
@sso_bp.route("/callback", methods=["GET"])
def callback():
    if 'error' in request.args:
        log_audit_event(
            user_id="unknown",
            action="login",
            resource="session",
            result="failure",
            trace_id=getattr(g, "correlation_id", None),
            details={"method": "sso", "error": request.args.get("error", "")},
        )
        if request.args.get('error') == 'access_denied':
            flash('Access denied.', "danger")
        else:
            flash('Error encountered.', "danger")
    ssoServer = SSOSererGet()
    if ('code' not in request.args and 'state' not in request.args) or not ssoServer:
        return redirect(url_for('auth.login'))
    else:
        if request.args.get("state") != session.get("oauth_state"):
            logger.warning(
                "OIDC callback rejected: state mismatch or missing (remote=%s)",
                request.remote_addr,
            )
            session.pop("oauth_code_verifier", None)
            flash("Sign-in failed. Please try again.", "danger")
            return redirect(url_for("auth.login"))

        auth_server_info, oauth = get_auth_server_info()

        if auth_server_info is None:
            flash("Cannot connect to identity provider. Please try again later.", "danger")
            logger.error("Cannot connect to identity provider during callback - auth_server_info is None")
            return redirect(url_for('auth.login'))

        token_url = auth_server_info["token_endpoint"]
        userinfo_url = auth_server_info["userinfo_endpoint"]
        tls_verify = oauth_tls_verify_value(ssoServer)

        if (
            request.url.startswith("http://") and
            "HTTP_X_FORWARDED_PROTO" in request.environ and
            request.environ["HTTP_X_FORWARDED_PROTO"] == "https"
        ):
            request_url = request.url.replace("http", "https")
        else:
            request_url = request.url

        code_verifier = session.pop("oauth_code_verifier", None)
        token = oauth.fetch_token(
            token_url,
            authorization_response=request_url,
            client_secret=ssoServer.client_secret,
            timeout=60,
            verify=tls_verify,
            code_verifier=code_verifier,
        )
        user_data = oauth.get(
            userinfo_url,
            timeout=60,
            verify=tls_verify,
        ).json()

        remote_addr = client_ip_for_kdlogin_push(request)

        if session.get(SESSION_OIDC_CLIENT_FLOW) == KDLOGIN_FLOW_KDLOGIN:
            logger.info(
                "kdlogin OIDC callback url=%s client_ip_for_push=%s kdlogin_port=%s",
                _redact_oauth_callback_url(request_url),
                remote_addr,
                session.get(SESSION_KDLOGIN_CLIENT_PORT),
            )

## Kubectl config (kdlogin push + one-time code fallback)
        k8sConfig = k8sServerConfigGet()
        response_json = None
        if k8sConfig is None:
            logger.error("Kubectl Integration is not configured.")
        else:
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            response_json = {
                "username": k8sConfig.k8s_context,
                "context": k8sConfig.k8s_context,
                "server": k8sConfig.k8s_server_url,
                "certificate-authority-data": k8s_server_ca,
                "client-id": ssoServer.client_id,
                "id-token": token.get("id_token"),
                "refresh-token": token.get("refresh_token"),
                "idp-issuer-url": ssoServer.oauth_server_uri,
                "client_secret": ssoServer.client_secret,
            }
            if ssoServer.oauth_server_ca:
                response_json["idp-certificate-authority-data"] = ssoServer.oauth_server_ca
            else:
                response_json["idp-certificate-authority-data"] = None
## Kubectl config end (push runs after login_user — see below)

        email = user_data['email']
        username = user_data["preferred_username"]
        user_token = json.dumps(token)
        user = User.query.filter_by(username=username).first()
        USER_GROUPS = user_data.get("groups")
                
        if user is None:
            SSOUserCreate(username, email, user_token, "OpenID")
            if USER_GROUPS:
                SSOGroupCreateFromList(username, USER_GROUPS)
                SSOGroupsUpdateFromList(username, USER_GROUPS)
            else:
                logger.warning("No groups found for user %s" % username)
            user = User.query.filter_by(username=username, user_type = "OpenID").first()
        else:
            SSOTokenUpdate(username, user_token)
            if USER_GROUPS:
                SSOGroupsUpdateFromList(username, USER_GROUPS)
            else:
                logger.warning("No groups found for user %s" % username)

        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        if not user_role:
            flash('User role not assigned. Please contact administrator.', "danger")
            logger.error(f"User {username} has no role assigned")
            return redirect(url_for('dashboard.cluster_metrics'))
        role = Role.query.filter_by(id=user_role.role_id).first()
        if not role:
            flash('Invalid role configuration. Please contact administrator.', "danger")
            logger.error(f"User {username} has invalid role_id {user_role.role_id}")
            return redirect(url_for('dashboard.cluster_metrics'))

        session['oauth_token'] = token
        session['refresh_token'] = token.get("refresh_token")
        session['user_name'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"

        login_user(user)
        log_audit_event(
            user_id=username,
            action="login",
            resource="session",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
            details={"method": "sso"},
        )

        if (
            session.get(SESSION_OIDC_CLIENT_FLOW) == KDLOGIN_FLOW_KDLOGIN
            and response_json
        ):
            listen_port = resolve_kdlogin_listen_port(dict(session), current_app)
            plugin_lan_hint = (session.get(SESSION_KDLOGIN_CLIENT_HOST) or "").strip()
            logger.info(
                "kdlogin: server-side push to plugin host %s (from kdlogin_client)",
                plugin_lan_hint or "none",
            )
            push = try_push_kubeconfig_to_kdlogin(
                current_app, session, remote_addr, response_json
            )
            if push.success:
                logger.info(
                    "kdlogin kubeconfig delivered to the plugin (server-side push)"
                )
                return redirect(url_for("sso.kdlogin_push_delivered"))
            else:
                handoff_host = http_url_host_for_browser_handoff(plugin_lan_hint)
                if push.skipped:
                    logger.warning(
                        "kdlogin push skipped unexpectedly; using browser delivery page"
                    )
                else:
                    logger.info(
                        "kdlogin: server-side push did not complete (that path probes "
                        "GET /info then POST / from KubeDash); loading browser delivery "
                        "page that POSTs to http://%s:%s/ from the browser (no /info probe)",
                        handoff_host,
                        listen_port,
                    )
                hid = store_kdlogin_handoff_payload(current_app, response_json)
                session[SESSION_KDLOGIN_HANDOFF_ID] = hid
                return render_template(
                    "settings/kdlogin-browser-handoff.html.j2",
                    payload_json=response_json,
                    listen_port=listen_port,
                    handoff_host=handoff_host,
                    next_url=url_for("sso.kdlogin_push_delivered"),
                    fallback_url=url_for("sso.kdlogin_handoff_fallback"),
                )

        if session.get(SESSION_KDLOGIN_CODE_SHOW):
            return redirect(url_for("sso.kdlogin_code"))
        return redirect(url_for('dashboard.cluster_metrics'))
    
##############################################################
## Kubectl config
##############################################################

@settings_bp.route('/k8s-config', methods=['GET', 'POST'])
@login_required
def k8s_config():
    """
    Kubernetes cluster configuration page.

    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/settings/k8s/configs
    return render_template('settings/cluster-config.html.j2')

@settings_bp.route('/audit-log')
@login_required
def audit_log():
    """
    Audit log page (Admin only). Query and export audit events for compliance.
    """
    if session.get('user_role') != 'Admin':
        flash('Access denied. Admin role required.', 'danger')
        return redirect(url_for('dashboard.cluster_metrics'))
    return render_template('settings/audit-log.html.j2')


@settings_bp.route('/export')
@login_required
def export():
    """
    Export kubectl configuration page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Same variable name as kdlogin-code.html.j2; value is a fresh example token per page load (not usable for exchange).
    return render_template(
        'settings/export.html.j2',
        exchange_code=secrets.token_urlsafe(18),
    )

@sso_bp.route('/kdlogin')
def index():
    auth_server_info, oauth = get_auth_server_info()

    if auth_server_info is None:
        flash("Cannot connect to identity provider. Please try again later.", "danger")
        logger.error("Cannot connect to identity provider - auth_server_info is None")
        return redirect(url_for('auth.login'))

    session[SESSION_OIDC_CLIENT_FLOW] = "kdlogin"
    port = request.args.get("port", type=int)
    if port is not None and 1 <= port <= 65535:
        session[SESSION_KDLOGIN_CLIENT_PORT] = port
    else:
        session.pop(SESSION_KDLOGIN_CLIENT_PORT, None)

    client_hint = request.args.get("kdlogin_client") or request.args.get("client_ip")
    if client_hint:
        try:
            _validate_ip(client_hint.strip())
            session[SESSION_KDLOGIN_CLIENT_HOST] = client_hint.strip()
        except ValueError:
            session.pop(SESSION_KDLOGIN_CLIENT_HOST, None)
    else:
        session.pop(SESSION_KDLOGIN_CLIENT_HOST, None)

    auth_url = auth_server_info["authorization_endpoint"]
    code_verifier, code_challenge = generate_pkce_pair()
    session["oauth_code_verifier"] = code_verifier

    authorization_url, state = oauth.authorization_url(
        auth_url,
        access_type="offline",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    session["oauth_state"] = state
    return redirect(authorization_url)


@sso_bp.route("/kdlogin/handoff-fallback")
@login_required
def kdlogin_handoff_fallback():
    """Issue one-time code when browser could not POST kubeconfig to localhost kdlogin."""
    hid = session.pop(SESSION_KDLOGIN_HANDOFF_ID, None)
    if not hid:
        return redirect(url_for("dashboard.cluster_metrics"))
    payload = pop_kdlogin_handoff_payload(current_app, hid)
    if not payload:
        flash(
            "That login handoff expired. Please run kubectl kdlogin again if you still need the config.",
            "warning",
        )
        return redirect(url_for("dashboard.cluster_metrics"))
    otc = store_kdlogin_config_payload(current_app, payload)
    session[SESSION_KDLOGIN_CODE_SHOW] = otc
    session[SESSION_KDLOGIN_CODE_FROM_HANDOFF] = True
    logger.info(
        "kdlogin: browser POST to localhost did not complete; issued one-time config code"
    )
    return redirect(url_for("sso.kdlogin_code"))


@sso_bp.route("/kdlogin/delivered")
@login_required
def kdlogin_push_delivered():
    """After kubeconfig was pushed to kdlogin (server or browser); user can close the tab."""
    return render_template("settings/kdlogin-delivered.html.j2")


@sso_bp.route("/kdlogin/success")
def kdlogin_success_legacy_redirect():
    """Old URL for the one-time code page; use /kdlogin/code."""
    return redirect(url_for("sso.kdlogin_code"), code=301)


@sso_bp.route("/kdlogin/code")
@login_required
def kdlogin_code():
    """One-time code for kubectl when kubeconfig push to the local plugin did not complete."""
    code = session.get(SESSION_KDLOGIN_CODE_SHOW)
    if not code:
        return redirect(url_for("dashboard.cluster_metrics"))
    session.pop(SESSION_KDLOGIN_CODE_SHOW, None)
    from_handoff_fallback = session.pop(SESSION_KDLOGIN_CODE_FROM_HANDOFF, False)
    sso = SSOSererGet()
    base = (sso.base_uri if sso else "").rstrip("/")
    return render_template(
        "settings/kdlogin-code.html.j2",
        exchange_code=code,
        plugin_base_url=base or request.url_root.rstrip("/"),
        from_handoff_fallback=from_handoff_fallback,
    )

@sso_bp.route("/get-file")
@login_required
def get_file():
    user = User.query.filter_by(username=session['user_name'], user_type = "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=session['user_name']).first()
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
        
        if auth_server_info is None:
            flash("Cannot connect to identity provider. Please try again later.", "danger")
            logger.error("Cannot connect to identity provider - auth_server_info is None")
            return Response("Cannot connect to identity provider", status=503, mimetype='text/plain')
        
        token_url = auth_server_info["token_endpoint"]
        verify = oauth_tls_verify_value(ssoServer)

        try:
            token = oauth.refresh_token(
                token_url = token_url,
                refresh_token = session['refresh_token'],
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                verify = verify,
                timeout = 60,
            )
        except Exception as e:
            flash(f"Failed to refresh token: {str(e)}", "danger")
            logger.error(f"Failed to refresh token: {e}")
            return Response(f"Failed to refresh token: {str(e)}", status=503, mimetype='text/plain')

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
        if ssoServer.oauth_server_ca:
            kube_user["auth-provider"]["config"]["idp-certificate-authority-data"] = ssoServer.oauth_server_ca
        if ssoServer.client_secret:
            kube_user["auth-provider"]["config"]["client-secret"] = ssoServer.client_secret

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
