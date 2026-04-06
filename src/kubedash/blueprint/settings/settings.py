import json

import requests
import yaml
from flask import (Blueprint, Response, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_login import login_required, login_user
from itsdangerous import base64_decode, base64_encode

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.k8s.server import (k8sServerConfigCreate, k8sServerConfigDelete,
                            k8sServerConfigGet, k8sServerConfigList,
                            k8sServerConfigUpdate)
from lib.sso import (SSOSererGet, SSOServerCreate, SSOServerUpdate,
                     get_auth_server_info)
from lib.user import (KubectlConfig, Role, SSOGroupCreateFromList,
                      SSOGroupsUpdateFromList, SSOTokenUpdate, SSOUserCreate,
                      User, UsersRoles)

##############################################################
## Helpers
##############################################################

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
        return redirect(url_for('sso.login'))
    else:
        auth_server_info, oauth = get_auth_server_info()
        
        if auth_server_info is None:
            flash("Cannot connect to identity provider. Please try again later.", "danger")
            logger.error("Cannot connect to identity provider during callback - auth_server_info is None")
            return redirect(url_for('login.login'))
        
        token_url = auth_server_info["token_endpoint"]
        userinfo_url = auth_server_info["userinfo_endpoint"]

        if (
            request.url.startswith("http://") and
            "HTTP_X_FORWARDED_PROTO" in request.environ and
            request.environ["HTTP_X_FORWARDED_PROTO"] == "https"
        ):
            request_url = request.url.replace("http", "https")
        else:
            request_url = request.url
        logger.info("Request URL %s" % request_url)

        token = oauth.fetch_token(
            token_url,
            authorization_response = request_url,
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
                i = requests.get('http://%s:8080/info' % remote_addr, timeout=1)
                info = i.json()
                response_json = {
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
                if ssoServer.oauth_server_ca:
                    response_json["idp-certificate-authority-data"] = ssoServer.oauth_server_ca
                else:
                    response_json["idp-certificate-authority-data"] = None
                
                if info.get("message") == "kdlogin":
                    x = requests.post('http://%s:8080/' % remote_addr, json=response_json, timeout=5)
                    logger.info("Config sent to client")
                    logger.info("Answer from clinet: %s" % x.text)
                else:
                    logger.warning("NO config sent to client")
                    logger.warning("Missing header")
            except:
                pass
## Kubectl config end

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
    # Template now loads data via JavaScript from /api/v1/settings/export
    return render_template('settings/export.html.j2')

@sso_bp.route('/kdlogin')
def index():
    auth_server_info, oauth = get_auth_server_info()
    
    if auth_server_info is None:
        flash("Cannot connect to identity provider. Please try again later.", "danger")
        logger.error("Cannot connect to identity provider - auth_server_info is None")
        return redirect(url_for('login.login'))
    
    auth_url = auth_server_info["authorization_endpoint"]

    authorization_url, state = oauth.authorization_url(
        auth_url,
        access_type="offline",  # not sure if it is actually always needed,
                                # may be a cargo-cult from Google-based example
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

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
        verify = False

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
