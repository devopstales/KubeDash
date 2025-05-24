import json

import requests
import yaml
from flask import (Blueprint, Response, flash, redirect, render_template,
                   request, session, url_for)
from flask_login import login_required, login_user
from itsdangerous import base64_decode, base64_encode
from opentelemetry import trace

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

settings = Blueprint("settings", __name__, url_prefix="/settings")
sso = Blueprint("sso", __name__)
logger = get_logger()

tracer = trace.get_tracer(__name__)

##############################################################
## SSO Settings
##############################################################

@settings.route('/sso-config', methods=['GET', 'POST'])
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
            'settings/sso-config.html.j2',
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
                'settings/sso-config.html.j2',
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
                'settings/sso-config.html.j2',
                oauth_server_uri = ssoServer.oauth_server_uri,
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                base_uri = ssoServer.base_uri,
                scope  = ssoServer.scope,
            )
        
@sso.route("/callback", methods=["GET"])
def callback():
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            flash('Access denied.', "danger")
        else:
            flash('Error encountered.', "danger")
    ssoServer = SSOSererGet()
    if ('code' not in request.args and 'state' not in request.args) or not ssoServer:
        return redirect(url_for('sso.login'))
    else:
        auth_server_info, oauth = get_auth_server_info()
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

        if user is None:
            SSOUserCreate(username, email, user_token, "OpenID")
            SSOGroupCreateFromList(username, user_data["groups"])
            SSOGroupsUpdateFromList(username, user_data["groups"])
            user = User.query.filter_by(username=username, user_type = "OpenID").first()
        else:
            SSOTokenUpdate(username, user_token)
            SSOGroupsUpdateFromList(username, user_data["groups"])

        user_role = UsersRoles.query.filter_by(user_id=user.id).first()
        role = Role.query.filter_by(id=user_role.role_id).first()

        session['oauth_token'] = token
        session['refresh_token'] = token.get("refresh_token")
        session['user_name'] = username
        session['user_role'] = role.name
        session['user_type'] = user.user_type
        session['ns_select'] = "default"

        login_user(user)
        return redirect(url_for('dashboard.cluster_metrics'))
    
##############################################################
## Kubectl config
##############################################################

@settings.route('/cluster-config', methods=['GET', 'POST'])
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
            k8sServerConfigDelete(k8s_context)

    k8s_servers, k8s_config_list_length = k8sServerConfigList()

    return render_template(
        'settings/cluster-config.html.j2',
        k8s_servers = k8s_servers,
        k8s_config_list_length = k8s_config_list_length,
    )

@settings.route('/export')
@login_required
def export():
    user = User.query.filter_by(username=session['user_name'], user_type = "OpenID").first()
    user2 = KubectlConfig.query.filter_by(name=session['user_name']).first()
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
                'settings/export.html.j2',
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
                'settings/export.html.j2',
                preferred_username = user2.name,
                context = k8sConfig.k8s_context,
                k8s_server_url = k8sConfig.k8s_server_url,
                k8s_server_ca = k8s_server_ca,
                k8s_user_private_key = user2.private_key,
                k8s_user_certificate = user2.user_certificate,
            )
        else:
            return render_template(
                'settings/export.html.j2',
                preferred_username = session['user_name'],
                username_role = session['user_role']
            )
    else:
        flash("Kubernetes Cluster is not Configured.", "danger")
        return render_template(
            'settings/export.html.j2',
            preferred_username = session['user_name'],
            username_role = session['user_role']
        )

@sso.route('/kdlogin')
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

@sso.route("/get-file")
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
