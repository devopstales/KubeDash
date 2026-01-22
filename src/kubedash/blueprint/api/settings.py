"""
Settings API endpoints for application configuration.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint
from itsdangerous import base64_encode, base64_decode

from lib.helper_functions import get_logger
from lib.k8s.server import (
    k8sServerConfigList, k8sServerContextsList, k8sServerConfigCreate,
    k8sServerConfigUpdate, k8sServerConfigDelete, k8sServerConfigGet
)
from lib.sso import (
    SSOSererGet, SSOServerCreate, SSOServerUpdate
)
from lib.opentelemetry import get_tracer

##############################################################
## Blueprint Definition
##############################################################

settings_api_bp = Blueprint(
    "settings_api",
    "settings_api",
    url_prefix="/settings",
    description="Settings API endpoints - Manage application settings including SSO configuration and Kubernetes server contexts"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## SSO Configuration
##############################################################

@settings_api_bp.route('/sso')
class SSOConfigResource(MethodView):
    """
    SSO configuration endpoint.
    
    Manages SSO/OIDC server configuration.
    """
    
    @settings_api_bp.response(200, description="Successfully retrieved SSO configuration")
    @settings_api_bp.response(404, description="SSO configuration not found")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def get(self):
        """
        Get SSO configuration
        
        Retrieves the current SSO/OIDC server configuration.
        
        Returns:
            dict: SSO configuration including OAuth server URI, client credentials, etc.
        """
        sso_server = SSOSererGet()
        
        if not sso_server:
            return jsonify({
                "error": "NotFound",
                "message": "No SSO configuration has been set up"
            }), 404
        
        # Handle scope - it's stored as a MutableList, so convert to regular list
        scope = sso_server.scope if sso_server.scope else []
        if isinstance(scope, list):
            scope = list(scope)  # Convert MutableList to regular list
        elif isinstance(scope, str):
            scope = [s.strip() for s in scope.split(',') if s.strip()]
        else:
            scope = []
        
        return jsonify({
            "data": {
                "oauth_server_uri": sso_server.oauth_server_uri,
                "oauth_server_ca": sso_server.oauth_server_ca,
                "client_id": sso_server.client_id,
                "client_secret": sso_server.client_secret,  # Return actual secret for UI display
                "base_uri": sso_server.base_uri,
                "scope": scope
            }
        })
    
    @settings_api_bp.response(200, description="Successfully updated SSO configuration")
    @settings_api_bp.response(201, description="Successfully created SSO configuration")
    @settings_api_bp.response(400, description="Bad request - Invalid input data")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def post(self):
        """
        Create or update SSO configuration
        
        Creates a new SSO configuration or updates an existing one.
        
        Request Body:
            dict: SSO configuration data:
                {
                    "oauth_server_uri": str,
                    "oauth_server_ca": str (optional),
                    "client_id": str,
                    "client_secret": str,
                    "base_uri": str,
                    "scope": list[str],
                    "request_type": str ("create" or "edit")
                }
        
        Returns:
            dict: Created/updated SSO configuration
        """
        data = request.get_json() or request.form.to_dict()
        oauth_server_uri = data.get('oauth_server_uri')
        oauth_server_ca = data.get('oauth_server_ca')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        base_uri = data.get('base_uri', request.root_url.rstrip(request.root_url[-1]))
        scope = data.get('scope', ['openid', 'email', 'offline_access', 'profile'])
        request_type = data.get('request_type', 'create')
        
        # Handle scope as list or string
        if isinstance(scope, str):
            scope = [s.strip() for s in scope.split(',') if s.strip()]
        
        # Validate required fields
        if not all([oauth_server_uri, client_id]):
            return jsonify({
                "error": "BadRequest",
                "message": "oauth_server_uri and client_id are required"
            }), 400
        
        # Client secret is required for create, optional for edit
        if request_type == "create" and not client_secret:
            return jsonify({
                "error": "BadRequest",
                "message": "client_secret is required when creating SSO configuration"
            }), 400
        
        # If editing and client_secret is empty, get the existing one from database
        if request_type == "edit" and not client_secret:
            from lib.sso import SSOSererGet
            existing_sso = SSOSererGet()
            if existing_sso:
                client_secret = existing_sso.client_secret
            else:
                return jsonify({
                    "error": "NotFound",
                    "message": "Cannot update: SSO configuration not found"
                }), 404
        
        if oauth_server_ca:
            oauth_server_ca = str(base64_encode(oauth_server_ca.strip()), 'UTF-8')
        
        if request_type == "edit":
            oauth_server_uri_old = data.get('oauth_server_uri_old', oauth_server_uri)
            SSOServerUpdate(
                oauth_server_uri_old, oauth_server_uri, oauth_server_ca,
                client_id, client_secret, base_uri, scope
            )
            status_code = 200
        else:
            SSOServerCreate(
                oauth_server_uri, oauth_server_ca, client_id,
                client_secret, base_uri, scope
            )
            status_code = 201
        
        return jsonify({
            "message": f"SSO configuration {request_type}ed successfully",
            "data": {
                "oauth_server_uri": oauth_server_uri,
                "client_id": client_id,
                "base_uri": base_uri,
                "scope": scope
            }
        }), status_code


##############################################################
## Kubernetes Server Contexts
##############################################################

@settings_api_bp.route('/k8s/contexts')
class K8sContextsResource(MethodView):
    """
    Kubernetes server contexts endpoint.
    
    Manages Kubernetes server context configurations.
    """
    
    @settings_api_bp.response(200, description="Successfully retrieved K8s contexts list")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def get(self):
        """
        List Kubernetes server contexts
        
        Retrieves all configured Kubernetes server contexts.
        
        Returns:
            dict: List of K8s contexts
        """
        contexts = k8sServerContextsList()
        
        return jsonify({
            "data": contexts,
            "metadata": {
                "count": len(contexts)
            }
        })


@settings_api_bp.route('/k8s/configs')
class K8sConfigsResource(MethodView):
    """
    Kubernetes server configurations endpoint.
    """
    
    @settings_api_bp.response(200, description="Successfully retrieved K8s configs list")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def get(self):
        """
        List Kubernetes server configurations
        
        Returns:
            dict: List of K8s server configurations
        """
        configs_query, config_list_length = k8sServerConfigList()
        
        # Convert SQLAlchemy query results to list of dictionaries
        configs = []
        for config in configs_query.all():
            configs.append({
                "k8s_context": config.k8s_context,
                "k8s_server_url": config.k8s_server_url,
                "k8s_server_ca": config.k8s_server_ca  # This is base64 encoded
            })
        
        return jsonify({
            "data": configs,
            "metadata": {
                "count": len(configs),
                "list_length": config_list_length
            }
        })
    
    @settings_api_bp.response(201, description="Successfully created K8s config")
    @settings_api_bp.response(400, description="Bad request - Invalid input data")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def post(self):
        """
        Create a new Kubernetes server configuration
        
        Request Body:
            dict: K8s config data:
                {
                    "k8s_context": str,
                    "k8s_server_url": str,
                    "k8s_server_ca": str (base64 encoded)
                }
        
        Returns:
            dict: Created K8s configuration
        """
        data = request.get_json() or request.form.to_dict()
        k8s_context = data.get('k8s_context')
        k8s_server_url = data.get('k8s_server_url')
        k8s_server_ca = data.get('k8s_server_ca')
        
        if not all([k8s_context, k8s_server_url, k8s_server_ca]):
            return jsonify({
                "error": "BadRequest",
                "message": "k8s_context, k8s_server_url, and k8s_server_ca are required"
            }), 400
        
        k8s_server_ca = str(base64_encode(k8s_server_ca.strip()), 'UTF-8')
        k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca)
        
        return jsonify({
            "message": "Kubernetes Config Created Successfully",
            "data": {
                "k8s_context": k8s_context,
                "k8s_server_url": k8s_server_url
            }
        }), 201


@settings_api_bp.route('/k8s/configs/<context>')
class K8sConfigResource(MethodView):
    """
    Individual Kubernetes server configuration endpoint.
    """
    
    @settings_api_bp.response(200, description="Successfully updated K8s config")
    @settings_api_bp.response(400, description="Bad request - Invalid input data")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def put(self, context):
        """
        Update a Kubernetes server configuration
        
        Path Parameters:
            context (str): Name of the K8s context to update
        
        Request Body:
            dict: K8s config data:
                {
                    "k8s_context": str (new context name, optional),
                    "k8s_server_url": str,
                    "k8s_server_ca": str (base64 encoded)
                }
        
        Returns:
            dict: Updated K8s configuration
        """
        data = request.get_json() or request.form.to_dict()
        k8s_context_old = context
        k8s_context = data.get('k8s_context', k8s_context_old)
        k8s_server_url = data.get('k8s_server_url')
        k8s_server_ca = data.get('k8s_server_ca')
        
        if not all([k8s_server_url, k8s_server_ca]):
            return jsonify({
                "error": "BadRequest",
                "message": "k8s_server_url and k8s_server_ca are required"
            }), 400
        
        k8s_server_ca = base64_encode(k8s_server_ca.strip())
        k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca)
        
        return jsonify({
            "message": "Kubernetes Config Updated Successfully",
            "data": {
                "k8s_context": k8s_context,
                "k8s_server_url": k8s_server_url
            }
        })
    
    @settings_api_bp.response(200, description="Successfully deleted K8s config")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def delete(self, context):
        """
        Delete a Kubernetes server configuration
        
        Path Parameters:
            context (str): Name of the K8s context to delete
        
        Returns:
            dict: Deletion confirmation
        """
        k8sServerConfigDelete(context)
        
        return jsonify({
            "message": "Kubernetes Config Deleted Successfully"
        })


@settings_api_bp.route('/export')
class ExportResource(MethodView):
    """
    Export kubectl configuration endpoint.
    """
    
    @settings_api_bp.response(200, description="Successfully retrieved export data")
    @settings_api_bp.response(404, description="Kubernetes cluster not configured")
    @settings_api_bp.doc(tags=['Settings'])
    @login_required
    def get(self):
        """
        Get kubectl configuration export data
        
        Returns export data for generating kubectl config files.
        Supports both OIDC and certificate-based authentication.
        
        Returns:
            dict: Export configuration data
        """
        from lib.user import User, KubectlConfig
        import requests
        
        user = User.query.filter_by(username=session['user_name'], user_type="OpenID").first()
        user2 = KubectlConfig.query.filter_by(name=session['user_name']).first()
        k8sConfig = k8sServerConfigGet()
        
        if not k8sConfig:
            return jsonify({
                "error": "NotFound",
                "message": "Kubernetes Cluster is not Configured"
            }), 404
        
        k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
        
        if user:
            # OIDC user
            ssoServer = SSOSererGet()
            if not ssoServer:
                return jsonify({
                    "error": "NotFound",
                    "message": "SSO configuration not found"
                }), 404
            
            redirect_uri = ssoServer.base_uri + "/callback"
            auth_server_info, oauth = get_auth_server_info()
            
            if not auth_server_info:
                return jsonify({
                    "error": "ServiceUnavailable",
                    "message": "Cannot connect to identity provider"
                }), 503
            
            try:
                token_url = auth_server_info["token_endpoint"]
                token = oauth.refresh_token(
                    token_url=token_url,
                    refresh_token=session.get('refresh_token'),
                    client_id=ssoServer.client_id,
                    client_secret=ssoServer.client_secret,
                    verify=False,
                    timeout=60,
                )
                
                userinfo_url = auth_server_info["userinfo_endpoint"]
                user_data = oauth.get(
                    userinfo_url,
                    timeout=60,
                    verify=False,
                ).json()
                
                return jsonify({
                    "data": {
                        "type": "oidc",
                        "base_uri": ssoServer.base_uri,
                        "preferred_username": user_data.get("preferred_username"),
                        "redirect_uri": redirect_uri,
                        "client_id": ssoServer.client_id,
                        "client_secret": ssoServer.client_secret,
                        "id_token": token.get("id_token"),
                        "refresh_token": token.get("refresh_token"),
                        "oauth_server_uri": ssoServer.oauth_server_uri,
                        "oauth_server_ca": ssoServer.oauth_server_ca,
                        "context": k8sConfig.k8s_context,
                        "k8s_server_url": k8sConfig.k8s_server_url,
                        "k8s_server_ca": k8s_server_ca
                    }
                })
            except Exception as e:
                return jsonify({
                    "error": "InternalServerError",
                    "message": f"Failed to refresh token: {str(e)}"
                }), 500
        elif user2:
            # Certificate-based user
            return jsonify({
                "data": {
                    "type": "cert",
                    "preferred_username": user2.name,
                    "context": k8sConfig.k8s_context,
                    "k8s_server_url": k8sConfig.k8s_server_url,
                    "k8s_server_ca": k8s_server_ca,
                    "k8s_user_private_key": user2.private_key,
                    "k8s_user_certificate": user2.user_certificate
                }
            })
        else:
            # No authentication configured
            return jsonify({
                "data": {
                    "type": "none",
                    "preferred_username": session.get('user_name'),
                    "username_role": session.get('user_role')
                }
            })

