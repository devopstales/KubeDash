"""
Security API endpoints for managing Kubernetes security resources.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.security import k8sSecretListGet, k8sPolicyListGet
from lib.k8s.storage import k8sConfigmapListGet
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

security_api_bp = Blueprint(
    "security_api",
    "security_api",
    url_prefix="/security",
    description="Security API endpoints - Manage secrets and configmaps"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Secrets
##############################################################

@security_api_bp.route('/secrets')
class SecretsListResource(MethodView):
    """
    Secrets list endpoint.
    """
    
    @security_api_bp.response(200, description="Successfully retrieved secrets list")
    @security_api_bp.doc(tags=['Security'])
    @login_required
    def get(self):
        """
        List secrets
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of secrets with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        secrets = k8sSecretListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": secrets,
            "metadata": {
                "namespace": namespace,
                "count": len(secrets)
            }
        })


@security_api_bp.route('/secrets/<name>')
class SecretResource(MethodView):
    """
    Individual secret endpoint.
    """
    
    @security_api_bp.response(200, description="Successfully retrieved secret details")
    @security_api_bp.response(404, description="Secret not found")
    @security_api_bp.doc(tags=['Security'])
    @login_required
    def get(self, name):
        """
        Get secret details
        
        Path Parameters:
            name (str): Name of the secret
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Secret details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "secret-get",
            attributes={
                "http.route": "/api/v1/security/secrets/{name}",
                "http.method": "GET",
                "secret.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            secrets = k8sSecretListGet(session['user_role'], user_token, namespace)
            secret_data = None
            for secret in secrets:
                if secret["name"] == name:
                    secret_data = secret
                    break
            
            if not secret_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Secret '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": secret_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Network Policies
##############################################################

@security_api_bp.route('/network-policies')
class NetworkPoliciesListResource(MethodView):
    """
    Network policies list endpoint.
    """
    
    @security_api_bp.response(200, description="Successfully retrieved network policies list")
    @security_api_bp.doc(tags=['Security'])
    @login_required
    def get(self):
        """
        List network policies
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of network policies with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "network-policies-list",
            attributes={
                "http.route": "/api/v1/security/network-policies",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            policies = k8sPolicyListGet(session['user_role'], user_token, namespace)
            
            return jsonify({
                "data": policies,
                "metadata": {
                    "namespace": namespace,
                    "count": len(policies)
                }
            })


@security_api_bp.route('/network-policies/<name>')
class NetworkPolicyResource(MethodView):
    """
    Individual network policy endpoint.
    Supports NetworkPolicy, CiliumNetworkPolicy, and CiliumClusterwideNetworkPolicy.
    """
    
    @security_api_bp.response(200, description="Successfully retrieved network policy details")
    @security_api_bp.response(404, description="Network policy not found")
    @security_api_bp.doc(tags=['Security'])
    @login_required
    def get(self, name):
        """
        Get network policy details
        
        Path Parameters:
            name (str): Name of the network policy
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
            kind (str): Optional policy kind (NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy)
        
        Returns:
            dict: Network policy details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        kind = request.args.get('kind', None)
        
        with tracer.start_as_current_span(
            "network-policy-get",
            attributes={
                "http.route": "/api/v1/security/network-policies/{name}",
                "http.method": "GET",
                "network-policy.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            policies = k8sPolicyListGet(session['user_role'], user_token, namespace)
            policy_data = None
            
            # Find policy by name and optionally by kind
            for policy in policies:
                if policy["name"] == name:
                    # If kind is specified, match it; otherwise take first match
                    if not kind or policy.get("kind") == kind:
                        policy_data = policy
                        break
            
            if not policy_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"NetworkPolicy '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": policy_data,
                "metadata": {
                    "name": name,
                    "namespace": policy_data.get("namespace") or namespace,
                    "kind": policy_data.get("kind", "NetworkPolicy")
                }
            })


##############################################################
## ConfigMaps
##############################################################

@security_api_bp.route('/configmaps')
class ConfigMapsListResource(MethodView):
    """
    ConfigMaps list endpoint.
    """
    
    @security_api_bp.response(200, description="Successfully retrieved configmaps list")
    @security_api_bp.doc(tags=['Security'])
    @login_required
    def get(self):
        """
        List configmaps
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of configmaps with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        configmaps = k8sConfigmapListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": configmaps,
            "metadata": {
                "namespace": namespace,
                "count": len(configmaps)
            }
        })

