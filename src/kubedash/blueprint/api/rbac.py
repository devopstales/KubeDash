"""
RBAC API endpoints for managing Kubernetes RBAC resources.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.security import (
    k8sRoleListGet, k8sRoleGet,
    k8sClusterRoleListGet, k8sClusterRoleGet,
    k8sRoleBindingListGet, k8sClusterRoleBindingListGet,
    k8sSaListGet
)
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

rbac_api_bp = Blueprint(
    "rbac_api",
    "rbac_api",
    url_prefix="/rbac",
    description="RBAC API endpoints - Manage roles, cluster roles, role bindings, and service accounts"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Roles
##############################################################

@rbac_api_bp.route('/roles')
class RolesListResource(MethodView):
    """
    Roles list endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved roles list")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self):
        """
        List roles
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of roles with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        roles = k8sRoleListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": roles,
            "metadata": {
                "namespace": namespace,
                "count": len(roles)
            }
        })


@rbac_api_bp.route('/roles/<name>')
class RoleResource(MethodView):
    """
    Individual role endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved role details")
    @rbac_api_bp.response(404, description="Role not found")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self, name):
        """
        Get role details
        
        Path Parameters:
            name (str): Name of the role
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Role details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "role-get",
            attributes={
                "http.route": "/api/v1/rbac/roles/{name}",
                "http.method": "GET",
                "role.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            role = k8sRoleGet(session['user_role'], user_token, name, namespace)
            
            if not role:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Role '{name}' not found in namespace '{namespace}'"
                }), 404
            
            # Convert V1PolicyRule objects to dictionaries for JSON serialization
            if role.get('rules'):
                serialized_rules = []
                for rule in role['rules']:
                    if hasattr(rule, 'to_dict'):
                        # Use to_dict() if available (Kubernetes client library method)
                        rule_dict = rule.to_dict()
                        serialized_rules.append(rule_dict)
                    elif isinstance(rule, dict):
                        # Already a dict
                        serialized_rules.append(rule)
                    else:
                        # Manual conversion for V1PolicyRule objects
                        rule_dict = {
                            'apiGroups': list(rule.api_groups) if hasattr(rule, 'api_groups') and rule.api_groups else [],
                            'resources': list(rule.resources) if hasattr(rule, 'resources') and rule.resources else [],
                            'verbs': list(rule.verbs) if hasattr(rule, 'verbs') and rule.verbs else [],
                            'resourceNames': list(rule.resource_names) if hasattr(rule, 'resource_names') and rule.resource_names else None,
                            'nonResourceURLs': list(rule.non_resource_urls) if hasattr(rule, 'non_resource_urls') and rule.non_resource_urls else None
                        }
                        # Remove None values
                        rule_dict = {k: v for k, v in rule_dict.items() if v is not None}
                        serialized_rules.append(rule_dict)
                role['rules'] = serialized_rules
            
            return jsonify({
                "data": role,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Cluster Roles
##############################################################

@rbac_api_bp.route('/cluster-roles')
class ClusterRolesListResource(MethodView):
    """
    Cluster roles list endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved cluster roles list")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self):
        """
        List cluster roles
        
        Returns:
            dict: List of cluster roles with metadata
        """
        user_token = get_user_token(session)
        
        cluster_roles = k8sClusterRoleListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": cluster_roles,
            "metadata": {
                "count": len(cluster_roles)
            }
        })


@rbac_api_bp.route('/cluster-roles/<name>')
class ClusterRoleResource(MethodView):
    """
    Individual cluster role endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved cluster role details")
    @rbac_api_bp.response(404, description="Cluster role not found")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self, name):
        """
        Get cluster role details
        
        Path Parameters:
            name (str): Name of the cluster role
        
        Returns:
            dict: Cluster role details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "cluster-role-get",
            attributes={
                "http.route": "/api/v1/rbac/cluster-roles/{name}",
                "http.method": "GET",
                "cluster-role.name": name,
            }
        ) if tracer else nullcontext():
            cluster_role = k8sClusterRoleGet(session['user_role'], user_token, name)
            
            if not cluster_role:
                return jsonify({
                    "error": "NotFound",
                    "message": f"ClusterRole '{name}' not found"
                }), 404
            
            # Convert V1PolicyRule objects to dictionaries for JSON serialization
            if cluster_role.get('rules'):
                serialized_rules = []
                for rule in cluster_role['rules']:
                    if hasattr(rule, 'to_dict'):
                        # Use to_dict() if available (Kubernetes client library method)
                        rule_dict = rule.to_dict()
                        serialized_rules.append(rule_dict)
                    elif isinstance(rule, dict):
                        # Already a dict
                        serialized_rules.append(rule)
                    else:
                        # Manual conversion for V1PolicyRule objects
                        rule_dict = {
                            'apiGroups': list(rule.api_groups) if hasattr(rule, 'api_groups') and rule.api_groups else [],
                            'resources': list(rule.resources) if hasattr(rule, 'resources') and rule.resources else [],
                            'verbs': list(rule.verbs) if hasattr(rule, 'verbs') and rule.verbs else [],
                            'resourceNames': list(rule.resource_names) if hasattr(rule, 'resource_names') and rule.resource_names else None,
                            'nonResourceURLs': list(rule.non_resource_urls) if hasattr(rule, 'non_resource_urls') and rule.non_resource_urls else None
                        }
                        # Remove None values
                        rule_dict = {k: v for k, v in rule_dict.items() if v is not None}
                        serialized_rules.append(rule_dict)
                cluster_role['rules'] = serialized_rules
            
            return jsonify({
                "data": cluster_role,
                "metadata": {
                    "name": name
                }
            })


##############################################################
## Role Bindings
##############################################################

@rbac_api_bp.route('/role-bindings')
class RoleBindingsListResource(MethodView):
    """
    Role bindings list endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved role bindings list")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self):
        """
        List role bindings
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of role bindings with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        role_bindings = k8sRoleBindingListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": role_bindings,
            "metadata": {
                "namespace": namespace,
                "count": len(role_bindings)
            }
        })


##############################################################
## Cluster Role Bindings
##############################################################

@rbac_api_bp.route('/cluster-role-bindings')
class ClusterRoleBindingsListResource(MethodView):
    """
    Cluster role bindings list endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved cluster role bindings list")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self):
        """
        List cluster role bindings
        
        Returns:
            dict: List of cluster role bindings with metadata
        """
        user_token = get_user_token(session)
        
        cluster_role_bindings = k8sClusterRoleBindingListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": cluster_role_bindings,
            "metadata": {
                "count": len(cluster_role_bindings)
            }
        })


##############################################################
## Service Accounts
##############################################################

@rbac_api_bp.route('/service-accounts')
class ServiceAccountsListResource(MethodView):
    """
    Service accounts list endpoint.
    """
    
    @rbac_api_bp.response(200, description="Successfully retrieved service accounts list")
    @rbac_api_bp.doc(tags=['RBAC'])
    @login_required
    def get(self):
        """
        List service accounts
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of service accounts with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        service_accounts = k8sSaListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": service_accounts,
            "metadata": {
                "namespace": namespace,
                "count": len(service_accounts)
            }
        })

