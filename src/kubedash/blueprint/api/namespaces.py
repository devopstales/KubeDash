"""
Namespaces API endpoints for managing Kubernetes namespaces.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.namespace import (
    k8sNamespacesGet, k8sNamespaceListGet,
    k8sNamespaceCreate, k8sNamespaceDelete
)
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

namespaces_api_bp = Blueprint(
    "namespaces_api",
    "namespaces_api",
    url_prefix="/namespaces",
    description="Namespaces API endpoints - Manage Kubernetes namespaces"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Namespaces List
##############################################################

@namespaces_api_bp.route('')
class NamespacesListResource(MethodView):
    """
    Namespaces list endpoint.
    """
    
    @namespaces_api_bp.response(200, description="Successfully retrieved namespaces list")
    @namespaces_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        List namespaces
        
        Returns:
            dict: List of namespaces with metadata
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "namespaces-list",
            attributes={
                "http.route": "/api/v1/namespaces",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            namespaces = k8sNamespacesGet(session['user_role'], user_token)
            
            return jsonify({
                "data": namespaces,
                "metadata": {
                    "count": len(namespaces)
                }
            })


@namespaces_api_bp.route('/list')
class NamespacesListWithPermissionsResource(MethodView):
    """
    Namespaces list with permissions endpoint.
    
    Returns namespaces with user permission information.
    """
    
    @namespaces_api_bp.response(200, description="Successfully retrieved namespaces list with permissions")
    @namespaces_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        List namespaces with permissions
        
        Returns namespaces along with user permission information.
        
        Returns:
            dict: List of namespaces with permission metadata
        """
        user_token = get_user_token(session)
        
        namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
        
        if error:
            return jsonify({
                "data": [],
                "metadata": {
                    "count": 0,
                    "error": error
                }
            }), 500
        
        return jsonify({
            "data": namespace_list,
            "metadata": {
                "count": len(namespace_list),
                "error": None
            }
        })


##############################################################
## Namespace Operations
##############################################################

@namespaces_api_bp.route('', methods=['POST'])
class NamespaceCreateResource(MethodView):
    """
    Namespace creation endpoint.
    """
    
    @namespaces_api_bp.response(201, description="Successfully created namespace")
    @namespaces_api_bp.response(400, description="Bad request - Invalid namespace name")
    @namespaces_api_bp.doc(tags=['Cluster'])
    @login_required
    def post(self):
        """
        Create namespace
        
        Request Body:
            dict: Namespace creation data:
                {
                    "namespace": str
                }
        
        Returns:
            dict: Created namespace information
        """
        data = request.get_json() or {}
        namespace = data.get('namespace') or request.form.get('namespace')
        
        if not namespace:
            return jsonify({
                "error": "BadRequest",
                "message": "Namespace name is required"
            }), 400
        
        user_token = get_user_token(session)
        
        try:
            k8sNamespaceCreate(session['user_role'], user_token, namespace)
            return jsonify({
                "message": f"Namespace '{namespace}' created successfully",
                "data": {
                    "namespace": namespace
                }
            }), 201
        except Exception as e:
            logger.error(f"Error creating namespace {namespace}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e)
            }), 500


@namespaces_api_bp.route('/<name>')
class NamespaceResource(MethodView):
    """
    Individual namespace endpoint.
    """
    
    @namespaces_api_bp.response(200, description="Successfully retrieved namespace details")
    @namespaces_api_bp.response(404, description="Namespace not found")
    @namespaces_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self, name):
        """
        Get namespace details
        
        Path Parameters:
            name (str): Name of the namespace
        
        Returns:
            dict: Namespace details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "namespace-get",
            attributes={
                "http.route": "/api/v1/namespaces/{name}",
                "http.method": "GET",
                "namespace.name": name,
            }
        ) if tracer else nullcontext():
            namespaces = k8sNamespacesGet(session['user_role'], user_token)
            
            # Find the namespace by name
            namespace_data = None
            for ns in namespaces:
                if ns.get('name') == name:
                    namespace_data = ns
                    break
            
            if not namespace_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Namespace '{name}' not found"
                }), 404
            
            return jsonify({
                "data": namespace_data,
                "metadata": {
                    "name": name
                }
            })
    
    @namespaces_api_bp.response(200, description="Successfully deleted namespace")
    @namespaces_api_bp.response(404, description="Namespace not found")
    @namespaces_api_bp.doc(tags=['Cluster'])
    @login_required
    def delete(self, name):
        """
        Delete namespace
        
        Path Parameters:
            name (str): Name of the namespace to delete
        
        Returns:
            dict: Deletion confirmation
        """
        try:
            k8sNamespaceDelete(session['user_role'], name)
            return jsonify({
                "message": f"Namespace '{name}' deleted successfully",
                "data": {
                    "namespace": name
                }
            }), 200
        except Exception as e:
            logger.error(f"Error deleting namespace {name}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e)
            }), 500

