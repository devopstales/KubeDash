"""
Network API endpoints for managing Kubernetes network resources.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.network import (
    k8sServiceListGet, k8sIngressListGet, k8sIngressClassListGet,
    k8sPodSelectorListGet
)
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

network_api_bp = Blueprint(
    "network_api",
    "network_api",
    url_prefix="/network",
    description="Network API endpoints - Manage services, ingress, and ingress classes"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Services
##############################################################

@network_api_bp.route('/services')
class ServicesListResource(MethodView):
    """
    Services list endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved services list")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self):
        """
        List services
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of services with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        services = k8sServiceListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": services,
            "metadata": {
                "namespace": namespace,
                "count": len(services)
            }
        })


@network_api_bp.route('/services/<name>')
class ServiceResource(MethodView):
    """
    Individual service endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved service details")
    @network_api_bp.response(404, description="Service not found")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self, name):
        """
        Get service details
        
        Path Parameters:
            name (str): Name of the service
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Service details including pods
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "service-get",
            attributes={
                "http.route": "/api/v1/network/services/{name}",
                "http.method": "GET",
                "service.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            services = k8sServiceListGet(session['user_role'], user_token, namespace)
            service_data = None
            for service in services:
                if service["name"] == name:
                    service_data = service
                    break
            
            if not service_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Service '{name}' not found in namespace '{namespace}'"
                }), 404
            
            # Get pods if selector exists
            pod_list = None
            if service_data.get("selector"):
                pod_list = k8sPodSelectorListGet(session['user_role'], user_token, namespace, service_data["selector"])
            
            return jsonify({
                "data": {
                    "service": service_data,
                    "pods": pod_list or []
                },
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Ingress
##############################################################

@network_api_bp.route('/ingress')
class IngressListResource(MethodView):
    """
    Ingress list endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved ingress list")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self):
        """
        List ingress resources
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of ingress resources with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        ingresses = k8sIngressListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": ingresses,
            "metadata": {
                "namespace": namespace,
                "count": len(ingresses)
            }
        })


@network_api_bp.route('/ingress/<name>')
class IngressResource(MethodView):
    """
    Individual ingress endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved ingress details")
    @network_api_bp.response(404, description="Ingress not found")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self, name):
        """
        Get ingress details
        
        Path Parameters:
            name (str): Name of the ingress
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Ingress details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "ingress-get",
            attributes={
                "http.route": "/api/v1/network/ingress/{name}",
                "http.method": "GET",
                "ingress.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            ingresses = k8sIngressListGet(session['user_role'], user_token, namespace)
            ingress_data = None
            for ingress in ingresses:
                if ingress["name"] == name:
                    ingress_data = ingress
                    break
            
            if not ingress_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Ingress '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": ingress_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


@network_api_bp.route('/ingress-classes')
class IngressClassesListResource(MethodView):
    """
    Ingress classes list endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved ingress classes list")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self):
        """
        List ingress classes
        
        Returns:
            dict: List of ingress classes with metadata
        """
        user_token = get_user_token(session)
        
        ingress_classes = k8sIngressClassListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": ingress_classes,
            "metadata": {
                "count": len(ingress_classes)
            }
        })


@network_api_bp.route('/ingress-classes/<name>')
class IngressClassResource(MethodView):
    """
    Individual ingress class endpoint.
    """
    
    @network_api_bp.response(200, description="Successfully retrieved ingress class details")
    @network_api_bp.response(404, description="Ingress class not found")
    @network_api_bp.doc(tags=['Network'])
    @login_required
    def get(self, name):
        """
        Get ingress class details
        
        Path Parameters:
            name (str): Name of the ingress class
        
        Returns:
            dict: Ingress class details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "ingress-class-get",
            attributes={
                "http.route": "/api/v1/network/ingress-classes/{name}",
                "http.method": "GET",
                "ingress-class.name": name,
            }
        ) if tracer else nullcontext():
            ingress_classes = k8sIngressClassListGet(session['user_role'], user_token)
            ingress_class_data = None
            for ic in ingress_classes:
                if ic["name"] == name:
                    ingress_class_data = ic
                    break
            
            if not ingress_class_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"IngressClass '{name}' not found"
                }), 404
            
            return jsonify({
                "data": ingress_class_data,
                "metadata": {
                    "name": name
                }
            })

