"""
Nodes API endpoints for managing Kubernetes nodes.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.node import k8sNodesListGet, k8sNodeGet
from lib.k8s.metrics import k8sGetNodeMetric
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

nodes_api_bp = Blueprint(
    "nodes_api",
    "nodes_api",
    url_prefix="/nodes",
    description="Nodes API endpoints - Manage Kubernetes cluster nodes"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Nodes List
##############################################################

@nodes_api_bp.route('')
class NodesListResource(MethodView):
    """
    Nodes list endpoint.
    """
    
    @nodes_api_bp.response(200, description="Successfully retrieved nodes list")
    @nodes_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        List nodes
        
        Returns:
            dict: List of nodes with metadata
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "nodes-list",
            attributes={
                "http.route": "/api/v1/nodes",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            nodes = k8sNodesListGet(session['user_role'], user_token)
            
            return jsonify({
                "data": nodes,
                "metadata": {
                    "count": len(nodes)
                }
            })


##############################################################
## Node Details
##############################################################

@nodes_api_bp.route('/<name>')
class NodeResource(MethodView):
    """
    Individual node endpoint.
    """
    
    @nodes_api_bp.response(200, description="Successfully retrieved node details")
    @nodes_api_bp.response(404, description="Node not found")
    @nodes_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self, name):
        """
        Get node details
        
        Path Parameters:
            name (str): Name of the node
        
        Returns:
            dict: Node details
        """
        user_token = get_user_token(session)
        
        node_data = k8sNodeGet(session['user_role'], user_token, name)
        
        if not node_data:
            return jsonify({
                "error": "NotFound",
                "message": f"Node '{name}' not found"
            }), 404
        
        return jsonify({
            "data": node_data,
            "metadata": {
                "name": name
            }
        })


##############################################################
## Node Metrics
##############################################################

@nodes_api_bp.route('/<name>/metrics')
class NodeMetricsResource(MethodView):
    """
    Node metrics endpoint.
    """
    
    @nodes_api_bp.response(200, description="Successfully retrieved node metrics")
    @nodes_api_bp.response(404, description="Node not found")
    @nodes_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self, name):
        """
        Get node metrics
        
        Path Parameters:
            name (str): Name of the node
        
        Returns:
            dict: Node metrics including CPU, memory, and pod count
        """
        with tracer.start_as_current_span(
            "node-metrics",
            attributes={
                "http.route": "/api/v1/nodes/{name}/metrics",
                "http.method": "GET",
                "node.name": name,
            }
        ) if tracer else nullcontext():
            node_metrics = k8sGetNodeMetric(name)
            
            return jsonify({
                "data": node_metrics,
                "metadata": {
                    "name": name
                }
            })

