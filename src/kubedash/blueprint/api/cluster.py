"""
Cluster API endpoints for cluster-level metrics and events.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.metrics import k8sGetClusterMetric, k8sGetClusterEvents
from lib.k8s.other import k8sRuntimeClassListGet
from lib.k8s.server import k8sGetClusterStatus
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

cluster_api_bp = Blueprint(
    "cluster_api",
    "cluster_api",
    url_prefix="/cluster",
    description="Cluster API endpoints - Provides cluster-level metrics, events, and status information"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Cluster Metrics
##############################################################

@cluster_api_bp.route('/metrics')
class ClusterMetricsResource(MethodView):
    """
    Cluster resource metrics endpoint.
    
    Returns CPU, memory, and pod allocation metrics for the entire cluster.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved cluster metrics")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.response(503, description="Service unavailable - Kubernetes cluster not accessible")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get cluster resource metrics
        
        Retrieves aggregated resource metrics including:
        - CPU capacity, allocatable, requests, limits, and usage
        - Memory capacity, allocatable, requests, limits, and usage  
        - Pod count (current vs allocatable)
        
        Returns:
            dict: Cluster metrics with metadata
        """
        with tracer.start_as_current_span(
            "cluster-metrics",
            attributes={
                "http.route": "/api/v1/cluster/metrics",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            cluster_metrics = k8sGetClusterMetric()
            
            return jsonify({
                "data": cluster_metrics,
                "metadata": {
                    "source": "kubernetes"
                }
            })


@cluster_api_bp.route('/events')
class ClusterEventsResource(MethodView):
    """
    Cluster events endpoint.
    
    Returns recent cluster events with filtering and pagination support.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved cluster events")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get cluster events
        
        Retrieves recent cluster events with optional filtering.
        
        Query Parameters:
            limit (int): Maximum number of events to return (default: 100)
            namespace (str): Filter events by namespace (optional)
            kind (str): Filter events by involved object kind (optional)
        
        Returns:
            dict: List of cluster events with metadata
        """
        user_token = get_user_token(session)
        limit = request.args.get('limit', 100, type=int)
        namespace = request.args.get('namespace', None)
        kind = request.args.get('kind', None)
        
        with tracer.start_as_current_span(
            "cluster-events",
            attributes={
                "http.route": "/api/v1/cluster/events",
                "http.method": "GET",
                "events.limit": limit,
            }
        ) if tracer else nullcontext():
            cluster_events = k8sGetClusterEvents(
                session['user_role'],
                user_token,
                limit=limit
            )
            
            # Apply filters if provided
            if namespace:
                cluster_events = [e for e in cluster_events if e.get('namespace') == namespace]
            if kind:
                cluster_events = [e for e in cluster_events if e.get('involvedObjectKind') == kind]
            
            return jsonify({
                "data": cluster_events,
                "metadata": {
                    "count": len(cluster_events),
                    "limit": limit,
                    "namespace": namespace,
                    "kind": kind
                }
            })


@cluster_api_bp.route('/status')
class ClusterStatusResource(MethodView):
    """
    Cluster status endpoint.
    
    Returns the current connection status to the Kubernetes cluster.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved cluster status")
    @cluster_api_bp.response(503, description="Service unavailable - Cluster not accessible")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get cluster connection status
        
        Checks if the application can connect to the Kubernetes cluster.
        
        Returns:
            dict: Cluster status information
        """
        from datetime import datetime
        
        with tracer.start_as_current_span(
            "cluster-status",
            attributes={
                "http.route": "/api/v1/cluster/status",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            status = k8sGetClusterStatus()
            
            return jsonify({
                "data": {
                    "connected": status,
                    "message": "Cluster is accessible" if status else "Cannot connect to cluster",
                    "timestamp": datetime.utcnow().isoformat()
                }
            }), 200 if status else 503


@cluster_api_bp.route('/workload-map')
class WorkloadMapResource(MethodView):
    """
    Workload map endpoint.
    
    Returns pod relationship data for visualization.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved workload map data")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get workload map data
        
        Retrieves pod relationship data (nodes and edges) for visualization.
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Workload map data with nodes and edges
        """
        from lib.k8s.metrics import k8sGetPodMap
        from lib.k8s.namespace import k8sNamespaceListGet
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "workload-map",
            attributes={
                "http.route": "/api/v1/cluster/workload-map",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
            if not error:
                nodes, edges = k8sGetPodMap(session['user_role'], user_token, namespace)
            else:
                nodes = []
                edges = []
            
            return jsonify({
                "data": {
                    "nodes": nodes,
                    "edges": edges
                },
                "metadata": {
                    "namespace": namespace,
                    "nodes_count": len(nodes),
                    "edges_count": len(edges)
                }
            })


##############################################################
## Runtime Classes
##############################################################

@cluster_api_bp.route('/runtime-classes')
class RuntimeClassesListResource(MethodView):
    """
    Runtime Classes list endpoint.
    
    Returns a list of all RuntimeClasses in the cluster.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved runtime classes list")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        List runtime classes
        
        Retrieves a list of all RuntimeClasses available in the cluster.
        
        Returns:
            dict: List of runtime classes with metadata
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "runtime-classes-list",
            attributes={
                "http.route": "/api/v1/cluster/runtime-classes",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            runtime_classes = k8sRuntimeClassListGet(session['user_role'], user_token)
            
            return jsonify({
                "data": runtime_classes,
                "metadata": {
                    "count": len(runtime_classes)
                }
            })

