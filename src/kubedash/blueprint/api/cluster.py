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
from lib.replica_mode import get_replica_mode, get_pod_identity
from lib.leader_election import get_leader_elector
from lib.leader_tasks import get_task_registry

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


##############################################################
## Replica Mode and Leader Election
##############################################################

@cluster_api_bp.route('/mode')
class ClusterModeResource(MethodView):
    """
    Cluster mode endpoint.
    
    Returns the current replica mode configuration and feature flags.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved cluster mode")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get cluster mode
        
        Returns the current replica mode (single/cluster) and associated feature flags.
        
        Returns:
            dict: Cluster mode information with feature flags
        """
        from flask import current_app
        
        with tracer.start_as_current_span(
            "cluster-mode",
            attributes={
                "http.route": "/api/v1/cluster/mode",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            mode = get_replica_mode()
            replica_count = current_app.config.get('REPLICA_COUNT', 1)
            
            # Feature flags based on mode
            feature_flags = {
                'leader_election': mode == 'cluster',
                'distributed_sessions': mode == 'cluster',
                'coordinated_tasks': mode == 'cluster',
                'metrics_cleanup': mode == 'cluster'
            }
            
            return jsonify({
                "data": {
                    "mode": mode,
                    "replica_count": replica_count,
                    "feature_flags": feature_flags
                },
                "metadata": {
                    "source": "configuration"
                }
            })


@cluster_api_bp.route('/leader/status')
class LeaderStatusResource(MethodView):
    """
    Leader election status endpoint.
    
    Returns the current leader election status and lease information.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved leader status")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get leader election status
        
        Returns detailed information about the current leader election state,
        including identity, lease duration, renewal times, and transition history.
        
        Returns:
            dict: Leader election status with lease information
        """
        with tracer.start_as_current_span(
            "leader-status",
            attributes={
                "http.route": "/api/v1/cluster/leader/status",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            elector = get_leader_elector()
            if not elector:
                return jsonify({
                    "data": {
                        "enabled": False,
                        "message": "Leader election not enabled (single replica mode)"
                    }
                })
            
            status = elector.get_status()
            
            return jsonify({
                "data": status,
                "metadata": {
                    "source": "leader_election"
                }
            })


@cluster_api_bp.route('/replicas/self')
class ReplicaSelfResource(MethodView):
    """
    Local replica status endpoint.
    
    Returns status information for the current replica instance.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved replica status")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get local replica status
        
        Returns status information for this replica instance, including
        identity, leadership status, and uptime.
        
        Returns:
            dict: Local replica status information
        """
        from datetime import datetime
        import time
        
        with tracer.start_as_current_span(
            "replica-self",
            attributes={
                "http.route": "/api/v1/cluster/replicas/self",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            pod_identity = get_pod_identity()
            elector = get_leader_elector()
            
            # Calculate uptime (simplified - would need to track actual start time)
            uptime_seconds = time.time() - time.time()  # Placeholder
            
            status = {
                "identity": pod_identity,
                "is_leader": elector.is_leader() if elector else True,  # Single mode = always leader
                "uptime_seconds": uptime_seconds,
                "mode": get_replica_mode()
            }
            
            return jsonify({
                "data": status,
                "metadata": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "local_instance"
                }
            })


@cluster_api_bp.route('/tasks')
class LeaderTasksResource(MethodView):
    """
    Leader tasks endpoint.
    
    Returns information about registered leader-only tasks and their execution status.
    """
    
    @cluster_api_bp.response(200, description="Successfully retrieved tasks list")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def get(self):
        """
        Get leader tasks list
        
        Returns a list of all registered leader-only tasks with their
        execution status, last run time, and scope information.
        
        Returns:
            dict: List of leader tasks with execution information
        """
        with tracer.start_as_current_span(
            "leader-tasks",
            attributes={
                "http.route": "/api/v1/cluster/tasks",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            registry = get_task_registry()
            if not registry:
                return jsonify({
                    "data": [],
                    "metadata": {
                        "message": "Leader tasks not enabled (single replica mode)",
                        "count": 0
                    }
                })
            
            tasks = registry.list_tasks()
            
            return jsonify({
                "data": tasks,
                "metadata": {
                    "count": len(tasks),
                    "source": "leader_task_registry"
                }
            })


@cluster_api_bp.route('/tasks/<task_name>/trigger', methods=['POST'])
class LeaderTaskTriggerResource(MethodView):
    """
    Manual leader task trigger endpoint.
    
    Allows manual execution of a registered leader-only task.
    Only works if this instance is the current leader.
    """
    
    @cluster_api_bp.response(200, description="Task triggered successfully")
    @cluster_api_bp.response(403, description="Not the current leader")
    @cluster_api_bp.response(404, description="Task not found")
    @cluster_api_bp.response(401, description="Unauthorized - User not authenticated")
    @cluster_api_bp.doc(tags=['Cluster'])
    @login_required
    def post(self, task_name):
        """
        Trigger leader task manually
        
        Manually executes a registered leader-only task. This endpoint will
        only succeed if the current instance is the elected leader.
        
        Path Parameters:
            task_name (str): Name of the task to trigger
        
        Returns:
            dict: Task execution result
        """
        from flask import current_app
        
        with tracer.start_as_current_span(
            "trigger-leader-task",
            attributes={
                "http.route": "/api/v1/cluster/tasks/{task_name}/trigger",
                "http.method": "POST",
                "task.name": task_name,
            }
        ) if tracer else nullcontext():
            registry = get_task_registry()
            if not registry:
                return jsonify({
                    "error": "Leader tasks not enabled (single replica mode)"
                }), 403
            
            elector = get_leader_elector()
            if elector and not elector.is_leader():
                return jsonify({
                    "error": "Not the current leader",
                    "leader": elector.get_current_leader()
                }), 403
            
            # Execute the task
            try:
                result = registry.execute_task(task_name, current_app, None)  # db parameter not needed for manual trigger
                return jsonify({
                    "data": {
                        "task_name": task_name,
                        "executed": True,
                        "result": result
                    },
                    "metadata": {
                        "timestamp": "now",
                        "source": "manual_trigger"
                    }
                })
            except ValueError as e:
                return jsonify({
                    "error": str(e)
                }), 404

