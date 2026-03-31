"""
Workloads API endpoints for managing Kubernetes workloads.
"""

from contextlib import nullcontext
from flask import g, jsonify, request, session
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint
from kubernetes.client.rest import ApiException

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.k8s.workload import (
    k8sPodListGet, k8sPodGet, k8sPodDelete, k8sPodGetContainers, k8sPodGetEvents,
    k8sDeploymentsGet, k8sDeploymentsPatchReplica,
    k8sStatefulSetsGet, k8sStatefulSetPatchReplica,
    k8sDaemonSetsGet, k8sDaemonsetPatch,
    k8sReplicaSetsGet
)
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

workloads_api_bp = Blueprint(
    "workloads_api",
    "workloads_api",
    url_prefix="/workloads",
    description="Workloads API endpoints - Manage pods, deployments, statefulsets, daemonsets, and replicasets"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Pods
##############################################################

@workloads_api_bp.route('/pods')
class PodsListResource(MethodView):
    """
    Pods list endpoint.
    
    Returns a list of pods in the specified namespace or all namespaces.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved pod list")
    @workloads_api_bp.response(401, description="Unauthorized - User not authenticated")
    @workloads_api_bp.response(403, description="Forbidden - User lacks permission to list pods")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self):
        """
        List pods
        
        Retrieves a list of pods from the specified namespace or all namespaces.
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
            all_namespaces (bool): If true, list pods from all namespaces (default: false)
        
        Returns:
            dict: List of pods with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        all_namespaces = request.args.get('all_namespaces', 'false').lower() == 'true'
        
        if all_namespaces:
            namespace = 'all'
        
        with tracer.start_as_current_span(
            "pods-list",
            attributes={
                "http.route": "/api/v1/workloads/pods",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            pod_list = k8sPodListGet(session['user_role'], user_token, namespace)
            
            return jsonify({
                "data": pod_list,
                "metadata": {
                    "namespace": namespace,
                    "count": len(pod_list)
                }
            })


@workloads_api_bp.route('/pods/<name>')
class PodResource(MethodView):
    """
    Individual pod endpoint.
    
    Provides GET and DELETE operations for a specific pod.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved pod details")
    @workloads_api_bp.response(404, description="Pod not found")
    @workloads_api_bp.response(401, description="Unauthorized - User not authenticated")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get pod details
        
        Retrieves detailed information about a specific pod.
        
        Path Parameters:
            name (str): Name of the pod
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Pod details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pod-get",
            attributes={
                "http.route": "/api/v1/workloads/pods/{name}",
                "http.method": "GET",
                "pod.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            pod_data = k8sPodGet(session['user_role'], user_token, namespace, name)
            
            if not pod_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Pod '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": pod_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })
    
    @workloads_api_bp.response(200, description="Successfully deleted pod")
    @workloads_api_bp.response(404, description="Pod not found")
    @workloads_api_bp.response(401, description="Unauthorized - User not authenticated")
    @workloads_api_bp.response(403, description="Forbidden - User lacks permission to delete pod")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def delete(self, name):
        """
        Delete pod
        
        Deletes a specific pod from the cluster.
        
        Path Parameters:
            name (str): Name of the pod to delete
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Deletion confirmation
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pod-delete",
            attributes={
                "http.route": "/api/v1/workloads/pods/{name}",
                "http.method": "DELETE",
                "pod.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            try:
                k8sPodDelete(session['user_role'], user_token, namespace, name)
                log_audit_event(
                    user_id=actor,
                    action="delete_k8s_pod",
                    resource=f"pod:{namespace}/{name}",
                    result="success",
                    trace_id=getattr(g, "correlation_id", None),
                )
                return jsonify({
                    "message": f"Pod '{name}' deleted successfully",
                    "data": {
                        "name": name,
                        "namespace": namespace
                    }
                }), 200
            except ApiException as e:
                log_audit_event(
                    user_id=actor,
                    action="delete_k8s_pod",
                    resource=f"pod:{namespace}/{name}",
                    result="failure",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"error": str(e)},
                )
                logger.error(f"Error deleting pod {name}: {str(e)}")
                return jsonify({
                    "error": "ApiException",
                    "message": str(e)
                }), e.status if hasattr(e, 'status') else 500
            except Exception as e:
                log_audit_event(
                    user_id=actor,
                    action="delete_k8s_pod",
                    resource=f"pod:{namespace}/{name}",
                    result="failure",
                    trace_id=getattr(g, "correlation_id", None),
                    details={"error": str(e)},
                )
                logger.error(f"Error deleting pod {name}: {str(e)}")
                return jsonify({
                    "error": "InternalError",
                    "message": str(e)
                }), 500


##############################################################
## Deployments
##############################################################

@workloads_api_bp.route('/deployments')
class DeploymentsListResource(MethodView):
    """
    Deployments list endpoint.
    
    Returns a list of deployments in the specified namespace.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved deployments list")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self):
        """
        List deployments
        
        Retrieves a list of deployments from the specified namespace.
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of deployments with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "deployments-list",
            attributes={
                "http.route": "/api/v1/workloads/deployments",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            deployments = k8sDeploymentsGet(session['user_role'], user_token, namespace)
            
            return jsonify({
                "data": deployments,
                "metadata": {
                    "namespace": namespace,
                    "count": len(deployments)
                }
            })


@workloads_api_bp.route('/deployments/<name>')
class DeploymentResource(MethodView):
    """
    Individual deployment endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved deployment details")
    @workloads_api_bp.response(404, description="Deployment not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get deployment details
        
        Path Parameters:
            name (str): Name of the deployment
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Deployment details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "deployment-get",
            attributes={
                "http.route": "/api/v1/workloads/deployments/{name}",
                "http.method": "GET",
                "deployment.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            deployments = k8sDeploymentsGet(session['user_role'], user_token, namespace)
            deployment_data = None
            for deployment in deployments:
                if deployment["name"] == name:
                    deployment_data = deployment
                    break
            
            if not deployment_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"Deployment '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": deployment_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })
    
    @workloads_api_bp.response(200, description="Successfully updated deployment")
    @workloads_api_bp.response(400, description="Bad request - Invalid input data")
    @workloads_api_bp.response(404, description="Deployment not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def patch(self, name):
        """
        Scale deployment
        
        Path Parameters:
            name (str): Name of the deployment
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Request Body:
            dict: Scale data:
                {
                    "replicas": int
                }
        
        Returns:
            dict: Updated deployment information
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        data = request.get_json() or {}
        replicas = data.get('replicas')
        
        if replicas is None:
            return jsonify({
                "error": "BadRequest",
                "message": "replicas is required"
            }), 400
        
        try:
            scale_status = k8sDeploymentsPatchReplica(session['user_role'], user_token, namespace, name, str(replicas))
            return jsonify({
                "message": f"Deployment '{name}' scaled to {replicas} replicas",
                "data": {
                    "name": name,
                    "namespace": namespace,
                    "replicas": replicas
                }
            })
        except Exception as e:
            logger.error(f"Error scaling deployment {name}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e)
            }), 500


##############################################################
## StatefulSets
##############################################################

@workloads_api_bp.route('/statefulsets')
class StatefulSetsListResource(MethodView):
    """
    StatefulSets list endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved statefulsets list")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self):
        """
        List statefulsets
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of statefulsets with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        statefulsets = k8sStatefulSetsGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": statefulsets,
            "metadata": {
                "namespace": namespace,
                "count": len(statefulsets)
            }
        })


@workloads_api_bp.route('/statefulsets/<name>')
class StatefulSetResource(MethodView):
    """
    Individual statefulset endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved statefulset details")
    @workloads_api_bp.response(404, description="StatefulSet not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get statefulset details
        
        Path Parameters:
            name (str): Name of the statefulset
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: StatefulSet details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "statefulset-get",
            attributes={
                "http.route": "/api/v1/workloads/statefulsets/{name}",
                "http.method": "GET",
                "statefulset.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            statefulsets = k8sStatefulSetsGet(session['user_role'], user_token, namespace)
            statefulset_data = None
            for statefulset in statefulsets:
                if statefulset["name"] == name:
                    statefulset_data = statefulset
                    break
            
            if not statefulset_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"StatefulSet '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": statefulset_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })
    
    @workloads_api_bp.response(200, description="Successfully updated statefulset")
    @workloads_api_bp.response(400, description="Bad request - Invalid input data")
    @workloads_api_bp.response(404, description="StatefulSet not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def patch(self, name):
        """
        Scale statefulset
        
        Path Parameters:
            name (str): Name of the statefulset
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Request Body:
            dict: Scale data:
                {
                    "replicas": int
                }
        
        Returns:
            dict: Updated statefulset information
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        data = request.get_json() or {}
        replicas = data.get('replicas')
        
        if replicas is None:
            return jsonify({
                "error": "BadRequest",
                "message": "replicas is required"
            }), 400
        
        try:
            scale_status = k8sStatefulSetPatchReplica(session['user_role'], user_token, namespace, name, str(replicas))
            return jsonify({
                "message": f"StatefulSet '{name}' scaled to {replicas} replicas",
                "data": {
                    "name": name,
                    "namespace": namespace,
                    "replicas": replicas
                }
            })
        except Exception as e:
            logger.error(f"Error scaling statefulset {name}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e)
            }), 500


##############################################################
## DaemonSets
##############################################################

@workloads_api_bp.route('/daemonsets')
class DaemonSetsListResource(MethodView):
    """
    DaemonSets list endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved daemonsets list")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self):
        """
        List daemonsets
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of daemonsets with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        daemonsets = k8sDaemonSetsGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": daemonsets,
            "metadata": {
                "namespace": namespace,
                "count": len(daemonsets)
            }
        })


@workloads_api_bp.route('/daemonsets/<name>')
class DaemonSetResource(MethodView):
    """
    Individual daemonset endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved daemonset details")
    @workloads_api_bp.response(404, description="DaemonSet not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get daemonset details
        
        Path Parameters:
            name (str): Name of the daemonset
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: DaemonSet details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "daemonset-get",
            attributes={
                "http.route": "/api/v1/workloads/daemonsets/{name}",
                "http.method": "GET",
                "daemonset.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            daemonsets = k8sDaemonSetsGet(session['user_role'], user_token, namespace)
            daemonset_data = None
            for daemonset in daemonsets:
                if daemonset["name"] == name:
                    daemonset_data = daemonset
                    break
            
            if not daemonset_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"DaemonSet '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": daemonset_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })
    
    @workloads_api_bp.response(200, description="Successfully updated daemonset")
    @workloads_api_bp.response(400, description="Bad request - Invalid input data")
    @workloads_api_bp.response(404, description="DaemonSet not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def patch(self, name):
        """
        Enable/disable daemonset
        
        Path Parameters:
            name (str): Name of the daemonset
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Request Body:
            dict: Enable/disable data:
                {
                    "enabled": bool (true to enable, false to disable)
                }
        
        Returns:
            dict: Updated daemonset information
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        data = request.get_json() or {}
        enabled = data.get('enabled', True)
        
        try:
            if enabled:
                # Enable: remove nodeSelector
                body = [{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]
            else:
                # Disable: add nodeSelector
                body = {"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}
            
            scale_status = k8sDaemonsetPatch(session['user_role'], user_token, namespace, name, body)
            return jsonify({
                "message": f"DaemonSet '{name}' {'enabled' if enabled else 'disabled'}",
                "data": {
                    "name": name,
                    "namespace": namespace,
                    "enabled": enabled
                }
            })
        except Exception as e:
            logger.error(f"Error updating daemonset {name}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e)
            }), 500


##############################################################
## Pod Containers
##############################################################

@workloads_api_bp.route('/pods/<name>/containers')
class PodContainersResource(MethodView):
    """
    Pod containers endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved pod containers")
    @workloads_api_bp.response(404, description="Pod not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get pod containers
        
        Retrieves list of containers and init containers for a pod.
        
        Path Parameters:
            name (str): Name of the pod
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Pod containers information
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pod-containers-get",
            attributes={
                "http.route": "/api/v1/workloads/pods/{name}/containers",
                "http.method": "GET",
                "pod.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            pod_containers, pod_init_containers = k8sPodGetContainers(session['user_role'], user_token, namespace, name)
            
            return jsonify({
                "data": {
                    "containers": pod_containers or [],
                    "init_containers": pod_init_containers or []
                },
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


@workloads_api_bp.route('/pods/<name>/events')
class PodEventsResource(MethodView):
    """
    Pod events endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved pod events")
    @workloads_api_bp.response(404, description="Pod not found")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self, name):
        """
        Get pod events
        
        Retrieves Kubernetes events related to a specific pod.
        
        Path Parameters:
            name (str): Name of the pod
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
            limit (int): Maximum number of events to return (default: 50)
        
        Returns:
            dict: Pod events information
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        limit = request.args.get('limit', 50, type=int)
        
        with tracer.start_as_current_span(
            "pod-events-get",
            attributes={
                "http.route": "/api/v1/workloads/pods/{name}/events",
                "http.method": "GET",
                "pod.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            events, error = k8sPodGetEvents(session['user_role'], user_token, namespace, name, limit)
            
            if error:
                return jsonify({
                    "error": "InternalError",
                    "message": error,
                    "data": []
                }), 500
            
            return jsonify({
                "data": events,
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "count": len(events),
                    "limit": limit
                }
            })


##############################################################
## ReplicaSets
##############################################################

@workloads_api_bp.route('/replicasets')
class ReplicaSetsListResource(MethodView):
    """
    ReplicaSets list endpoint.
    """
    
    @workloads_api_bp.response(200, description="Successfully retrieved replicasets list")
    @workloads_api_bp.doc(tags=['Workloads'])
    @login_required
    def get(self):
        """
        List replicasets
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of replicasets with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        replicasets = k8sReplicaSetsGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": replicasets,
            "metadata": {
                "namespace": namespace,
                "count": len(replicasets)
            }
        })

