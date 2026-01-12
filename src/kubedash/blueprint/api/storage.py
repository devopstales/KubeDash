"""
Storage API endpoints for managing Kubernetes storage resources.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.metrics import k8sPVCMetric
from lib.k8s.storage import (
    k8sConfigmapListGet,
    k8sPersistentVolumeClaimListGet,
    k8sPersistentVolumeListGet,
    k8sPersistentVolumeSnapshotListGet,
    k8sSnapshotClassListGet,
    k8sStorageClassListGet
)
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

storage_api_bp = Blueprint(
    "storage_api",
    "storage_api",
    url_prefix="/storage",
    description="Storage API endpoints - Manage PVCs, PVs, and storage classes"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Persistent Volume Claims
##############################################################

@storage_api_bp.route('/pvcs')
class PVCsListResource(MethodView):
    """
    Persistent Volume Claims list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved PVCs list")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        List persistent volume claims
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of PVCs with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        pvcs = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": pvcs,
            "metadata": {
                "namespace": namespace,
                "count": len(pvcs)
            }
        })


@storage_api_bp.route('/pvcs/<name>')
class PVCResource(MethodView):
    """
    Individual persistent volume claim endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved PVC details")
    @storage_api_bp.response(404, description="PVC not found")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self, name):
        """
        Get PVC details
        
        Path Parameters:
            name (str): Name of the PVC
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: PVC details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pvc-get",
            attributes={
                "http.route": "/api/v1/storage/pvcs/{name}",
                "http.method": "GET",
                "pvc.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            pvcs = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, namespace)
            pvc_data = None
            for pvc in pvcs:
                if pvc["name"] == name:
                    pvc_data = pvc
                    break
            
            if not pvc_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"PVC '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": pvc_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


@storage_api_bp.route('/pvcs/metrics')
class PVCMetricsResource(MethodView):
    """
    PVC metrics endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved PVC metrics")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        Get PVC metrics
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: PVC metrics
        """
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pvc-metrics",
            attributes={
                "http.route": "/api/v1/storage/pvcs/metrics",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            metrics = k8sPVCMetric(namespace)
            
            return jsonify({
                "data": metrics,
                "metadata": {
                    "namespace": namespace
                }
            })


##############################################################
## Persistent Volumes
##############################################################

@storage_api_bp.route('/pvs')
class PVsListResource(MethodView):
    """
    Persistent Volumes list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved PVs list")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        List persistent volumes
        
        Returns:
            dict: List of PVs with metadata
        """
        user_token = get_user_token(session)
        
        pvs = k8sPersistentVolumeListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": pvs,
            "metadata": {
                "count": len(pvs)
            }
        })


@storage_api_bp.route('/pvs/<name>')
class PVResource(MethodView):
    """
    Individual persistent volume endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved PV details")
    @storage_api_bp.response(404, description="PV not found")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self, name):
        """
        Get PV details
        
        Path Parameters:
            name (str): Name of the PV
        
        Returns:
            dict: PV details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "pv-get",
            attributes={
                "http.route": "/api/v1/storage/pvs/{name}",
                "http.method": "GET",
                "pv.name": name,
            }
        ) if tracer else nullcontext():
            pvs = k8sPersistentVolumeListGet(session['user_role'], user_token, session.get('ns_select', 'default'))
            pv_data = None
            for pv in pvs:
                if pv["name"] == name:
                    pv_data = pv
                    break
            
            if not pv_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"PV '{name}' not found"
                }), 404
            
            return jsonify({
                "data": pv_data,
                "metadata": {
                    "name": name
                }
            })


##############################################################
## Storage Classes
##############################################################

@storage_api_bp.route('/storage-classes')
class StorageClassesListResource(MethodView):
    """
    Storage classes list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved storage classes list")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        List storage classes
        
        Returns:
            dict: List of storage classes with metadata
        """
        user_token = get_user_token(session)
        
        storage_classes = k8sStorageClassListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": storage_classes,
            "metadata": {
                "count": len(storage_classes)
            }
        })


@storage_api_bp.route('/storage-classes/<name>')
class StorageClassResource(MethodView):
    """
    Individual storage class endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved storage class details")
    @storage_api_bp.response(404, description="Storage class not found")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self, name):
        """
        Get storage class details
        
        Path Parameters:
            name (str): Name of the storage class
        
        Returns:
            dict: Storage class details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "storage-class-get",
            attributes={
                "http.route": "/api/v1/storage/storage-classes/{name}",
                "http.method": "GET",
                "storage-class.name": name,
            }
        ) if tracer else nullcontext():
            storage_classes = k8sStorageClassListGet(session['user_role'], user_token)
            sc_data = None
            for sc in storage_classes:
                if sc["name"] == name:
                    sc_data = sc
                    break
            
            if not sc_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"StorageClass '{name}' not found"
                }), 404
            
            return jsonify({
                "data": sc_data,
                "metadata": {
                    "name": name
                }
            })


##############################################################
## Snapshot Classes
##############################################################

@storage_api_bp.route('/snapshot-classes')
class SnapshotClassesListResource(MethodView):
    """
    Snapshot classes list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved snapshot classes list")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        List snapshot classes
        
        Returns:
            dict: List of snapshot classes with metadata
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "snapshot-classes-list",
            attributes={
                "http.route": "/api/v1/storage/snapshot-classes",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            snapshot_classes = k8sSnapshotClassListGet(session['user_role'], user_token)
            
            return jsonify({
                "data": snapshot_classes,
                "metadata": {
                    "count": len(snapshot_classes)
                }
            })


@storage_api_bp.route('/snapshot-classes/<name>')
class SnapshotClassResource(MethodView):
    """
    Individual snapshot class endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved snapshot class details")
    @storage_api_bp.response(404, description="Snapshot class not found")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self, name):
        """
        Get snapshot class details
        
        Path Parameters:
            name (str): Name of the snapshot class
        
        Returns:
            dict: Snapshot class details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "snapshot-class-get",
            attributes={
                "http.route": "/api/v1/storage/snapshot-classes/{name}",
                "http.method": "GET",
                "snapshot-class.name": name,
            }
        ) if tracer else nullcontext():
            snapshot_classes = k8sSnapshotClassListGet(session['user_role'], user_token)
            sc_data = None
            for sc in snapshot_classes:
                if sc["name"] == name:
                    sc_data = sc
                    break
            
            if not sc_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"SnapshotClass '{name}' not found"
                }), 404
            
            return jsonify({
                "data": sc_data,
                "metadata": {
                    "name": name
                }
            })


##############################################################
## Volume Snapshots
##############################################################

@storage_api_bp.route('/volume-snapshots')
class VolumeSnapshotsListResource(MethodView):
    """
    Volume snapshots list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved volume snapshots list")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self):
        """
        List volume snapshots
        
        Returns:
            dict: List of volume snapshots with metadata
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "volume-snapshots-list",
            attributes={
                "http.route": "/api/v1/storage/volume-snapshots",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            snapshots = k8sPersistentVolumeSnapshotListGet(session['user_role'], user_token)
            
            return jsonify({
                "data": snapshots,
                "metadata": {
                    "count": len(snapshots)
                }
            })


##############################################################
## ConfigMaps
##############################################################

@storage_api_bp.route('/configmaps')
class ConfigMapsListResource(MethodView):
    """
    ConfigMaps list endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved configmaps list")
    @storage_api_bp.doc(tags=['Storage'])
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
        
        with tracer.start_as_current_span(
            "configmaps-list",
            attributes={
                "http.route": "/api/v1/storage/configmaps",
                "http.method": "GET",
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            configmaps = k8sConfigmapListGet(session['user_role'], user_token, namespace)
            
            return jsonify({
                "data": configmaps,
                "metadata": {
                    "namespace": namespace,
                    "count": len(configmaps)
                }
            })


@storage_api_bp.route('/configmaps/<name>')
class ConfigMapResource(MethodView):
    """
    Individual configmap endpoint.
    """
    
    @storage_api_bp.response(200, description="Successfully retrieved configmap details")
    @storage_api_bp.response(404, description="ConfigMap not found")
    @storage_api_bp.doc(tags=['Storage'])
    @login_required
    def get(self, name):
        """
        Get configmap details
        
        Path Parameters:
            name (str): Name of the configmap
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: ConfigMap details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "configmap-get",
            attributes={
                "http.route": "/api/v1/storage/configmaps/{name}",
                "http.method": "GET",
                "configmap.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            configmaps = k8sConfigmapListGet(session['user_role'], user_token, namespace)
            configmap_data = None
            for configmap in configmaps:
                if configmap["name"] == name:
                    configmap_data = configmap
                    break
            
            if not configmap_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"ConfigMap '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": configmap_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })

