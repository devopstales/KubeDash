"""
Other Resources API endpoints for HPA, VPA, LimitRanges, Quotas, PDBs, and CRDs.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.k8s.other import (
    k8sHPAListGet, k8sVPAListGet, k8sLimitRangeListGet,
    k8sPodDisruptionBudgetListGet, k8sQuotaListGet, k8sPriorityClassList,
    k8sRuntimeClassListGet
)
from lib.k8s.crds import get_custom_resources, get_custom_resource_data
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

other_resources_api_bp = Blueprint(
    "other_resources_api",
    "other_resources_api",
    url_prefix="/other-resources",
    description="Other Resources API endpoints - Manage HPAs, VPAs, LimitRanges, ResourceQuotas, PodDisruptionBudgets, and Custom Resource Definitions"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Horizontal Pod Autoscalers
##############################################################

@other_resources_api_bp.route('/hpa')
class HPAListResource(MethodView):
    """
    Horizontal Pod Autoscaler list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved HPA list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List horizontal pod autoscalers
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of HPAs with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        hpas = k8sHPAListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": hpas,
            "metadata": {
                "namespace": namespace,
                "count": len(hpas)
            }
        })


@other_resources_api_bp.route('/hpa/<name>')
class HPAResource(MethodView):
    """
    Individual HPA endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved HPA details")
    @other_resources_api_bp.response(404, description="HPA not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get HPA details
        
        Path Parameters:
            name (str): Name of the HPA
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: HPA details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "hpa-get",
            attributes={
                "http.route": "/api/v1/other-resources/hpa/{name}",
                "http.method": "GET",
                "hpa.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            hpas = k8sHPAListGet(session['user_role'], user_token, namespace)
            hpa_data = None
            for hpa in hpas:
                if hpa["name"] == name:
                    hpa_data = hpa
                    break
            
            if not hpa_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"HPA '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": hpa_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Vertical Pod Autoscalers
##############################################################

@other_resources_api_bp.route('/vpa')
class VPAListResource(MethodView):
    """
    Vertical Pod Autoscaler list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved VPA list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List vertical pod autoscalers
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of VPAs with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        vpas = k8sVPAListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": vpas,
            "metadata": {
                "namespace": namespace,
                "count": len(vpas)
            }
        })


@other_resources_api_bp.route('/vpa/<name>')
class VPAResource(MethodView):
    """
    Individual VPA endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved VPA details")
    @other_resources_api_bp.response(404, description="VPA not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get VPA details
        
        Path Parameters:
            name (str): Name of the VPA
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: VPA details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "vpa-get",
            attributes={
                "http.route": "/api/v1/other-resources/vpa/{name}",
                "http.method": "GET",
                "vpa.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            vpas = k8sVPAListGet(session['user_role'], user_token, namespace)
            vpa_data = None
            for vpa in vpas:
                if vpa["name"] == name:
                    vpa_data = vpa
                    break
            
            if not vpa_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"VPA '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": vpa_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Limit Ranges
##############################################################

@other_resources_api_bp.route('/limit-ranges')
class LimitRangesListResource(MethodView):
    """
    Limit ranges list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved limit ranges list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List limit ranges
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of limit ranges with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        limit_ranges = k8sLimitRangeListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": limit_ranges,
            "metadata": {
                "namespace": namespace,
                "count": len(limit_ranges)
            }
        })


@other_resources_api_bp.route('/limit-ranges/<name>')
class LimitRangeResource(MethodView):
    """
    Individual limit range endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved limit range details")
    @other_resources_api_bp.response(404, description="Limit range not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get limit range details
        
        Path Parameters:
            name (str): Name of the limit range
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Limit range details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "limit-range-get",
            attributes={
                "http.route": "/api/v1/other-resources/limit-ranges/{name}",
                "http.method": "GET",
                "limit-range.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            limit_ranges = k8sLimitRangeListGet(session['user_role'], user_token, namespace)
            limit_range_data = None
            for lr in limit_ranges:
                if lr["name"] == name:
                    limit_range_data = lr
                    break
            
            if not limit_range_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"LimitRange '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": limit_range_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Resource Quotas
##############################################################

@other_resources_api_bp.route('/quotas')
class QuotasListResource(MethodView):
    """
    Resource quotas list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved quotas list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List resource quotas
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of quotas with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        quotas = k8sQuotaListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": quotas,
            "metadata": {
                "namespace": namespace,
                "count": len(quotas)
            }
        })


@other_resources_api_bp.route('/quotas/<name>')
class QuotaResource(MethodView):
    """
    Individual resource quota endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved quota details")
    @other_resources_api_bp.response(404, description="Quota not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get resource quota details
        
        Path Parameters:
            name (str): Name of the quota
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Quota details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "quota-get",
            attributes={
                "http.route": "/api/v1/other-resources/quotas/{name}",
                "http.method": "GET",
                "quota.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            quotas = k8sQuotaListGet(session['user_role'], user_token, namespace)
            quota_data = None
            for quota in quotas:
                if quota["name"] == name:
                    quota_data = quota
                    break
            
            if not quota_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"ResourceQuota '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": quota_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Pod Disruption Budgets
##############################################################

@other_resources_api_bp.route('/pdb')
class PDBListResource(MethodView):
    """
    Pod disruption budgets list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved PDB list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List pod disruption budgets
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of PDBs with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        pdbs = k8sPodDisruptionBudgetListGet(session['user_role'], user_token, namespace)
        
        return jsonify({
            "data": pdbs,
            "metadata": {
                "namespace": namespace,
                "count": len(pdbs)
            }
        })


@other_resources_api_bp.route('/pdb/<name>')
class PDBResource(MethodView):
    """
    Individual pod disruption budget endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved PDB details")
    @other_resources_api_bp.response(404, description="PDB not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get pod disruption budget details
        
        Path Parameters:
            name (str): Name of the PDB
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: PDB details
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "pdb-get",
            attributes={
                "http.route": "/api/v1/other-resources/pdb/{name}",
                "http.method": "GET",
                "pdb.name": name,
                "namespace": namespace,
            }
        ) if tracer else nullcontext():
            pdbs = k8sPodDisruptionBudgetListGet(session['user_role'], user_token, namespace)
            pdb_data = None
            for pdb in pdbs:
                if pdb["name"] == name:
                    pdb_data = pdb
                    break
            
            if not pdb_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"PodDisruptionBudget '{name}' not found in namespace '{namespace}'"
                }), 404
            
            return jsonify({
                "data": pdb_data,
                "metadata": {
                    "name": name,
                    "namespace": namespace
                }
            })


##############################################################
## Priority Classes
##############################################################

@other_resources_api_bp.route('/priority-classes')
class PriorityClassesListResource(MethodView):
    """
    Priority classes list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved priority classes list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List priority classes
        
        Returns:
            dict: List of priority classes with metadata
        """
        user_token = get_user_token(session)
        
        priority_classes = k8sPriorityClassList(session['user_role'], user_token)
        
        return jsonify({
            "data": priority_classes,
            "metadata": {
                "count": len(priority_classes)
            }
        })


@other_resources_api_bp.route('/priority-classes/<name>')
class PriorityClassResource(MethodView):
    """
    Individual priority class endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved priority class details")
    @other_resources_api_bp.response(404, description="Priority class not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get priority class details
        
        Path Parameters:
            name (str): Name of the priority class
        
        Returns:
            dict: Priority class details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "priority-class-get",
            attributes={
                "http.route": "/api/v1/other-resources/priority-classes/{name}",
                "http.method": "GET",
                "priority-class.name": name,
            }
        ) if tracer else nullcontext():
            priority_classes = k8sPriorityClassList(session['user_role'], user_token)
            priority_class_data = None
            for pc in priority_classes:
                if pc["name"] == name:
                    priority_class_data = pc
                    break
            
            if not priority_class_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"PriorityClass '{name}' not found"
                }), 404
            
            return jsonify({
                "data": priority_class_data,
                "metadata": {
                    "name": name
                }
            })


##############################################################
## Custom Resource Definitions
##############################################################

@other_resources_api_bp.route('/crds')
class CRDsListResource(MethodView):
    """
    Custom Resource Definitions list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved CRDs list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List custom resource definitions
        
        Returns all CRDs available in the cluster.
        
        Returns:
            dict: List of CRDs with metadata
        """
        user_token = get_user_token(session)
        
        crds = get_custom_resources(session['user_role'], user_token)
        
        return jsonify({
            "data": crds,
            "metadata": {
                "count": len(crds)
            }
        })


@other_resources_api_bp.route('/crds/<group>/<version>/<kind>')
class CRDDataResource(MethodView):
    """
    Custom Resource Definition data endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved CRD data")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, group, version, kind):
        """
        Get custom resource definition data
        
        Path Parameters:
            group (str): CRD API group
            version (str): CRD API version
            kind (str): CRD kind
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional)
            name (str): CRD plural resource name (optional, defaults to kind.lower() + 's')
        
        Returns:
            dict: CRD data
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', None)
        crd_name = request.args.get('name', None)
        
        # Use provided name or construct from kind (fallback)
        if not crd_name:
            crd_name = kind.lower() + 's'
        
        try:
            crd_data = get_custom_resource_data(
                session['user_role'], user_token, namespace,
                crd_name, group, version
            )
            
            # Check if crd_data is None (error case)
            if crd_data is None:
                return jsonify({
                    "data": [],
                    "error": "UnknownError",
                    "message": f"Failed to retrieve CRD data for {kind}",
                    "metadata": {
                        "group": group,
                        "version": version,
                        "kind": kind,
                        "namespace": namespace,
                        "plural": crd_name
                    }
                }), 500
            
            return jsonify({
                "data": crd_data,
                "metadata": {
                    "group": group,
                    "version": version,
                    "kind": kind,
                    "namespace": namespace,
                    "plural": crd_name,
                    "count": len(crd_data) if crd_data else 0
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving CRD data for {kind}: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "group": group,
                    "version": version,
                    "kind": kind,
                    "namespace": namespace,
                    "plural": crd_name
                }
            }), 500


##############################################################
## Runtime Classes
##############################################################

@other_resources_api_bp.route('/runtime-classes')
class RuntimeClassesListResource(MethodView):
    """
    Runtime classes list endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved runtime classes list")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self):
        """
        List runtime classes
        
        Returns:
            dict: List of runtime classes with metadata
        """
        user_token = get_user_token(session)
        
        runtime_classes = k8sRuntimeClassListGet(session['user_role'], user_token)
        
        return jsonify({
            "data": runtime_classes,
            "metadata": {
                "count": len(runtime_classes)
            }
        })


@other_resources_api_bp.route('/runtime-classes/<name>')
class RuntimeClassResource(MethodView):
    """
    Individual runtime class endpoint.
    """
    
    @other_resources_api_bp.response(200, description="Successfully retrieved runtime class details")
    @other_resources_api_bp.response(404, description="Runtime class not found")
    @other_resources_api_bp.doc(tags=['Other Resources'])
    @login_required
    def get(self, name):
        """
        Get runtime class details
        
        Path Parameters:
            name (str): Name of the runtime class
        
        Returns:
            dict: Runtime class details
        """
        user_token = get_user_token(session)
        
        with tracer.start_as_current_span(
            "runtime-class-get",
            attributes={
                "http.route": "/api/v1/other-resources/runtime-classes/{name}",
                "http.method": "GET",
                "runtime-class.name": name,
            }
        ) if tracer else nullcontext():
            runtime_classes = k8sRuntimeClassListGet(session['user_role'], user_token)
            runtime_class_data = None
            for rc in runtime_classes:
                if rc["name"] == name:
                    runtime_class_data = rc
                    break
            
            if not runtime_class_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"RuntimeClass '{name}' not found"
                }), 404
            
            return jsonify({
                "data": runtime_class_data,
                "metadata": {
                    "name": name
                }
            })

