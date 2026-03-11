from flask import (Blueprint, g, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.k8s.metrics import k8sGetClusterMetric, k8sGetNodeMetric
from lib.k8s.namespace import (k8sNamespaceCreate, k8sNamespaceDelete,
                               k8sNamespacesGet)
from lib.k8s.node import k8sNodeGet, k8sNodesListGet
from lib.k8s.workload import (k8sDaemonsetPatch, k8sDeploymentsPatchAnnotation,
                              k8sDeploymentsPatchReplica,
                              k8sStatefulSetPatchAnnotation,
                              k8sStatefulSetPatchReplica, k8sWorkloadList)
from lib.sso import get_user_token
from lib.k8s.crds import get_custom_resources, get_custom_resource_data

##############################################################
## Helpers
##############################################################

cluster_bp = Blueprint("cluster", __name__, url_prefix="/cluster")
logger = get_logger()

##############################################################
# Cluster
##############################################################
## Namespaces
##############################################################

@cluster_bp.route("/namespace", methods=['GET', 'POST'])
@login_required
def namespace():
    """
    Namespaces list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/namespaces/list
    return render_template('cluster/namespace.html.j2')

@cluster_bp.route("/namespace/data", methods=['GET', 'POST'])
@login_required
def namespaces_data():
    """
    Namespace detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with namespace name
    if request.method == 'POST':
        namespace = request.form.get('ns_select')
        if namespace:
            # Redirect to GET request with namespace as query parameter
            return redirect(url_for('.namespaces_data', namespace=namespace))
        return redirect(url_for('.namespace'))
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the namespace query parameter
    return render_template('cluster/namespace-data.html.j2')

@cluster_bp.route("/namespace/create", methods=['GET', 'POST'])
@login_required
def namespaces_create():
    if request.method == 'POST':
        if request.form.get('namespace', None):
            namespace = request.form['namespace']
        user_token = get_user_token(session)

        k8sNamespaceCreate(session['user_role'], user_token, namespace)
        return redirect(url_for('.namespace'))
    else:
        return redirect(url_for('.namespace'))
    
@cluster_bp.route("/namespace/delete", methods=['GET', 'POST'])
@login_required
def namespaces_delete():
    if request.method == 'POST':
        if request.form.get('namespace', None):
            namespace = request.form['namespace']
        user_token = get_user_token(session)

        try:
            k8sNamespaceDelete(session['user_role'], user_token, namespace)
            actor = session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="delete_k8s_namespace",
                resource=f"namespace:{namespace}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
            )
        except Exception as e:
            actor = session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="delete_k8s_namespace",
                resource=f"namespace:{namespace}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"error": str(e)},
            )
        return redirect(url_for('.namespace'))
    else:
        return redirect(url_for('.namespace'))

@cluster_bp.route("/namespace/scale", methods=['GET', 'POST'])
@login_required
def namespaces_scale():
    if request.method == 'POST':
        namespace =  request.form['namespace']
        action = request.form['action']
        user_token = get_user_token(session)

        WORKLOAD_LIST = k8sWorkloadList(session['user_role'], user_token, namespace)
        for WORKLOAD in WORKLOAD_LIST:
            if action == "down":
                if WORKLOAD["type"] == "statefulset":
                    k8sStatefulSetPatchAnnotation(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], WORKLOAD["replicas"])
                    k8sStatefulSetPatchReplica(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], 0)
                if WORKLOAD["type"] == "deployment":
                    k8sDeploymentsPatchAnnotation(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], WORKLOAD["replicas"])
                    k8sDeploymentsPatchReplica(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], 0)
                if WORKLOAD["type"] == "daemonset":
                    body = {"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}
                    k8sDaemonsetPatch(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], body)
            else:
                if WORKLOAD["type"] == "statefulset":
                    k8sStatefulSetPatchReplica(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], WORKLOAD["original-replicas"])
                if WORKLOAD["type"] == "deployment":
                    k8sDeploymentsPatchReplica(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], WORKLOAD["original-replicas"])
                if WORKLOAD["type"] == "daemonset":
                    body = [{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]
                    k8sDaemonsetPatch(session['user_role'], user_token, WORKLOAD["namespace"], WORKLOAD["name"], body)

        return redirect(url_for('.namespace'))
    else:
        return redirect(url_for('.namespace'))

##############################################################
## Nodes
##############################################################

@cluster_bp.route("/node", methods=['GET', 'POST'])
@login_required
def node_list():
    """
    Nodes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        selected = request.form.get('selected')
        if selected:
            # Redirect to GET request with selected as query parameter
            return redirect(url_for('.node_list', selected=selected))
        return redirect(url_for('.node_list'))

    # Template now loads data via JavaScript from /api/v1/nodes and /api/v1/cluster/metrics
    return render_template('cluster/node.html.j2')

@cluster_bp.route('/node/data', methods=['GET', 'POST'])
@login_required
def nodes_data():
    """
    Node detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with node name
    if request.method == 'POST':
        no_name = request.form.get('no_name')
        if no_name:
            # Redirect to GET request with node name as query parameter
            return redirect(url_for('.nodes_data', no_name=no_name))
        return redirect(url_for('.node_list'))
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the no_name query parameter
    return render_template('cluster/node-data.html.j2')

##############################################################
## CRDs
##############################################################

@cluster_bp.route("/crd", methods=['GET', 'POST'])
@login_required
def crd_list():
    """
    CRDs list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/crds
    return render_template('cluster/crd.html.j2')
    
@cluster_bp.route("/crd/data", methods=['GET', 'POST'])
@login_required
def crd_data():
    """
    CRD data page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        crd_name = request.form.get('crd_name')
        crd_kind = request.form.get('crd_kind')
        crd_group = request.form.get('crd_group')
        crd_version = request.form.get('crd_version')
        crd_scope = request.form.get('crd_scope')
        
        # Build query parameters
        params = {}
        if crd_name:
            params['crd_name'] = crd_name
        if crd_kind:
            params['crd_kind'] = crd_kind
        if crd_group:
            params['crd_group'] = crd_group
        if crd_version:
            params['crd_version'] = crd_version
        if crd_scope:
            params['crd_scope'] = crd_scope
        
        # Redirect to GET request with parameters
        return redirect(url_for('.crd_data', **params))
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the query parameters
    return render_template('cluster/crd-data.html.j2')

##############################################################
## Runtime Classes
##############################################################

@cluster_bp.route("/runtime-class", methods=['GET', 'POST'])
@login_required
def runtime_class():
    """
    Runtime Classes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/cluster/runtime-classes
    return render_template('cluster/runetime-class.html.j2')