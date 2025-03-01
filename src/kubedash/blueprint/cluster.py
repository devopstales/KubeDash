from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required

from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespacesGet, k8sNamespaceCreate, k8sNamespaceDelete
from lib.k8s.workload import k8sWorkloadList, k8sStatefulSetPatchAnnotation, k8sStatefulSetPatchReplica, \
    k8sDeploymentsPatchAnnotation, k8sDeploymentsPatchReplica, k8sDaemonsetPatch

from lib.k8s.node import k8sNodesListGet, k8sNodeGet
from lib.k8s.metrics import k8sGetClusterMetric, k8sGetNodeMetric

from lib.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

cluster = Blueprint("cluster", __name__, url_prefix="/cluster")
logger = get_logger()

##############################################################
# Cluster
##############################################################
## Namespaces
##############################################################

@cluster.route("/namespace", methods=['GET', 'POST'])
@login_required
def namespaces():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    ns_list = k8sNamespacesGet(session['user_role'], user_token)
    #namespace_list = []
    #for namespace in ns_list:
    #    WORKLOAD_LIST = k8sWorkloadList(session['user_role'], user_token, namespace["name"])
    #    namespace["live"] = 0
    #    for WORKLOAD in WORKLOAD_LIST:
    #        if WORKLOAD["replicas"] > 0:
    #            namespace["live"] += WORKLOAD["replicas"]
    #    namespace_list.append(namespace)
    
    return render_template(
        'cluster/namespace.html.j2',
        selected = selected,
        namespace_list = ns_list,
    )

@cluster.route("/namespace/data", methods=['GET', 'POST'])
@login_required
def namespaces_data():
    if request.method == 'POST':
        namespace = request.form['ns_select']
        namespace_data = eval(request.form['ns_data'])
            
        user_token = get_user_token(session)
        WORKLOAD_NUM = 0
        WORKLOAD_LIST = k8sWorkloadList(session['user_role'], user_token, namespace)
        for WORKLOAD in WORKLOAD_LIST:
            if WORKLOAD["replicas"] > 0:
                WORKLOAD_NUM += WORKLOAD["replicas"]
        namespace_data['live_workers'] = WORKLOAD_NUM
                
        print(namespace_data)

        return render_template(
            'cluster/namespace-data.html.j2',
            ns_data = namespace_data,
        )
    else:
        return redirect(url_for('.namespace'))

@cluster.route("/namespace/create", methods=['GET', 'POST'])
@login_required
def namespaces_create():
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form['namespace']
        user_token = get_user_token(session)

        k8sNamespaceCreate(session['user_role'], user_token, session['ns_select'])
        return redirect(url_for('.namespace'))
    else:
        return redirect(url_for('.namespace'))
    
@cluster.route("/namespace/delete", methods=['GET', 'POST'])
@login_required
def namespaces_delete():
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form['namespace']
        user_token = get_user_token(session)

        k8sNamespaceDelete(session['user_role'], user_token, session['ns_select'])
        return redirect(url_for('.namespace'))
    else:
        return redirect(url_for('.namespace'))

@cluster.route("/namespace/scale", methods=['GET', 'POST'])
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

@cluster.route("/node", methods=['GET', 'POST'])
@login_required
def node_list():
    selected = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    user_token = get_user_token(session)

    node_data = k8sNodesListGet(session['user_role'], user_token)
    cluster_metrics = k8sGetClusterMetric()

    return render_template(
        'cluster/node.html.j2',
        nodes = node_data,
        selected = selected,
        cluster_metrics = cluster_metrics,
    )

@cluster.route('/node/data', methods=['GET', 'POST'])
@login_required
def nodes_data():
    if request.method == 'POST':
        no_name = request.form.get('no_name')

        user_token = get_user_token(session)
        node_data = k8sNodeGet(session['user_role'], user_token, no_name)
        node_metrics = k8sGetNodeMetric(no_name)

        return render_template(
            'cluster/node-data.html.j2',
            no_name = no_name,
            node_data = node_data,
            node_metrics = node_metrics,
        )
    else:
        return redirect(url_for('auth.login'))
