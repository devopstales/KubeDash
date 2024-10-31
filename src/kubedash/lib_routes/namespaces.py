from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespacesGet, k8sWorkloadList, k8sNamespaceCreate, \
    k8sNamespaceDelete, k8sStatefulSetPatchAnnotation, k8sStatefulSetPatchReplica, \
    k8sDeploymentsPatchAnnotation, k8sDeploymentsPatchReplica, k8sDaemonsetPatch

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

namespaces = Blueprint("namespaces", __name__)
logger = get_logger(__name__.split(".")[1])

##############################################################
## Namespaces
##############################################################

@namespaces.route("/namespaces", methods=['GET', 'POST'])
@login_required
def namespace_list():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    ns_list = k8sNamespacesGet(session['user_role'], user_token)
    namespace_list = []
    for namespace in ns_list:
        WORKLOAD_LIST = k8sWorkloadList(session['user_role'], user_token, namespace["name"])
        namespace["live"] = 0
        for WORKLOAD in WORKLOAD_LIST:
            if WORKLOAD["replicas"] > 0:
                namespace["live"] += WORKLOAD["replicas"]
        namespace_list.append(namespace)

    return render_template(
        'namespaces.html.j2',
        selected = selected,
        namespace_list = namespace_list,
    )

@namespaces.route("/namespaces/data", methods=['GET', 'POST'])
@login_required
def namespaces_data():
    if request.method == 'POST':
        namespace = request.form['ns_data']

        return render_template(
            'namespaces-data.html.j2',
            ns_data = eval(namespace),
        )
    else:
        return redirect(url_for('namespaces.namespaces'))

@namespaces.route("/namespaces/create", methods=['GET', 'POST'])
@login_required
def namespaces_create():
    if request.method == 'POST':
        namespace = request.form['namespace']
        user_token = get_user_token(session)

        k8sNamespaceCreate(session['user_role'], user_token, namespace)
        return redirect(url_for('namespaces.namespaces'))
    else:
        return redirect(url_for('namespaces.namespaces'))
    
@namespaces.route("/namespaces/delete", methods=['GET', 'POST'])
@login_required
def namespaces_delete():
    if request.method == 'POST':
        namespace = request.form['namespace']
        user_token = get_user_token(session)

        k8sNamespaceDelete(session['user_role'], user_token, namespace)
        return redirect(url_for('namespaces.namespaces'))
    else:
        return redirect(url_for('namespaces.namespaces'))

@namespaces.route("/namespaces/scale", methods=['GET', 'POST'])
@login_required
def namespaces_scale():
    if request.method == 'POST':
        namespace = request.form['namespace']
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

        return redirect(url_for('namespaces.namespaces'))
    else:
        return redirect(url_for('namespaces.namespaces'))
