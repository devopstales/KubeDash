from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sStatefulSetsGet, k8sStatefulSetPatchReplica, \
    k8sDaemonSetsGet, k8sDaemonsetPatch, k8sDeploymentsGet, k8sDeploymentsPatchReplica, k8sReplicaSetsGet

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

workloads = Blueprint("workloads", __name__)
logger = get_logger()

##############################################################
# Workloads
##############################################################
## Statefullsets
##############################################################

@workloads.route("/statefulsets", methods=['GET', 'POST'])
@login_required
def statefulsets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        statefulset_list = k8sStatefulSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        statefulset_list = []

    return render_template(
        'statefulsets.html.j2',
        selected = selected,
        statefulsets = statefulset_list,
        namespaces = namespace_list,
    )

@workloads.route('/statefulsets/data', methods=['GET', 'POST'])
@login_required
def statefulsets_data():
    if request.method == 'POST':
        selected = request.form.get('selected')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)
        statefulset_list = k8sStatefulSetsGet(session['user_role'], user_token, session['ns_select'])
        statefulset_data = None
        for statefulset in statefulset_list:
            if statefulset["name"] == selected:
                statefulset_data = statefulset

        return render_template(
            'statefulsets-data.html.j2',
            statefulset_data = statefulset_data,
        )
    else:
        return redirect(url_for('workloads.login'))
        
@workloads.route('/statefulsets/scale', methods=['GET', 'POST'])
@login_required
def statefulsets_scale():
    if request.method == 'POST':
        replicas = request.form.get('replica_number')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        scale_status = k8sStatefulSetPatchReplica(session['user_role'], user_token, session['ns_select'], selected, replicas)
        return redirect(url_for('workloads.statefulsets_data'), code=307)
    else:
        return redirect(url_for('workloads.login'))

##############################################################
## Daemonsets
##############################################################

@workloads.route("/daemonsets", methods=['GET', 'POST'])
@login_required
def daemonsets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        daemonset_list = k8sDaemonSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        daemonset_list = []

    return render_template(
        'daemonsets.html.j2',
        daemonsets = daemonset_list,
        namespaces = namespace_list,
        selected = selected,
    )

@workloads.route('/daemonsets/data', methods=['GET', 'POST'])
@login_required
def daemonsets_data():
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        daemonset_list = k8sDaemonSetsGet(session['user_role'], user_token, session['ns_select'])
        daemonset_data = None
        for daemonset in daemonset_list:
            if daemonset["name"] == selected:
                daemonset_data = daemonset

        return render_template(
            'daemonsets-data.html.j2',
            daemonset_data = daemonset_data,
        )
    else:
        return redirect(url_for('workloads.login'))
    
@workloads.route('/daemonset/scale', methods=['GET', 'POST'])
@login_required
def daemonsets_scale():
    if request.method == 'POST':
        replicas = request.form.get('replica_number')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        if replicas == str(0):
            body = {"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}
        elif replicas == str(1):
            body = [{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]
        else:
            body = None

        if body is not None:
            scale_status = k8sDaemonsetPatch(session['user_role'], user_token, session['ns_select'], selected, body)

        return redirect(url_for('workloads.daemonsets_data'), code=307)
    else:
        return redirect(url_for('workloads.login'))

##############################################################
## Deployments
##############################################################

@workloads.route("/deployments", methods=['GET', 'POST'])
@login_required
def deployments():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        deployments_list = k8sDeploymentsGet(session['user_role'], user_token, session['ns_select'])
    else:
        deployments_list = []

    return render_template(
        'deployments.html.j2',
        selected = selected,
        deployments = deployments_list,
        namespaces = namespace_list,
    )

@workloads.route('/deployments/data', methods=['GET', 'POST'])
@login_required
def deployments_data():
    if request.method == 'POST':
        selected = request.form.get('selected')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        deployments_list = k8sDeploymentsGet(session['user_role'], user_token, session['ns_select'])
        deployment_data = None
        for deployment in deployments_list:
            if deployment["name"] == selected:
                deployment_data = deployment

        return render_template(
            'deployment-data.html.j2',
            deployment_data = deployment_data,
        )
    else:
        return redirect(url_for('workloads.login'))
    
@workloads.route('/deployments/scale', methods=['GET', 'POST'])
@login_required
def deployments_scale():
    if request.method == 'POST':
        replicas = request.form.get('replica_number')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        scale_status = k8sDeploymentsPatchReplica(session['user_role'], user_token, session['ns_select'], selected, replicas)
        return redirect(url_for('workloads.deployments_data'), code=307)
    else:
        return redirect(url_for('workloads.login'))

##############################################################
## ReplicaSets
##############################################################

@workloads.route("/replicasets", methods=['GET', 'POST'])
@login_required
def replicasets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        replicaset_list = k8sReplicaSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        replicaset_list = []

    return render_template(
        'replicasets.html.j2',
        replicasets = replicaset_list,
        namespaces = namespace_list,
        selected = selected,
    )
