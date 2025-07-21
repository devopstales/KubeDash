import functools
import logging

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required
from flask_socketio import disconnect
from kubernetes.client.rest import ApiException

from lib.components import socketio
from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import k8sPodListVulnsGet, k8sPodVulnsGet
from lib.k8s.workload import (ErrorHandler, k8sDaemonsetPatch,
                              k8sDaemonSetsGet, k8sDeploymentsGet,
                              k8sDeploymentsPatchReplica, k8sPodExecSocket,
                              k8sPodExecStream, k8sPodGet, k8sPodGetContainers,
                              k8sPodListGet, k8sPodLogsStream,
                              k8sReplicaSetsGet, k8sStatefulSetPatchReplica,
                              k8sStatefulSetsGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

workload_bp = Blueprint("workload", __name__, url_prefix="/workload")
logger = get_logger()

def authenticated_only(f):
    """Test Current user is authenticated"""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

##############################################################
# Workloads
##############################################################
## Pods
##############################################################

@workload_bp.route("/pods", methods=['GET', 'POST'])
@login_required
def pod_list():
    selected = None
    
    if request.method == 'POST':
        selected = request.form.get('selected')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

    user_token = get_user_token(session)

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    #    has_report, pod_list = k8sPodListVulnsGet(session['user_role'], user_token, session['ns_select'])
    pod_list = k8sPodListGet(session['user_role'], user_token, session['ns_select'])

    return render_template(
        'workload/pod.html.j2',
        pods = pod_list,
        namespaces = namespace_list,
        selected = selected
    )

@workload_bp.route('/pods/data', methods=['GET', 'POST'])
@login_required
def pod_data():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        pod_data = k8sPodGet(session['user_role'], user_token, session['ns_select'], po_name)
        # has_report, pod_vulns = k8sPodVulnsGet(session['user_role'], user_token, session['ns_select'], po_name)

        return render_template(
            'workload/pod-data.html.j2',
            po_name = po_name,
            pod_data = pod_data,
        )
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Pod Logs
##############################################################

logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

@workload_bp.route('/pods/logs', methods=['POST'])
@login_required
def pod_logs():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        logger.info("async_mode: %s" % socketio.async_mode)
        pod_containers, pod_init_containers = k8sPodGetContainers(session['user_role'], user_token, session['ns_select'], po_name)
        if request.form.get('container_select'):
            container_select = request.form.get('container_select')
        else:
            if pod_containers:
                container_select = pod_containers[0]
            else:
                container_select = None

        return render_template(
            'workload/pod-log.html.j2', 
            po_name = po_name,
            container_select = container_select,
            pod_containers = pod_containers,
            pod_init_containers = pod_init_containers,
            async_mode = socketio.async_mode
        )
    else:
        return redirect(url_for('auth.login'))

@socketio.on("connect", namespace="/log")
@authenticated_only
def log_connect():
    socketio.emit('response', {'data': ''}, namespace="/log")

@socketio.on("message", namespace="/log")
@authenticated_only
def log_message(po_name, container):
    user_token = get_user_token(session)
    socketio.start_background_task(k8sPodLogsStream, session['user_role'], user_token, session['ns_select'], po_name, container)

##############################################################
## Pod Exec
##############################################################

@workload_bp.route('/pods/exec', methods=['POST'])
@login_required
def pod_exec():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        logger.info("async_mode: %s" % socketio.async_mode)
        pod_containers, pod_init_containers = k8sPodGetContainers(session['user_role'], user_token, session['ns_select'], po_name)
        if request.form.get('container_select'):
            container_select = request.form.get('container_select')
        else:
            if pod_containers:
                container_select = pod_containers[0]
            else:
                container_select = None

        return render_template(
            'workload/pod-exec.html.j2', 
            po_name = po_name,
            container_select = container_select,
            pod_containers = pod_containers,
            pod_init_containers = pod_init_containers,  # Not used in this context, but kept for completeness.
            async_mode = socketio.async_mode
        )
    else:
        return redirect(url_for('auth.login'))

@socketio.on("connect", namespace="/exec")
@authenticated_only
def connect():
    socketio.emit("response", {"output":  ''}, namespace="/exec")

@socketio.on("message", namespace="/exec")
@authenticated_only
def message(po_name, container):
    user_token = get_user_token(session)

    global wsclient
    wsclient = k8sPodExecSocket(session['user_role'], user_token, session['ns_select'], po_name, container)

    socketio.start_background_task(k8sPodExecStream, wsclient, session['user_role'], user_token, session['ns_select'], po_name, container)

@socketio.on("exec-input", namespace="/exec")
@authenticated_only
def exec_input(data):
    """
    Write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    try:
        wsclient.write_stdin(data["input"].encode())
    except ApiException as error:
            ErrorHandler(logger, error, "exec_input")
    except Exception as error:
        ERROR = "exec_input: %s" % error
        ErrorHandler(logger, "error", ERROR)

##############################################################
## Statefullsets
##############################################################

@workload_bp.route("/statefulsets", methods=['GET', 'POST'])
@login_required
def statefulsets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected', None)
        
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        statefulset_list = k8sStatefulSetsGet(session['user_role'], user_token, session['ns_select'])
    else:
        statefulset_list = []

    return render_template(
        'workload/statefulset.html.j2',
        selected = selected,
        statefulsets = statefulset_list,
        namespaces = namespace_list,
    )

@workload_bp.route('/statefulsets/data', methods=['GET', 'POST'])
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
            'workload/statefulset-data.html.j2',
            statefulset_data = statefulset_data,
        )
    else:
        return redirect(url_for('auth.login'))
        
@workload_bp.route('/statefulsets/scale', methods=['GET', 'POST'])
@login_required
def statefulsets_scale():
    if request.method == 'POST':
        replicas = request.form.get('replica_number')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        scale_status = k8sStatefulSetPatchReplica(session['user_role'], user_token, session['ns_select'], selected, replicas)
        return redirect(url_for('auth.statefulsets_data'), code=307)
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Daemonsets
##############################################################

@workload_bp.route("/daemonsets", methods=['GET', 'POST'])
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
        'workload/daemonset.html.j2',
        daemonsets = daemonset_list,
        namespaces = namespace_list,
        selected = selected,
    )

@workload_bp.route('/daemonsets/data', methods=['GET', 'POST'])
@login_required
def daemonset_data():
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
            'workload/daemonset-data.html.j2',
            daemonset_data = daemonset_data,
        )
    else:
        return redirect(url_for('auth.login'))
    
@workload_bp.route('/statefulsets/scale', methods=['GET', 'POST'])
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

        return redirect(url_for('auth.daemonsets_data'), code=307)
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Deployments
##############################################################

@workload_bp.route("/deployments", methods=['GET', 'POST'])
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
        'workload/deployment.html.j2',
        selected = selected,
        deployments = deployments_list,
        namespaces = namespace_list,
    )

@workload_bp.route('/deployments/data', methods=['GET', 'POST'])
@login_required
def deployment_data():
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
            'workload/deployment-data.html.j2',
            deployment_data = deployment_data,
        )
    else:
        return redirect(url_for('auth.login'))
    
@workload_bp.route('/deployments/scale', methods=['GET', 'POST'])
@login_required
def deployment_scale():
    if request.method == 'POST':
        replicas = request.form.get('replica_number')
        selected = request.form.get('selected')

        user_token = get_user_token(session)

        scale_status = k8sDeploymentsPatchReplica(session['user_role'], user_token, session['ns_select'], selected, replicas)
        return redirect(url_for('auth.deployments_data'), code=307)
    else:
        return redirect(url_for('auth.login'))

##############################################################
## ReplicaSets
##############################################################

@workload_bp.route("/replicasets", methods=['GET', 'POST'])
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
        'workload/replicaset.html.j2',
        replicasets = replicaset_list,
        namespaces = namespace_list,
        selected = selected,
    )
