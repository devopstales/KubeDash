import logging, functools

from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required, current_user
from flask_socketio import disconnect

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sPodListVulnsGet, k8sPodGet, \
    k8sPodVulnsGet, k8sPodGetContainers, k8sPodExecSocket, k8sPodLogsStream, \
    k8sPodExecStream, ApiException, NoFlashErrorHandler

from lib_functions.helper_functions import get_logger
from lib_functions.components import socketio


##############################################################
## Helpers
##############################################################

pods = Blueprint("pods", __name__)
logger = get_logger(__name__.split(".")[1])

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
## Pods
##############################################################

@pods.route("/pods", methods=['GET', 'POST'])
@login_required
def pod_list():
    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')

    user_token = get_user_token(session)

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_report, pod_list = k8sPodListVulnsGet(session['user_role'], user_token, session['ns_select'])
    else:
        pod_list = []
        has_report = None

    return render_template(
        'pods.html.j2',
        pods = pod_list,
        has_report = has_report,
        namespaces = namespace_list,
    )

@pods.route('/pods/data', methods=['GET', 'POST'])
@login_required
def pods_data():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        pod_data = k8sPodGet(session['user_role'], user_token, session['ns_select'], po_name)
        has_report, pod_vulns = k8sPodVulnsGet(session['user_role'], user_token, session['ns_select'], po_name)

        return render_template(
            'pod-data.html.j2',
            po_name = po_name,
            pod_data = pod_data,
            has_report = has_report,
            pod_vulns = pod_vulns,
        )
    else:
        return redirect(url_for('pods.login'))

##############################################################
## Pod Logs
##############################################################

logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

@pods.route('/pods/logs', methods=['POST'])
@login_required
def pods_logs():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        if request.form.get('ns_select'):
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
            'pod-logs.html.j2', 
            po_name = po_name,
            container_select = container_select,
            pod_containers = pod_containers,
            pod_init_containers = pod_init_containers,
            async_mode = socketio.async_mode
        )
    else:
        return redirect(url_for('pods.login'))

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

@pods.route('/pods/exec', methods=['POST'])
@login_required
def pods_exec():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        if request.form.get('ns_select'):
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
            'pod-exec.html.j2', 
            po_name = po_name,
            container_select = container_select,
            pod_containers = pod_containers,
            async_mode = socketio.async_mode
        )
    else:
        return redirect(url_for('pods.login'))

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

    socketio.start_background_task(k8sPodExecStream, wsclient)

@socketio.on("exec-input", namespace="/exec")
@authenticated_only
def exec_input(data):
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    try:
        wsclient.write_stdin(data["input"].encode())
    except ApiException as error:
            NoFlashErrorHandler(logger, error, "exec_input")
    except Exception as error:
        ERROR = "exec_input: %s" % error
        NoFlashErrorHandler(logger, "error", ERROR)
