import functools
import logging

from flask import (Blueprint, flash, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required
from flask_socketio import disconnect
from kubernetes.client.rest import ApiException

from lib.components import socketio
from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import k8sPodListVulnsGet
from lib.k8s.workload import (ErrorHandler, k8sDaemonsetPatch,
                              k8sDaemonSetsGet, k8sDeploymentsGet,
                              k8sDeploymentsPatchReplica, k8sPodExecSocket,
                              k8sPodExecStream, k8sPodGet, k8sPodGetContainers,
                              k8sPodListGet, k8sPodLogsStream, k8sPodDelete,
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
    """
    Pod list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        selected = request.form.get('selected')
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('.pod_list', **params))
        return redirect(url_for('.pod_list'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/workloads/pods
    return render_template('workload/pod.html.j2', namespaces=namespaces)
    
@workload_bp.route('/pods/delete', methods=['POST'])
@login_required
def pod_delete():
    if request.method == 'POST':
        from lib.helper_functions import validate_pod_name, validate_namespace
        
        pod_name = request.form.get('pod_name', '').strip()
        namespace = request.form.get('ns_select', '').strip()
        
        # Validate pod name to prevent XSS and path traversal
        is_valid, error_msg = validate_pod_name(pod_name)
        if not is_valid:
            flash(f"Invalid pod name: {error_msg}", "danger")
            return redirect(url_for('.pod_list'))
        
        # Validate namespace
        if namespace:
            is_valid_ns, error_msg_ns = validate_namespace(namespace)
            if not is_valid_ns:
                flash(f"Invalid namespace: {error_msg_ns}", "danger")
                return redirect(url_for('.pod_list'))
            session['ns_select'] = namespace

        user_token = get_user_token(session)
        
        try:
            k8sPodDelete(session['user_role'], user_token, session['ns_select'], pod_name)
            return redirect(url_for('.pod_list'))
        except ApiException:
            return redirect(url_for('.pod_list'))
        
            

@workload_bp.route('/pods/data', methods=['GET', 'POST'])
@login_required
def pod_data():
    """
    Pod detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if po_name:
            params['po_name'] = po_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with parameters
        return redirect(url_for('.pod_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the query parameters
    return render_template('workload/pod-data.html.j2', namespaces=namespaces)

##############################################################
## Pod Logs
##############################################################

logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

@workload_bp.route('/pods/logs', methods=['GET', 'POST'])
@login_required
def pod_logs():
    """
    Pod logs page.
    
    Containers are loaded client-side via JavaScript API calls.
    Websocket connection is handled server-side for log streaming.
    """
    from lib.helper_functions import validate_pod_name, validate_namespace
    
    # Get pod name and namespace from query params or form
    po_name = request.args.get('po_name') or request.form.get('po_name', '')
    namespace = request.form.get('ns_select', '')
    
    # Validate pod name to prevent XSS and path traversal
    if po_name:
        is_valid, error_msg = validate_pod_name(po_name)
        if not is_valid:
            flash(f"Invalid pod name: {error_msg}", "danger")
            po_name = ''
    
    # Validate namespace
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            flash(f"Invalid namespace: {error_msg_ns}", "danger")
            namespace = ''
        else:
            session['ns_select'] = namespace
    
    # Template loads containers via JavaScript from /api/v1/workloads/pods/<name>/containers
    # Websocket connection is handled by the template's JavaScript
    return render_template(
        'workload/pod-log.html.j2', 
        po_name=po_name or '',
        async_mode=socketio.async_mode
    )

@socketio.on("connect", namespace="/log")
@authenticated_only
def log_connect():
    socketio.emit('response', {'data': ''}, namespace="/log")

@socketio.on("message", namespace="/log")
@authenticated_only
def log_message(po_name, container):
    from lib.helper_functions import validate_pod_name, validate_namespace
    
    # Validate pod name to prevent XSS and path traversal
    if not po_name or not isinstance(po_name, str):
        logger.warning(f"Invalid pod name in log_message: {po_name}")
        return
    
    is_valid, error_msg = validate_pod_name(po_name)
    if not is_valid:
        logger.warning(f"Invalid pod name in log_message: {error_msg}")
        return
    
    # Validate namespace
    namespace = session.get('ns_select', 'default')
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            logger.warning(f"Invalid namespace in log_message: {error_msg_ns}")
            return
    
    # Validate container name (basic check)
    if container and not isinstance(container, str):
        logger.warning(f"Invalid container name in log_message: {container}")
        return
    
    user_token = get_user_token(session)
    socketio.start_background_task(k8sPodLogsStream, session['user_role'], user_token, namespace, po_name, container)

##############################################################
## Pod Exec
##############################################################

@workload_bp.route('/pods/exec', methods=['GET', 'POST'])
@login_required
def pod_exec():
    """
    Pod exec page.
    
    Containers are loaded client-side via JavaScript API calls.
    Websocket connection is handled server-side for exec streaming.
    """
    from lib.helper_functions import validate_pod_name, validate_namespace
    
    # Get pod name and namespace from query params or form
    po_name = request.args.get('po_name') or request.form.get('po_name', '')
    namespace = request.form.get('ns_select', '')
    
    # Validate pod name to prevent XSS and path traversal
    if po_name:
        is_valid, error_msg = validate_pod_name(po_name)
        if not is_valid:
            flash(f"Invalid pod name: {error_msg}", "danger")
            po_name = ''
    
    # Validate namespace
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            flash(f"Invalid namespace: {error_msg_ns}", "danger")
            namespace = ''
        else:
            session['ns_select'] = namespace
    
    # Template loads containers via JavaScript from /api/v1/workloads/pods/<name>/containers
    # Websocket connection is handled by the template's JavaScript
    return render_template(
        'workload/pod-exec.html.j2', 
        po_name=po_name or '',
        async_mode=socketio.async_mode
    )

@socketio.on("connect", namespace="/exec")
@authenticated_only
def connect():
    socketio.emit("response", {"output":  ''}, namespace="/exec")

@socketio.on("message", namespace="/exec")
@authenticated_only
def message(po_name, container):
    from lib.helper_functions import validate_pod_name, validate_namespace
    
    # Validate pod name to prevent XSS and path traversal
    if not po_name or not isinstance(po_name, str):
        logger.warning(f"Invalid pod name in exec message: {po_name}")
        return
    
    is_valid, error_msg = validate_pod_name(po_name)
    if not is_valid:
        logger.warning(f"Invalid pod name in exec message: {error_msg}")
        return
    
    # Validate namespace
    namespace = session.get('ns_select', 'default')
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            logger.warning(f"Invalid namespace in exec message: {error_msg_ns}")
            return
    
    # Validate container name (basic check)
    if container and not isinstance(container, str):
        logger.warning(f"Invalid container name in exec message: {container}")
        return
    
    user_token = get_user_token(session)

    global wsclient
    wsclient = k8sPodExecSocket(session['user_role'], user_token, namespace, po_name, container)

    socketio.start_background_task(k8sPodExecStream, wsclient, session['user_role'], user_token, namespace, po_name, container)

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
    """
    StatefulSets list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected', None)
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('.statefulsets', **params))
        return redirect(url_for('.statefulsets'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/workloads/statefulsets
    return render_template('workload/statefulset.html.j2', namespaces=namespaces)

@workload_bp.route('/statefulsets/data', methods=['GET', 'POST'])
@login_required
def statefulsets_data():
    """
    StatefulSet detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if selected:
            params['statefulset_name'] = selected
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with parameters
        return redirect(url_for('.statefulsets_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the query parameters
    return render_template('workload/statefulset-data.html.j2', namespaces=namespaces)
        
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
    """
    DaemonSets list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('.daemonsets', **params))
        return redirect(url_for('.daemonsets'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/workloads/daemonsets
    return render_template('workload/daemonset.html.j2', namespaces=namespaces)

@workload_bp.route('/daemonsets/data', methods=['GET', 'POST'])
@login_required
def daemonset_data():
    """
    DaemonSet detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if selected:
            params['daemonset_name'] = selected
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with parameters
        return redirect(url_for('.daemonset_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the query parameters
    return render_template('workload/daemonset-data.html.j2', namespaces=namespaces)
    
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
    """
    Deployments list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('.deployments', **params))
        return redirect(url_for('.deployments'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/workloads/deployments
    return render_template('workload/deployment.html.j2', namespaces=namespaces)

@workload_bp.route('/deployments/data', methods=['GET', 'POST'])
@login_required
def deployment_data():
    """
    Deployment detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if selected:
            params['deployment_name'] = selected
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with parameters
        return redirect(url_for('.deployment_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Handle GET requests - just render the template
    # The template will fetch data client-side using the query parameters
    return render_template('workload/deployment-data.html.j2', namespaces=namespaces)
    
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
    """
    ReplicaSets list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with selected parameter
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        
        # Build query parameters
        params = {}
        if selected:
            params['selected'] = selected
        
        # Redirect to GET request with parameters
        if params:
            return redirect(url_for('.replicasets', **params))
        return redirect(url_for('.replicasets'))

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/workloads/replicasets
    return render_template('workload/replicaset.html.j2', namespaces=namespaces)
