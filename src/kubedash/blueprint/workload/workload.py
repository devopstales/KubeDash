import functools
import logging
import threading

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required
from flask_socketio import disconnect
from kubernetes.client.rest import ApiException

from lib.components import socketio
from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.security import k8sPodListVulnsGet
from lib.k8s.workload import (ErrorHandler, k8sDaemonsetPatch,
                              k8sDaemonSetsGet, k8sDeploymentsGet,
                              k8sDeploymentsPatchReplica, k8sPodExecSocket,
                              k8sPodExecStream, k8sPodGet, k8sPodGetContainers,
                              k8sPodListGet, k8sPodLogsStream, k8sPodLogsStreamWithTail, k8sPodDelete,
                              k8sReplicaSetsGet, k8sStatefulSetPatchReplica,
                              k8sStatefulSetsGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

workload_bp = Blueprint("workload", __name__, url_prefix="/workload")
logger = get_logger()

# Per-connection exec state: sid -> {"wsclient": wsclient, "cancel": threading.Event}
exec_streams = {}
# Per-connection log cancel: sid -> threading.Event (set to stop the log task)
log_cancel = {}

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
        namespace = session['ns_select']
        actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
        try:
            k8sPodDelete(session['user_role'], user_token, namespace, pod_name)
            log_audit_event(
                user_id=actor,
                action="delete_k8s_pod",
                resource=f"pod:{namespace}/{pod_name}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
            )
            return redirect(url_for('.pod_list'))
        except ApiException as e:
            log_audit_event(
                user_id=actor,
                action="delete_k8s_pod",
                resource=f"pod:{namespace}/{pod_name}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"error": str(e)},
            )
            return redirect(url_for('.pod_list'))
        except Exception as e:
            log_audit_event(
                user_id=actor,
                action="delete_k8s_pod",
                resource=f"pod:{namespace}/{pod_name}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"error": str(e)},
            )
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

@workload_bp.route('/pods/logs/enhanced', methods=['GET', 'POST'])
@login_required
def pod_logs_enhanced():
    """
    Enhanced pod logs page with filtering, search, and export.

    Uses the new DOM-based log viewer with toolbar controls.
    Containers are loaded client-side via JavaScript API calls.
    WebSocket connection is handled server-side for log streaming.
    """
    from lib.helper_functions import validate_pod_name, validate_namespace

    # Get pod name and namespace from query params or form
    po_name = request.args.get('po_name') or request.form.get('po_name', '')
    namespace = request.form.get('ns_select', '')
    container_select = request.args.get('container') or request.form.get('container', '')

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

    # Check feature flag
    config = current_app.config.get('kubedash.ini')
    feature_enabled = 'true'
    if config:
        feature_enabled = config.get('features', 'enhanced_log_viewer', fallback='true')

    return render_template(
        'workload/pod-logs.html.j2',
        po_name=po_name or '',
        container_select=container_select or '',
        feature_enabled=feature_enabled,
        async_mode=socketio.async_mode
    )


@workload_bp.route('/workloads/logs', methods=['GET', 'POST'])
@login_required
def workload_logs():
    """
    Multi-pod log viewer for workloads (Deployment, StatefulSet, DaemonSet, ReplicaSet).
    
    Shows merged logs from all pods belonging to a workload.
    """
    from lib.helper_functions import validate_namespace

    workload_kind = request.args.get('workload_kind', '')
    workload_name = request.args.get('workload_name', '')
    namespace = request.form.get('ns_select', '') or request.args.get('namespace', '')

    # Validate namespace
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            flash(f"Invalid namespace: {error_msg_ns}", "danger")
            namespace = ''
        else:
            session['ns_select'] = namespace

    # Check feature flag
    config = current_app.config.get('kubedash.ini')
    feature_enabled = 'true'
    if config:
        feature_enabled = config.get('features', 'enhanced_log_viewer', fallback='true')

    return render_template(
        'workload/multipod-logs.html.j2',
        workload_kind=workload_kind or '',
        workload_name=workload_name or '',
        feature_enabled=feature_enabled,
        async_mode=socketio.async_mode
    )

@workload_bp.route('/pods/logs', methods=['GET', 'POST'])
@login_required
def pod_logs():
    """
    Enhanced pod logs page with filtering, search, and export.

    Uses the new DOM-based log viewer with toolbar controls.
    Containers are loaded client-side via JavaScript API calls.
    WebSocket connection is handled server-side for log streaming.
    """
    from lib.helper_functions import validate_pod_name, validate_namespace

    # Get pod name and namespace from query params or form
    po_name = request.args.get('po_name') or request.form.get('po_name', '')
    namespace = request.form.get('ns_select', '')
    container_select = request.args.get('container') or request.form.get('container', '')

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

    # Check feature flag
    config = current_app.config.get('kubedash.ini')
    feature_enabled = 'true'
    if config:
        feature_enabled = config.get('features', 'enhanced_log_viewer', fallback='true')

    return render_template(
        'workload/pod-logs.html.j2',
        po_name=po_name or '',
        container_select=container_select or '',
        feature_enabled=feature_enabled,
        async_mode=socketio.async_mode
    )

@socketio.on("connect", namespace="/log")
@authenticated_only
def log_connect():
    socketio.emit("response", {"data": ""}, room=request.sid, namespace="/log")


@socketio.on("disconnect", namespace="/log")
def log_disconnect():
    sid = request.sid
    ev = log_cancel.pop(sid, None)
    if ev:
        ev.set()


@socketio.on("message", namespace="/log")
@authenticated_only
def log_message(po_name, container):
    from lib.helper_functions import validate_pod_name, validate_namespace

    if not po_name or not isinstance(po_name, str):
        logger.warning(f"Invalid pod name in log_message: {po_name}")
        return

    is_valid, error_msg = validate_pod_name(po_name)
    if not is_valid:
        logger.warning(f"Invalid pod name in log_message: {error_msg}")
        return

    namespace = session.get('ns_select', 'default')
    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            logger.warning(f"Invalid namespace in log_message: {error_msg_ns}")
            return

    if container and not isinstance(container, str):
        logger.warning(f"Invalid container name in log_message: {container}")
        return

    sid = request.sid
    # Cancel previous log stream for this connection
    old_ev = log_cancel.pop(sid, None)
    if old_ev:
        old_ev.set()
    cancel_ev = threading.Event()
    log_cancel[sid] = cancel_ev

    user_token = get_user_token(session)
    socketio.start_background_task(
        k8sPodLogsStream,
        session['user_role'],
        user_token,
        namespace,
        po_name,
        container,
        sid,
        cancel_ev,
    )


@socketio.on("join_pod_logs", namespace="/log")
@authenticated_only
def join_pod_logs(data):
    """
    Enhanced log join event that supports tail_lines parameter for loading older lines.
    
    Expected data format:
    {
        podName: string,
        container: string,
        namespace: string (optional, defaults to session),
        tail_lines: int (optional, defaults to 100)
    }
    """
    from lib.helper_functions import validate_pod_name, validate_namespace

    if not data or not isinstance(data, dict):
        logger.warning("Invalid data format in join_pod_logs")
        return

    po_name = data.get('podName', '')
    container = data.get('container', '')
    namespace = data.get('namespace', session.get('ns_select', 'default'))
    tail_lines = data.get('tail_lines', 100)

    # Validate inputs
    if not po_name or not isinstance(po_name, str):
        logger.warning(f"Invalid pod name in join_pod_logs: {po_name}")
        return

    is_valid, error_msg = validate_pod_name(po_name)
    if not is_valid:
        logger.warning(f"Invalid pod name in join_pod_logs: {error_msg}")
        return

    if namespace:
        is_valid_ns, error_msg_ns = validate_namespace(namespace)
        if not is_valid_ns:
            logger.warning(f"Invalid namespace in join_pod_logs: {error_msg_ns}")
            return

    if container and not isinstance(container, str):
        logger.warning(f"Invalid container name in join_pod_logs: {container}")
        return

    # Clamp tail_lines to reasonable range
    tail_lines = max(1, min(tail_lines, 10000))

    sid = request.sid
    # Cancel previous log stream for this connection
    old_ev = log_cancel.pop(sid, None)
    if old_ev:
        old_ev.set()
    cancel_ev = threading.Event()
    log_cancel[sid] = cancel_ev

    user_token = get_user_token(session)
    
    # Audit log for log access
    try:
        log_audit_event(
            action='log_access',
            username=session.get('user_role', 'unknown'),
            details={
                'namespace': namespace,
                'pod': po_name,
                'container': container,
                'tail_lines': tail_lines
            }
        )
    except Exception as audit_error:
        logger.debug(f"Audit logging failed (non-critical): {audit_error}")

    socketio.start_background_task(
        k8sPodLogsStreamWithTail,
        session['user_role'],
        user_token,
        namespace,
        po_name,
        container,
        sid,
        cancel_ev,
        tail_lines
    )

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
    container_select = request.args.get('container') or request.form.get('container', '')

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

    # Check feature flag
    config = current_app.config.get('kubedash.ini')
    feature_enabled = 'true'
    if config:
        feature_enabled = config.get('features', 'interactive_terminal', fallback='true')

    # Template loads containers via JavaScript from /api/v1/workloads/pods/<name>/containers
    # Websocket connection is handled by the template's JavaScript
    return render_template(
        'workload/pod-exec.html.j2',
        po_name=po_name or '',
        container_select=container_select or '',
        feature_enabled=feature_enabled,
        async_mode=socketio.async_mode
    )

@socketio.on("connect", namespace="/exec")
@authenticated_only
def connect():
    socketio.emit("response", {"output": ''}, room=request.sid, namespace="/exec")

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
    sid = request.sid

    # Cancel any existing exec for this connection
    if sid in exec_streams:
        exec_streams[sid].get("cancel").set()

    wsclient = k8sPodExecSocket(session['user_role'], user_token, namespace, po_name, container)
    if wsclient is None:
        return
    cancel_ev = threading.Event()
    exec_streams[sid] = {"wsclient": wsclient, "cancel": cancel_ev}
    socketio.start_background_task(
        k8sPodExecStream,
        wsclient,
        session['user_role'],
        user_token,
        namespace,
        po_name,
        container,
        sid,
        exec_streams,
        cancel_ev,
    )


@socketio.on("disconnect", namespace="/exec")
def exec_disconnect():
    sid = request.sid
    entry = exec_streams.pop(sid, None)
    if entry:
        entry.get("cancel").set()


@socketio.on("stop", namespace="/exec")
@authenticated_only
def exec_stop():
    """Client requested disconnect; stop the exec stream for this connection."""
    sid = request.sid
    entry = exec_streams.pop(sid, None)
    if entry:
        entry.get("cancel").set()
    try:
        socketio.emit("closed", {"message": "Disconnected"}, room=sid, namespace="/exec")
    except Exception:
        pass


@socketio.on("exec-input", namespace="/exec")
@authenticated_only
def exec_input(data):
    """
    Write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    sid = request.sid
    entry = exec_streams.get(sid)
    wsclient = entry.get("wsclient") if entry else None
    if not wsclient:
        logger.debug("exec_input: no stream for sid %s", sid)
        return
    try:
        inp = data.get("input")
        if inp is not None:
            wsclient.write_stdin(inp.encode() if isinstance(inp, str) else inp)
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
