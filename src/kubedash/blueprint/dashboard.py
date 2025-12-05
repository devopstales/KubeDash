from flask import Blueprint, flash, render_template, request, session
from flask_login import login_required
from werkzeug.security import check_password_hash

from lib.helper_functions import get_logger
from lib.k8s.metrics import k8sGetClusterMetric, k8sGetClusterEvents, k8sGetPodMap
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token
from lib.user import User

##############################################################
## Helpers
##############################################################

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard" )
logger = get_logger()

from lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()

##############################################################
## Dashboard
##############################################################
## Cluster Metrics
##############################################################

@dashboard_bp.route('/cluster-metric')
@tracer.start_as_current_span("/cluster-metrics")
@login_required
def cluster_metrics():
    span = trace.get_current_span()
    user_token = get_user_token(session)
    
    cluster_metrics = k8sGetClusterMetric()
    cluster_events  = k8sGetClusterEvents(session['user_role'], user_token)
    
    username = session['user_name']
    user = User.query.filter_by(username="admin", user_type = "Local").first()

    if tracer and span.is_recording():
        span.set_attribute("http.route", "/cluster-metrics")
        span.set_attribute("http.method", request.method)
        span.set_attribute("user.name", session['user_name'])
        span.set_attribute("user.type", session['user_type'])
        span.set_attribute("user.role", session['user_role'])


    if username == "admin" and check_password_hash(user.password_hash, "admin"):
        flash('<a href="/user/info">You should change the default password!</a>', "warning")
        if tracer and span.is_recording():
            span.add_event("log", {
                "log.severity": "warning",
                "log.message": "You should change the default password!",
            })

    return render_template(
        'dashboards/cluster-metric.html.j2',
        cluster_metrics = cluster_metrics,
        cluster_events  = cluster_events
    )

##############################################################
## Workload Map
##############################################################

@dashboard_bp.route('/workload-map', methods=['GET', 'POST'])
@tracer.start_as_current_span("/workload-map")
@login_required
def workloads():
    span = trace.get_current_span()
    if tracer and span.is_recording():
        span.set_attribute("http.route", "/cluster-metrics")
        span.set_attribute("http.method", request.method)

    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        if tracer and span.is_recording():
            span.set_attribute("namespace.selected", request.form.get('ns_select'))


    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        nodes, edges = k8sGetPodMap(session['user_role'], user_token, session['ns_select'])
    else:
        nodes = []
        edges = []

    if tracer and span.is_recording():
        span.set_attribute("workloads.nodes", nodes)
        span.set_attribute("workloads.edges", edges)

    return render_template(
        'dashboards/workload-map.html.j2',
        namespaces = namespace_list,
        nodes = nodes,
        edges = edges,
    )