from flask import Blueprint, render_template, session, flash, request
from flask_login import login_required
from werkzeug.security import check_password_hash

from opentelemetry import trace

from lib_functions.helper_functions import get_logger
from lib_functions.user import User
from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sGetClusterMetric, k8sNamespaceListGet, k8sGetPodMap

##############################################################
## Helpers
##############################################################

dashboard = Blueprint("dashboard", __name__)
logger = get_logger()

tracer = trace.get_tracer(__name__)

##############################################################
## Dashboard
##############################################################
## Cluster Metrics
##############################################################

@dashboard.route('/cluster-metrics')
@tracer.start_as_current_span("/cluster-metrics")
@login_required
def cluster_metrics():
    span = trace.get_current_span()

    cluster_metrics = k8sGetClusterMetric()
    username = session['username']
    user = User.query.filter_by(username="admin", user_type = "Local").first()

    if tracer and span.is_recording():
        span.set_attribute("http.route", "/cluster-metrics")
        span.set_attribute("http.method", request.method)
        span.set_attribute("user.name", session['username'])
        span.set_attribute("user.type", session['user_type'])
        span.set_attribute("user.role", session['user_role'])


    if username == "admin" and check_password_hash(user.password_hash, "admin"):
        flash('<a href="/profile">You should change the default password!</a>', "warning")
        if tracer and span.is_recording():
            span.add_event("log", {
                "log.severity": "warning",
                "log.message": "You should change the default password!",
            })

    return render_template(
        'cluster-metrics.html.j2',
        cluster_metrics = cluster_metrics
    )

@dashboard.route('/workload-map', methods=['GET', 'POST'])
@tracer.start_as_current_span("/workload-map")
@login_required
def workloads():
    span = trace.get_current_span()
    if tracer and span.is_recording():
        span.set_attribute("http.route", "/cluster-metrics")
        span.set_attribute("http.method", request.method)

    if request.method == 'POST':
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
        'workloads.html.j2',
        namespaces = namespace_list,
        nodes = nodes,
        edges = edges,
    )
