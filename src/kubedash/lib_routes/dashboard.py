from flask import Blueprint, render_template, session, flash, request
from flask_login import login_required
from werkzeug.security import check_password_hash

from opentelemetry import trace

from lib_functions.helper_functions import get_logger
from lib_functions.user import User
from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sGetClusterMetric, k8sNamespaceListGet, k8sGetPodMap

#from lib_functions.opentelemetry import tracer
from contextlib import nullcontext

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
@login_required
def cluster_metrics():
    with tracer.start_as_current_span("/cluster-metrics", 
        attributes={ 
            "http.route": "/cluster-metrics",
            "http.method": request.method,
        }
    ) as span:
        cluster_metrics = k8sGetClusterMetric()
        username = session['username']
        user = User.query.filter_by(username="admin", user_type = "Local").first()
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
@login_required
def workloads():
    with tracer.start_as_current_span("/workload-map", 
        attributes={ 
            "http.route": "/workload-map",
            "http.method": request.method,
        }
    ) as span:
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
