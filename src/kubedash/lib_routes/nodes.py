from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNodesListGet, k8sGetClusterMetric, k8sNodeGet, k8sGetNodeMetric

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

nodes = Blueprint("nodes", __name__)
logger = get_logger()

##############################################################
## Nodes
##############################################################

@nodes.route("/nodes", methods=['GET', 'POST'])
@login_required
def node_list():
    selected = None

    if request.method == 'POST':
        selected = request.form.get('selected')

    user_token = get_user_token(session)

    node_data = k8sNodesListGet(session['user_role'], user_token)
    cluster_metrics = k8sGetClusterMetric()

    return render_template(
        'nodes.html.j2',
        nodes = node_data,
        selected = selected,
        cluster_metrics = cluster_metrics,
    )

@nodes.route('/nodes/data', methods=['GET', 'POST'])
@login_required
def nodes_data():
    if request.method == 'POST':
        no_name = request.form.get('no_name')

        user_token = get_user_token(session)
        node_data = k8sNodeGet(session['user_role'], user_token, no_name)
        node_metrics = k8sGetNodeMetric(no_name)

        return render_template(
            'node-data.html.j2',
            no_name = no_name,
            node_data = node_data,
            node_metrics = node_metrics,
        )
    else:
        return redirect(url_for('nodes.login'))
