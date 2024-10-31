from flask import Blueprint, request, session,render_template, redirect, url_for
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sHelmChartListGet
from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

helm = Blueprint("helm", __name__)
logger = get_logger(__name__.split(".")[1])

##############################################################
## Helm Charts
##############################################################

@helm.route('/charts', methods=['GET', 'POST'])
@login_required
def charts():
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')


    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, session['ns_select'])
    else:
        chart_list = []
        has_chart = None

    return render_template(
        'charts.html.j2',
        namespaces = namespace_list,
        has_chart = has_chart,
        chart_list = chart_list,
    )

@helm.route('/charts/data', methods=['GET', 'POST'])
@login_required
def charts_data():
    if request.method == 'POST':
        selected = request.form.get('selected')
        user_token = get_user_token(session)

        has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, session['ns_select'])
        chart_data = None
        chart_name = None
        if has_chart:
            for name, release in chart_list.items():
                if name == selected:
                    chart_name = name
                    chart_data = release

        return render_template(
            'chart-data.html.j2',
            chart_name = chart_name,
            chart_data = chart_data,
        )
    else:
        return redirect(url_for('helm.login'))
