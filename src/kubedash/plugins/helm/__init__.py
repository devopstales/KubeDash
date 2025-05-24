#!/usr/bin/env python3

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .functions import k8sHelmChartListGet

##############################################################
## variables
##############################################################

helm = Blueprint("helm", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
## Helm Charts routes
##############################################################

@helm.route('/helm-chart', methods=['GET', 'POST'])
@login_required
def charts():
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')


    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, session['ns_select'])
    else:
        chart_list = []
        has_chart = None

    return render_template(
        'helm-charts.html.j2',
        namespaces = namespace_list,
        has_chart = has_chart,
        chart_list = chart_list,
    )

@helm.route('/helm-charts/data', methods=['GET', 'POST'])
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
            'helm-chart-data.html.j2',
            chart_name = chart_name,
            chart_data = chart_data,
        )
    else:
        return redirect(url_for('auth.login'))
