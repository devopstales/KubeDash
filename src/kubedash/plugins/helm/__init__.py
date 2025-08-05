#!/usr/bin/env python3

import re
from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token
from lib.components import cache, short_cache_time, long_cache_time

from .functions import k8sHelmChartListGet, k8sHelmChartReleaseGet

##############################################################
## variables
##############################################################

helm_bp = Blueprint("helm", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
## Helm Charts routes
##############################################################

@helm_bp.route('/helm-chart', methods=['GET', 'POST'])
@login_required
def charts():   
    user_token = get_user_token(session)
    selected = None
    
    if request.method == 'POST':
        selected = request.form.get('selected')
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
        selected = selected,
        has_chart = has_chart,
        chart_list = chart_list,
    )

@helm_bp.route('/helm-charts/data', methods=['GET', 'POST'])
@login_required
def charts_data():
    if request.method == 'POST':
        helm_release_name = request.form.get('helm_release_name')
        helm_release_version = request.form.get('helm_release_version')
        user_token = get_user_token(session)

        chart_data = k8sHelmChartReleaseGet(
            session['user_role'], 
            user_token, 
            session['ns_select'], 
            helm_release_name, 
            helm_release_version
        )

        return render_template(
            'helm-chart-data.html.j2',
            chart_name = helm_release_name,
            chart_data = chart_data,
        )
    else:
        return redirect(url_for('auth.login'))
