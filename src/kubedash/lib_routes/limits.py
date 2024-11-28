from flask import Blueprint, request, session,render_template, redirect, url_for, flash
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sHPAListGet, k8sPodDisruptionBudgetListGet, \
    k8sQuotaListGet, k8sLimitRangeListGet

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

limits = Blueprint("limits", __name__)
logger = get_logger()

##############################################################
## HPA
##############################################################

@limits.route("/horizontal_pod_autoscaler", methods=['GET', 'POST'])
@login_required
def hpa():
    selected = None

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        hpas = k8sHPAListGet(session['user_role'], user_token, session['ns_select'])
    else:
        hpas = []

    return render_template(
        'hpa.html.j2',
        selected = selected,
        hpas = hpas,
        namespaces = namespace_list,
    )

@limits.route('/horizontal_pod_autoscaler/data', methods=['GET', 'POST'])
@login_required
def hpa_data():
    if request.method == 'POST':
        hpa_name = request.form.get('hpa_name')
        user_token = get_user_token(session)

        hpas = k8sHPAListGet(session['user_role'], user_token, session['ns_select'])
        hpa_data = None
        for hpa in hpas:
            if hpa["name"] == hpa_name:
                hpa_data = hpa

        if hpa_data:
            return render_template(
                'hpa-data.html.j2',
                hpa_data = hpa_data,
            )
        else:
                flash("Cannot iterate NamespaceList", "danger")
                return redirect(url_for('limits.hpa'))
    else:
        return redirect(url_for('limits.login'))

##############################################################
## Pod Disruption Budget
##############################################################

@limits.route("/pod_disruption_budget", methods=['GET', 'POST'])
@login_required
def pdp():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        pdps = k8sPodDisruptionBudgetListGet(session['user_role'], user_token, session['ns_select'])
    else:
        pdps = []

    return render_template(
        'pdp.html.j2',
        selected = selected,
        pdps = pdps,
        namespaces = namespace_list,
    )

@limits.route('/pod_disruption_budget/data', methods=['GET', 'POST'])
@login_required
def pdp_data():
    if request.method == 'POST':
        pdp_name = request.form.get('pdp_name')

        user_token = get_user_token(session)
        pdps = k8sPodDisruptionBudgetListGet(session['user_role'], user_token, session['ns_select'])
        pdp_data = None
        for pdp in pdps:
            if pdp["name"] == pdp_name:
                pdp_data = pdp

        if pdp_data:
            return render_template(
                'pdp-data.html.j2',
                pdp_data = pdp_data,
            )
        else:
                flash("Cannot iterate PodDisruptionBudgetList", "danger")
                return redirect(url_for('limits.pdp'))
    else:
        return redirect(url_for('limits.login'))

##############################################################
# Resource Quota
##############################################################

@limits.route("/resource_quota", methods=['GET', 'POST'])
@login_required
def resource_quota():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        quotas = k8sQuotaListGet(session['user_role'], user_token, session['ns_select'])
    else:
        quotas = []

    return render_template(
        'resource_quota.html.j2',
        selected = selected,
        quotas = quotas,
        namespaces = namespace_list,
    )

@limits.route('/resource_quota/data', methods=['GET', 'POST'])
@login_required
def resource_quota_data():
    if request.method == 'POST':
        quota_name = request.form.get('quota_name')

        user_token = get_user_token(session)
        quotas = k8sQuotaListGet(session['user_role'], user_token, session['ns_select'])
        quota_data = None
        for quota in quotas:
            if quota["name"] == quota_name:
                quota_data = quota

        if quota_data:
            return render_template(
                'resource_quota-data.html.j2',
                quota_data = quota_data,
            )
        else:
                flash("Cannot iterate ResourceQuotaList", "danger")
                return redirect(url_for('limits.resource_quota'))
    else:
        return redirect(url_for('limits.login'))

##############################################################
# Limit Range
##############################################################

@limits.route("/limit_range", methods=['GET', 'POST'])
@login_required
def limit_range():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        limits = k8sLimitRangeListGet(session['user_role'], user_token, session['ns_select'])
    else:
        limits = []

    return render_template(
        'limit_range.html.j2',
        selected = selected,
        limits = limits,
        namespaces = namespace_list,
    )

@limits.route('/limit_range/data', methods=['GET', 'POST'])
@login_required
def limit_range_data():
    if request.method == 'POST':
        limit_name = request.form.get('limit_name')

        user_token = get_user_token(session)
        limits = k8sLimitRangeListGet(session['user_role'], user_token, session['ns_select'])
        quota_data = None
        for limit in limits:
            if limit["name"] == limit_name:
                limit_data = limit

        if limit_data:
            return render_template(
                'limit_range-data.html.j2',
                limit_data = limit_data,
            )
        else:
                flash("Cannot iterate Limit Range", "danger")
                return redirect(url_for('limits.resource_quota'))
    else:
        return redirect(url_for('limits.login'))
