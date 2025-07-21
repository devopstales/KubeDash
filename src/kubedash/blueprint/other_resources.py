from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.other import (
    k8sHPAListGet,
    k8sVPAListGet,
    k8sLimitRangeListGet,
    k8sPodDisruptionBudgetListGet, 
    k8sQuotaListGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

other_resources_bp = Blueprint("other_resources", __name__, url_prefix="/other-resource" )
logger = get_logger()

##############################################################
## VPA
##############################################################

@other_resources_bp.route("/vertical-pod-autoscaler", methods=['GET', 'POST'])
@login_required
def vpa():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        vpas = k8sVPAListGet(session['user_role'], user_token, session['ns_select'])
    else:
        vpas = []

    return render_template(
        'other-resources/vpa.html.j2',
        selected = selected,
        vpas = vpas,
        namespaces = namespace_list,
    )
    
@other_resources_bp.route('/vertical-pod-autoscaler/data', methods=['GET', 'POST'])
@login_required
def vpa_data():
    if request.method == 'POST':
        vpa_name = request.form.get('vpa_name')

        user_token = get_user_token(session)
        vpas = k8sVPAListGet(session['user_role'], user_token, session['ns_select'])
        vpa_data = None
        for vpa in vpas:
            if vpa["name"] == vpa_name:
                vpa_data = vpa

        if vpa_data:
            return render_template(
                'other-resources/vpa-data.html.j2',
                vpa_data = vpa_data,
            )
        else:
                flash("Cannot iterate VerticalPodAutoscalerList", "danger")
                return redirect(url_for('.vpa'))
    else:
        return redirect(url_for('auth.login'))
    

##############################################################
## HPA
##############################################################

@other_resources_bp.route("/horizontal-pod-autoscaler", methods=['GET', 'POST'])
@login_required
def hpa():
    selected = None

    if request.method == 'POST':
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        hpas = k8sHPAListGet(session['user_role'], user_token, session['ns_select'])
    else:
        hpas = []

    return render_template(
        'other-resources/hpa.html.j2',
        selected = selected,
        hpas = hpas,
        namespaces = namespace_list,
    )

@other_resources_bp.route('/horizontal-pod-autoscaler/data', methods=['GET', 'POST'])
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
                'other-resources/hpa-data.html.j2',
                hpa_data = hpa_data,
            )
        else:
                flash("Cannot iterate NamespaceList", "danger")
                return redirect(url_for('.hpa'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Pod Disruption Budget
##############################################################

@other_resources_bp.route("/pod-disruption-budget", methods=['GET', 'POST'])
@login_required
def pdp():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        pdps = k8sPodDisruptionBudgetListGet(session['user_role'], user_token, session['ns_select'])
    else:
        pdps = []

    return render_template(
        'other-resources/pod-disruption-budget.html.j2',
        selected = selected,
        pdps = pdps,
        namespaces = namespace_list,
    )

@other_resources_bp.route('/pod-disruption-budget/data', methods=['GET', 'POST'])
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
                'other-resources/pod-disruption-budget-data.html.j2',
                pdp_data = pdp_data,
            )
        else:
                flash("Cannot iterate PodDisruptionBudgetList", "danger")
                return redirect(url_for('.pdp'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
# Resource Quota
##############################################################

@other_resources_bp.route("/resource-quota", methods=['GET', 'POST'])
@login_required
def resource_quota():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        quotas = k8sQuotaListGet(session['user_role'], user_token, session['ns_select'])
    else:
        quotas = []

    return render_template(
        'other-resources/resource-quota.html.j2',
        selected = selected,
        quotas = quotas,
        namespaces = namespace_list,
    )

@other_resources_bp.route('/resource-quota/data', methods=['GET', 'POST'])
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
                'other-resources/resource-quota-data.html.j2',
                quota_data = quota_data,
            )
        else:
                flash("Cannot iterate ResourceQuotaList", "danger")
                return redirect(url_for('.resource_quota'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
# Limit Range
##############################################################

@other_resources_bp.route("/limit-range", methods=['GET', 'POST'])
@login_required
def limit_range():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select'):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        limits = k8sLimitRangeListGet(session['user_role'], user_token, session['ns_select'])
    else:
        limits = []
        
    return render_template(
        'other-resources/limit-range.html.j2',
        selected = selected,
        limits = limits,
        namespaces = namespace_list,
    )

@other_resources_bp.route('/limit-range/data', methods=['GET', 'POST'])
@login_required
def limit_range_data():
    if request.method == 'POST':
        limit_name = request.form.get('limit_name')

        user_token = get_user_token(session)
        other = k8sLimitRangeListGet(session['user_role'], user_token, session['ns_select'])
        quota_data = None
        for limit in other:
            if limit["name"] == limit_name:
                limit_data = limit

        if limit_data:
            return render_template(
                'other-resources/limit-range-data.html.j2',
                limit_data = limit_data,
            )
        else:
                flash("Cannot iterate Limit Range", "danger")
                return redirect(url_for('.resource_quota'))
    else:
        return redirect(url_for('auth.login'))
