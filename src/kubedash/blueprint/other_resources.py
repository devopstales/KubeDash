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
    """
    VPAs list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/vpa
    return render_template('other-resources/vpa.html.j2')
    
@other_resources_bp.route('/vertical-pod-autoscaler/data', methods=['GET', 'POST'])
@login_required
def vpa_data():
    """
    VPA detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/vpa/<name>
    return render_template('other-resources/vpa-data.html.j2')
    

##############################################################
## HPA
##############################################################

@other_resources_bp.route("/horizontal-pod-autoscaler", methods=['GET', 'POST'])
@login_required
def hpa():
    """
    HPAs list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/hpa
    return render_template('other-resources/hpa.html.j2')

@other_resources_bp.route('/horizontal-pod-autoscaler/data', methods=['GET', 'POST'])
@login_required
def hpa_data():
    """
    HPA detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/hpa/<name>
    return render_template('other-resources/hpa-data.html.j2')

##############################################################
## Pod Disruption Budget
##############################################################

@other_resources_bp.route("/pod-disruption-budget", methods=['GET', 'POST'])
@login_required
def pdp():
    """
    Pod Disruption Budgets list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/pdb
    return render_template('other-resources/pod-disruption-budget.html.j2')

@other_resources_bp.route('/pod-disruption-budget/data', methods=['GET', 'POST'])
@login_required
def pdp_data():
    """
    Pod Disruption Budget detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/pdb/<name>
    return render_template('other-resources/pod-disruption-budget-data.html.j2')

##############################################################
# Resource Quota
##############################################################

@other_resources_bp.route("/resource-quota", methods=['GET', 'POST'])
@login_required
def resource_quota():
    """
    Resource Quotas list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/quotas
    return render_template('other-resources/resource-quota.html.j2')

@other_resources_bp.route('/resource-quota/data', methods=['GET', 'POST'])
@login_required
def resource_quota_data():
    """
    Resource Quota detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/quotas/<name>
    return render_template('other-resources/resource-quota-data.html.j2')

##############################################################
# Limit Range
##############################################################

@other_resources_bp.route("/limit-range", methods=['GET', 'POST'])
@login_required
def limit_range():
    """
    Limit Ranges list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/other-resources/limit-ranges
    return render_template('other-resources/limit-range.html.j2')

@other_resources_bp.route('/limit-range/data', methods=['GET', 'POST'])
@login_required
def limit_range_data():
    """
    Limit Range detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/other-resources/limit-ranges/<name>
    return render_template('other-resources/limit-range-data.html.j2')
