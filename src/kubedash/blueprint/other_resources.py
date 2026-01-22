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
    k8sQuotaListGet,
    k8sRuntimeClassListGet)
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

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/vpa
    return render_template('other-resources/vpa.html.j2', namespaces=namespaces)
    
@other_resources_bp.route('/vertical-pod-autoscaler/data', methods=['GET', 'POST'])
@login_required
def vpa_data():
    """
    VPA detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        vpa_name = request.form.get('vpa_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if vpa_name:
            params['vpa_name'] = vpa_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.vpa_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/vpa/<name>
    return render_template('other-resources/vpa-data.html.j2', namespaces=namespaces)
    

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

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/hpa
    return render_template('other-resources/hpa.html.j2', namespaces=namespaces)

@other_resources_bp.route('/horizontal-pod-autoscaler/data', methods=['GET', 'POST'])
@login_required
def hpa_data():
    """
    HPA detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        hpa_name = request.form.get('hpa_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if hpa_name:
            params['hpa_name'] = hpa_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.hpa_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/hpa/<name>
    return render_template('other-resources/hpa-data.html.j2', namespaces=namespaces)

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

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/pdb
    return render_template('other-resources/pod-disruption-budget.html.j2', namespaces=namespaces)

@other_resources_bp.route('/pod-disruption-budget/data', methods=['GET', 'POST'])
@login_required
def pdp_data():
    """
    Pod Disruption Budget detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        pdp_name = request.form.get('pdp_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if pdp_name:
            params['pdp_name'] = pdp_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.pdp_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/pdb/<name>
    return render_template('other-resources/pod-disruption-budget-data.html.j2', namespaces=namespaces)

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

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/quotas
    return render_template('other-resources/resource-quota.html.j2', namespaces=namespaces)

@other_resources_bp.route('/resource-quota/data', methods=['GET', 'POST'])
@login_required
def resource_quota_data():
    """
    Resource Quota detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        quota_name = request.form.get('quota_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if quota_name:
            params['quota_name'] = quota_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.resource_quota_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/quotas/<name>
    return render_template('other-resources/resource-quota-data.html.j2', namespaces=namespaces)

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

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/limit-ranges
    return render_template('other-resources/limit-range.html.j2', namespaces=namespaces)

@other_resources_bp.route('/limit-range/data', methods=['GET', 'POST'])
@login_required
def limit_range_data():
    """
    Limit Range detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        limit_name = request.form.get('limit_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if limit_name:
            params['limit_name'] = limit_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.limit_range_data', **params))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/limit-ranges/<name>
    return render_template('other-resources/limit-range-data.html.j2', namespaces=namespaces)

##############################################################
# Runtime Class
##############################################################

@other_resources_bp.route("/runtimeclass", methods=['GET', 'POST'])
@login_required
def runtimeclass():
    """
    Runtime Classes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Get namespaces for topbar selector (RuntimeClass is cluster-scoped, but namespace dropdown is available for consistency)
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/runtime-classes
    return render_template('other-resources/runtimeclass.html.j2', namespaces=namespaces)

@other_resources_bp.route('/runtimeclass/data', methods=['GET', 'POST'])
@login_required
def runtimeclass_data():
    """
    Runtime Class detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests (from form submission) - redirect to GET with parameters
    if request.method == 'POST':
        rc_name = request.form.get('rc_name')
        ns_select = request.form.get('ns_select')
        
        # Build query parameters
        params = {}
        if rc_name:
            params['rc_name'] = rc_name
        if ns_select:
            params['namespace'] = ns_select
        
        # Redirect to GET request with query parameters
        return redirect(url_for('other_resources.runtimeclass_data', **params))
    
    # Get namespaces for topbar selector (RuntimeClass is cluster-scoped, but namespace dropdown is available for consistency)
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/other-resources/runtime-classes/<name>
    return render_template('other-resources/runtimeclass-data.html.j2', namespaces=namespaces)
