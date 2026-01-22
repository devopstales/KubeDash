#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

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
    """
    Helm charts list view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure and provides namespaces.
    """
    user_token = get_user_token(session)
    
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
    
    # Get namespace list for the dropdown
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    return render_template('helm-charts.html.j2', namespaces=namespaces)

@helm_bp.route('/helm-charts/data', methods=['GET'])
@login_required
def charts_data():
    """
    Helm chart data view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template('helm-chart-data.html.j2')
