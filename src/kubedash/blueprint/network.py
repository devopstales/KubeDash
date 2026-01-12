from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.network import (k8sIngressClassListGet, k8sIngressListGet,
                             k8sPodSelectorListGet, k8sServiceListGet)
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

network_bp = Blueprint("network", __name__, url_prefix="/network")
logger = get_logger()

##############################################################
# Network
##############################################################
## Ingress (Combined Ingress and IngressClass)
##############################################################

@network_bp.route("/ingress", methods=['GET', 'POST'])
@login_required
def ingresses():
    """
    Main Ingress view with tabs for Ingress and IngressClass resources.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')

    # Template now loads data via JavaScript from /api/v1/network/ingress and /api/v1/network/ingress-classes
    return render_template('network/ingress.html.j2')

@network_bp.route("/ingress-class", methods=['GET', 'POST'])
@login_required
def ingresses_class():
    """
    IngressClasses list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/network/ingress-classes
    return render_template('network/ingress-class.html.j2')

@network_bp.route('/ingress/data', methods=['GET', 'POST'])
@login_required
def ingresses_data():
    """
    Ingress detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        i_name = request.form.get('i_name')
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')

    # Template now loads data via JavaScript from /api/v1/network/ingress/<name>
    return render_template('network/ingress-data.html.j2')

@network_bp.route('/ingress-class/data', methods=['GET', 'POST'])
@login_required
def ingresses_class_data():
    """
    IngressClass detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        ic_name = request.form.get('ic_name')

    # Template now loads data via JavaScript from /api/v1/network/ingress-classes/<name>
    return render_template('network/ingress-class-data.html.j2')

##############################################################
# Service
##############################################################

@network_bp.route("/service", methods=['GET', 'POST'])
@login_required
def services():
    """
    Services list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Template now loads data via JavaScript from /api/v1/network/services
    return render_template('network/service.html.j2')

@network_bp.route('/service/data', methods=['GET', 'POST'])
@login_required
def services_data():
    """
    Service detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')

    # Template now loads data via JavaScript from /api/v1/network/services/<name>
    return render_template('network/service-data.html.j2')
