#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.sso import get_user_token

from .functions import GatewayApiGetGatewayClass

##############################################################
## variables
##############################################################

gateway_api = Blueprint("gateway_api", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# Get Gateway API 1.0 Routes
##############################################################

@gateway_api.route("/gateway-class", methods=['GET', 'POST'])
@login_required
def gateway_class():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    gateway_classes = GatewayApiGetGatewayClass(session['user_role'], user_token)
    print(gateway_classes)

    return render_template(
        'gateway-classes.html.j2',
        gateway_classes = gateway_classes,
        selected = selected,
    )

    
