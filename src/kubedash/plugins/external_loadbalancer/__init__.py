#!/usr/bin/env python3

import ast

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .helper import (bgpadvertisementsTest, bgppeersTest, ipaddresspoolTest,
                     l2advertisementsTest)

##############################################################
## variables
##############################################################

external_loadbalancer_bp = Blueprint("external_loadbalancer", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# exLB Routes
##############################################################

@external_loadbalancer_bp.route('/external-loadbalancer', methods=['GET', 'POST'])
@login_required
def external_loadbalancer():
    selected = None
    selected_type = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        selected_type = request.form.get('object_type')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        ipaddresspool_list = ipaddresspoolTest(session['ns_select'])
        l2advertisement_list = l2advertisementsTest(session['ns_select'])
        bgpadvertisement_list = bgpadvertisementsTest(session['ns_select'])
        bgppeers_list = bgppeersTest(session['ns_select'])

    else:
        bgppeers_list = list()
        ipaddresspool_list = list()
        l2advertisement_list = list()
        bgpadvertisement_list = list()

    return render_template(
        'external-loadbalancer.html.j2',
        namespaces = namespace_list,
        ipaddresspool_list=ipaddresspool_list,
        l2advertisement_list=l2advertisement_list,
        bgpadvertisement_list=bgpadvertisement_list,
        bgppeers_list=bgppeers_list,
        selected=selected,
        selected_type=selected_type,
    )

@external_loadbalancer_bp.route('/external-loadbalancer/data', methods=['GET', 'POST'])
@login_required
def external_loadbalancer_data():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        object_type = request.form.get('object_type')
        object_data_str = request.form.get('object_data')


        return render_template(
            'external-loadbalancer-data.html.j2',
            object_type=object_type,
            object_data=ast.literal_eval(object_data_str),
            selected=selected,
        )

    else:
        return redirect(url_for('auth.login'))
