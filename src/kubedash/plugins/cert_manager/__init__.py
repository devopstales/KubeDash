#!/usr/bin/env python3

import ast

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.sso import get_user_token

from .functions import (CertificateRequestsGet, CertificatesGet,
                        ClusterIssuerGet, IssuerGet)

##############################################################
## variables
##############################################################

cert_manager_bp = Blueprint("cert_manager", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# Cert-Manager Routes
##############################################################

@cert_manager_bp.route('/cert-manager', methods=['GET', 'POST'])
@login_required
def cert_manager():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        issuer_list = IssuerGet(session['user_role'], user_token, session['ns_select'])
        cluster_issuer_list = ClusterIssuerGet(session['user_role'], user_token)
        certificate_request_list = CertificateRequestsGet(session['user_role'], user_token, session['ns_select'])
        certificate_list = CertificatesGet(session['user_role'], user_token, session['ns_select'])
    else:
        issuer_list = list()
        cluster_issuer_list = list()
        certificate_request_list = list()
        certificate_list = list()

    return render_template(
        'cert-manager.html.j2',
        namespaces = namespace_list,
        issuer_list = issuer_list,
        cluster_issuer_list= cluster_issuer_list,
        certificate_request_list = certificate_request_list,
        certificate_list = certificate_list,
        selected = selected,
    )

@cert_manager_bp.route('/cert-manager/data', methods=['GET', 'POST'])
@login_required
def cert_manager_data():
    selected = None

    if request.method == 'POST':
        selected = request.form.get('selected')
        user_token = get_user_token(session)
        object_data_str = request.form.get('object_data')
        object_type = request.form.get('object_type')
        print(object_data_str)

        return render_template(
            'cert-manager-data.html.j2',
            selected = selected,
            object_data = ast.literal_eval(object_data_str),
            object_type = object_type,
        )
    else:
        return redirect(url_for('auth.login'))
