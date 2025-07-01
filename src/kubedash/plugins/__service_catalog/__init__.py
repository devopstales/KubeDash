#!/usr/bin/env python3

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger

##############################################################
## variables
##############################################################

service_catalog_bp = Blueprint("service_catalog", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

# Apps:
## Jira
## Confluence
## DefectDojo
## DependencyTrack
## SonarQube
## Nexus
## ArgoCD
## Grafana
## Prometheus
## Kibana
## Jaeger
## Harbor
## GitLab
## Jenkins
## Keycloak
## Tekton
## Kyverno

##############################################################
# Service Catalog Routes
##############################################################

#@cert_manager_bp.route('/cert-manager', methods=['GET', 'POST'])
#@login_required
#def cert_manager():
#    selected = None
#    user_token = get_user_token(session)
#
#    if request.method == 'POST':
#        if request.form.get('ns_select', None):
#            session['ns_select'] = request.form.get('ns_select')
#        selected = request.form.get('selected')
#
#    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
#    if not error:
#        issuer_list = IssuerGet(session['user_role'], user_token, session['ns_select'])
#        cluster_issuer_list = ClusterIssuerGet(session['user_role'], user_token)
#        certificate_request_list = CertificateRequestsGet(session['user_role'], user_token, session['ns_select'])
#        certificate_list = CertificatesGet(session['user_role'], user_token, session['ns_select'])
#    else:
#        issuer_list = list()
#        cluster_issuer_list = list()
#        certificate_request_list = list()
#        certificate_list = list()
#
#    return render_template(
#        'cert-manager.html.j2',
#        namespaces = namespace_list,
#        issuer_list = issuer_list,
#        cluster_issuer_list= cluster_issuer_list,
#        certificate_request_list = certificate_request_list,
#        certificate_list = certificate_list,
#        selected = selected,
#    )