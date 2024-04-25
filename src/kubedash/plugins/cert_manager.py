#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required
from kubernetes.client.rest import ApiException
import kubernetes.client as k8s_client
from functions.k8s import k8sClientConfigGet
from functions.helper_functions import get_logger, ErrorHandler
from functions.sso import get_user_token
from functions.k8s import k8sNamespaceListGet
import ast

##############################################################
## Helper Functions
##############################################################

cm_routes = Blueprint("cert_manager", __name__)
logger = get_logger(__name__)

def GenerateIssuerData(k8s_objects, k8s_object_list):
    for k8s_object in k8s_objects['items']:
        k8s_object_data = {
            "name": k8s_object['metadata']['name'],
            "status": k8s_object['status']['conditions'][-1]['status'],
            "reason": k8s_object['status']['conditions'][-1]['reason'],
        }
        if 'message' in k8s_object['status']['conditions'][-1]:
            k8s_object_data["message"] = k8s_object['status']['conditions'][-1]['message'].replace('"', '')
        if 'selfSigned' in k8s_object['spec']:
            k8s_object_data['type'] = "Sel Signed"
        if 'ca' in k8s_object['spec']:
            k8s_object_data['type'] = "CA"
            k8s_object_data['issuer_data'] = {
                "secret": k8s_object['spec']['ca']['secretName'],
            }
        if 'acme' in k8s_object['spec']:
            k8s_object_data['type'] = "ACME"
            k8s_object_data['issuer_data'] = {
                "email": None,
                "server": k8s_object['spec']['acme']['server'],
                "challenges": list(),
            }
            if 'email' in k8s_object['spec']['acme']:
                k8s_object_data['issuer_data']['email'] = k8s_object['spec']['acme']['email']
            for challenge in k8s_object['spec']['acme']['solvers']:
                if 'http01' in challenge:
                    k8s_object_data['issuer_data']['challenges'].append('http01')
                elif 'dns01' in challenge:
                    k8s_object_data['issuer_data']['challenges'].append('dns01')
        if 'vault' in k8s_object['spec']:
            k8s_object_data['type'] = "Vault"
            k8s_object_data['issuer_data'] = {
                "path": k8s_object['spec']['vault']['path'],
                "server": k8s_object['spec']['vault']['server'],
                "auth": None,
            }
            if 'appRole' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'App Role'
                k8s_object_data['issuer_data'] = {
                    "roleId": k8s_object['spec']['vault']['auth']['appRole']['roleId'],
                    "secret": k8s_object['spec']['vault']['auth']['appRole']['secretRef']['name'],
                }
            if 'tokenSecretRef' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'Token'
                k8s_object_data['issuer_data'] = {
                    "secret": k8s_object['spec']['vault']['auth']['tokenSecretRef']['name'],
                }
            if 'kubernetes' in  k8s_object['spec']['vault']['auth']:
                k8s_object_data['issuer_data']['auth'] = 'Kubernetes'
                k8s_object_data['issuer_data'] = {
                    "role": k8s_object['spec']['vault']['auth']['kubernetes']['role'],
                    'serviceA': k8s_object['spec']['vault']['auth']['kubernetes']['serviceAccountRef']['name'],
                }
        # Venafi
        k8s_object_list.append(k8s_object_data)
    return k8s_object_list

##############################################################
# Cert-Manager Functions
##############################################################

"""Issuer"""
def IssuerGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "cert-manager.io"
    api_version = "v1"
    api_plural = "issuers"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        k8s_object_list = GenerateIssuerData(k8s_objects, k8s_object_list)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "IssuerGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""Cluster Issuer"""
def ClusterIssuerGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    api_group = "cert-manager.io"
    api_version = "v1"
    api_plural = "clusterissuers"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=5)
        k8s_object_list = GenerateIssuerData(k8s_objects, k8s_object_list)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ClusterIssuerGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""Certificaterequests"""
def CertificateRequestsGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "cert-manager.io"
    api_version = "v1"
    api_plural = "certificaterequests"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "name": k8s_object['metadata']['name'],
                "status": k8s_object['status']['conditions'][-1]['status'],
                "reason": k8s_object['status']['conditions'][-1]['reason'],
                "message": k8s_object['status']['conditions'][-1]['message'],
                "issuer": k8s_object['spec']['issuerRef']['name'],
                "issuer_type": k8s_object['spec']['issuerRef']['kind'],
            }
            if 'ownerReferences' in k8s_object['metadata']:
                k8s_object_data["owner"] = k8s_object['metadata']['ownerReferences'][-1]['name']
                k8s_object_data["owner_type"] = k8s_object['metadata']['ownerReferences'][-1]['kind'] # certificate
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "CertificateRequestsGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""certificates"""
def CertificatesGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "cert-manager.io"
    api_version = "v1"
    api_plural = "certificates"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "name": k8s_object['metadata']['name'],
                "status": k8s_object['status']['conditions'][-1]['status'],
                "reason": k8s_object['status']['conditions'][-1]['reason'],
                "message": k8s_object['status']['conditions'][-1]['message'],
                "cert_valid": k8s_object['status']['notAfter'],
                "secret_name": k8s_object['spec']['secretName'],
                "hostnames": list(),
            }
            if 'ownerReferences' in k8s_object['metadata']:
                k8s_object_data["owner"] = k8s_object['metadata']['ownerReferences'][-1]['name']
                k8s_object_data["owner_type"] = k8s_object['metadata']['ownerReferences'][-1]['kind'] # certificate
            for host in k8s_object['spec']['dnsNames']:
                k8s_object_data['hostnames'].append(host)
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "CertificatesGet", "Cannot Connect to Kubernetes")
        return k8s_object_list
    
##############################################################
# Cert-Manager Routes
##############################################################

@cm_routes.route('/cert-manager', methods=['GET', 'POST'])
@login_required
def cert_manager():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
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

@cm_routes.route('/cert-manager/data', methods=['GET', 'POST'])
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
        return redirect(url_for('routes.login'))