from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler
from kubedash.lib.k8s.server import k8sClientConfigGet

from .helper import GenerateIssuerData

logger = getLogger(__name__)

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
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=1)
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
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
    