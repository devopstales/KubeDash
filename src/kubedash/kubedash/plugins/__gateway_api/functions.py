from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler
from kubedash.lib.k8s.server import k8sClientConfigGet

logger = getLogger(__name__)

##############################################################
# Get Gateway API 1.0
##############################################################

"""BackendTLSPolicy - experimental"""
def GatewayApiGetBackendTLSPolicy(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1alpha2"
    api_plural = "backendtlspolicies"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")

"""GatewayClass - standard"""
def GatewayApiGetGatewayClass(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1"
    api_plural = "gatewayclasses"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=1)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "name": k8s_object['metadata']['name'],
                "controller": k8s_object['spec']['controllerName'],
                "status": k8s_object['status']['conditions'][-1]['status']
            }
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""Gateway - standard"""
def GatewayApiGetGateway(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1"
    api_plural = "gateways"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "name": k8s_object['metadata']['name'],
                "gateway-class": k8s_object['spec']['gatewayClassName'],
                "listeners": list(),
            }
            for listener in k8s_object['spec']['listeners']:
                k8s_object_data["listeners"].append(listener)
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""HTTPRoute - standard"""
def GatewayApiGetHTTPRoute(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1"
    api_plural = "httproutes"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "name": k8s_object['metadata']['name'],
                "gateways": list(),
                "statuses": k8s_object['status']['parents'],
                "rules": k8s_object['spec']['rules'],
            }
            if 'hostnames' in k8s_object['spec']:
                k8s_object_data['hostnames'] =  k8s_object['spec']['hostnames']
            for gateway in  k8s_object['spec']['parentRefs']:
                k8s_object_data["gateways"].append(gateway['name'])
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""ReferenceGrant - standard"""
def GatewayApiGetReferenceGrant(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1"
    api_plural = "referencegrants"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")

"""GRPCRoute - experimental"""
def GatewayApiGetGRPCRoute(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1alpha2"
    api_plural = "grpcroute"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")

"""TCPRoute - experimental"""
def GatewayApiGetTCPRoute(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1alpha2"
    api_plural = "tcproutes"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")

"""TLSRoute - experimental"""
def GatewayApiGetTLSRoute(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1alpha2"
    api_plural = "tlsroutes"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")

"""UDPRoute - experimental"""
def GatewayApiGetUDPRoute(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "gateway.networking.k8s.io"
    api_version = "v1alpha2"
    api_plural = "udproutes"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
