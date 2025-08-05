from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException
from lib.k8s.server import k8sClientConfigGet
from lib.helper_functions import ErrorHandler

logger = getLogger(__name__)
notificationGroup = 'notification.toolkit.fluxcd.io'
notificationVersion = 'v1beta3'

##############################################################
# alertNotification
##############################################################

def FluxAlertNotificationGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = notificationGroup
    api_version = notificationVersion
    api_plural = "alerts"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxAlertNotificationGet", "Cannot Connect to Kubernetes")
        return k8s_objects

##############################################################
# providerNotification
#############################################################

def FluxProviderNotificationGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = notificationGroup
    api_version = notificationVersion
    api_plural = "providers"
    k8s_object_list = list()
    try:
        k8s_object_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        return k8s_object_list.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "FluxProviderNotificationGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

##############################################################
# receiverNotification
#############################################################

def FluxReceiverNotificationGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = notificationGroup
    api_version = notificationVersion
    api_plural = "receivers"
    k8s_object_list = list()
    try:
        k8s_object_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        return k8s_object_list.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "FluxReceiverNotificationGet", "Cannot Connect to Kubernetes")
        return k8s_object_list