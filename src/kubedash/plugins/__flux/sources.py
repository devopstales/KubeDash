
from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException
from lib.k8s.server import k8sClientConfigGet
from lib.helper_functions import ErrorHandler

logger = getLogger(__name__)
sourceGroup = 'source.toolkit.fluxcd.io'
sourceVersion = 'v1'

##############################################################
# bucketRepository
##############################################################

def FluxBucketRepositoryGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = sourceGroup
    api_version = sourceVersion
    api_plural = "buckets"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1, timeout_seconds=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxBucketRepositoryGet", "Cannot Connect to Kubernetes")
        return k8s_objects

##############################################################
# gitRepository
##############################################################

def FluxGitRepositoryGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = sourceGroup
    api_version = sourceVersion
    api_plural = "gitrepositories"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1, timeout_seconds=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxGitRepositoryGet", "Cannot Connect to Kubernetes")
        return k8s_objects

##############################################################
# helmChart
##############################################################

def FluxHelmChartGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = sourceGroup
    api_version = sourceVersion
    api_plural = "helmcharts"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1, timeout_seconds=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxHelmChartGet", "Cannot Connect to Kubernetes")
        return k8s_objects

##############################################################
# helmRepository
##############################################################

def FluxHelmRepositoryGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = sourceGroup
    api_version = sourceVersion
    api_plural = "helmrepositories"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1, timeout_seconds=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxHelmRepositoryGet", "Cannot Connect to Kubernetes")
        return k8s_objects

##############################################################
# ociRepository
##############################################################

def FluxOCIRepositoryGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = sourceGroup
    api_version = sourceVersion
    api_plural = "ocirepositories"
    k8s_objects = []
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1, timeout_seconds=1)
        return k8s_objects.get('items', [])
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxOCIRepositoryGet", "Cannot Connect to Kubernetes")
        return k8s_objects