from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException
from lib.k8s.server import k8sClientConfigGet
from lib.helper_functions import ErrorHandler, GenerateIssuerData

logger = getLogger(__name__)
kustomizationGroup = 'kustomize.toolkit.fluxcd.io'
kustomizationVersion = 'v1'

##############################################################
# kustomization
##############################################################

def FluxKustomizationGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = kustomizationGroup
    api_version = kustomizationVersion
    api_plural = "kustomizations"
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        return k8s_objects
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_objects
    except Exception as error:
        ErrorHandler(logger, "FluxKustomizationGet", "Cannot Connect to Kubernetes")
        return k8s_objects