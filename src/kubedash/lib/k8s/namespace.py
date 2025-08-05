
from flask import flash
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode

from lib.helper_functions import ErrorHandler, trimAnnotations
from lib.components import cache, short_cache_time, long_cache_time

from . import logger, tracer
from .server import k8sClientConfigGet

##############################################################
## Kubernetes Namespace
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sListNamespaces(username_role, user_token):
    """List Kubernetes namespaces

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user

    Return:
        namespace_list (list): List of the namespace objects
        error (str): Error message if any
    """
    with tracer.start_as_current_span("list-namespaces") as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        k8sClientConfigGet(username_role, user_token)
        try:
            namespace_list = k8s_client.CoreV1Api().list_namespace(_request_timeout=1)
            return namespace_list, None
        except ApiException as error:
            if error.status != 404:
                ErrorHandler(logger, error, "list namespaces - %s " % error.status)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "%s list namespaces" % error))
            namespace_list = ""
            return namespace_list, error
        except Exception as error:
            ErrorHandler(logger, "CannotConnect", "k8sListNamespaces: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sListNamespaces: %s" % error))
            namespace_list = ""
            return namespace_list, "CannotConnect"

#@cache.memoize(timeout=long_cache_time)
def k8sNamespaceListGet(username_role, user_token):
    """Get the list of namespaces

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        namespace_list (list): List of the namespace names
        error (str): Error message if any
    """
    with tracer.start_as_current_span("get-namespace-list") as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        k8sClientConfigGet(username_role, user_token)
        namespace_list = []
        try:
            namespaces, error = k8sListNamespaces(username_role, user_token)
            if not error:
                for ns in namespaces.items:
                    namespace_list.append(ns.metadata.name)
                return namespace_list, None
            else:
                return namespace_list, error
        except Exception as error:
            ErrorHandler(logger, "CannotConnect", "k8sNamespaceListGet: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sNamespaceListGet: %s" % error))
            return namespace_list, "CannotConnect"
    
@cache.memoize(timeout=long_cache_time)
def k8sNamespacesGet(username_role, user_token):
    """Get the list of namespaces with their details

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        namespace_list (list): List of namespace objects with details
        error (str): Error message if any
    """
    with tracer.start_as_current_span("get-namespace") as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        k8sClientConfigGet(username_role, user_token)
        NAMESPACE_LIST = []
        try:
            namespaces, error = k8sListNamespaces(username_role, user_token)
            if error is None:
                for ns in namespaces.items:
                    NAMESPACE_DATA = {
                        "name": None,
                        "status": None,
                        "labels": list(),
                        "annotations": list(),
                        "created": None,
                        "app_service": {
                            "repository": None,
                            "pipeline": None
                        },
                    }
                    NAMESPACE_DATA['name'] = ns.metadata.name
                    NAMESPACE_DATA['status'] = ns.status.__dict__['_phase']
                    NAMESPACE_DATA['created'] = ns.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    if ns.metadata.labels:
                        NAMESPACE_DATA['labels'] = ns.metadata.labels
                    if ns.metadata.annotations:
                        NAMESPACE_DATA['annotations'] = trimAnnotations(ns.metadata.annotations)
                        # Extract repository and pipeline from annotations if they exist
                        if 'metadata.k8s.io/repository' in ns.metadata.annotations:
                            NAMESPACE_DATA['app_service']['repository'] = ns.metadata.annotations['metadata.k8s.io/repository']
                        if 'metadata.k8s.io/pipeline' in ns.metadata.annotations:
                            NAMESPACE_DATA['app_service']['pipeline'] = ns.metadata.annotations['metadata.k8s.io/pipeline']
                    NAMESPACE_LIST.append(NAMESPACE_DATA)
                    if tracer and span.is_recording():
                        span.set_attribute("namespace.name", ns.metadata.name)
                        span.set_attribute("namespace.role", ns.status.__dict__['_phase'])
                return NAMESPACE_LIST
            else:
                return NAMESPACE_LIST
        except Exception as error:
            ErrorHandler(logger, "CannotConnect", "k8sNamespacesGet: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sNamespacesGet: %s" % error))
            return NAMESPACE_LIST
    
def k8sNamespaceCreate(username_role, user_token, ns_name):
    """Create a namespace
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Name of the namespace to be created
        
    Returns:
        success (bool): True if namespace is created successfully, False otherwise
    """
    k8sClientConfigGet(username_role, user_token)
    pretty = 'true'
    field_manager = 'KubeDash'
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CoreV1Api(api_client)
        body = k8s_client.V1Namespace(
            api_version = "",
            kind = "",
            metadata = k8s_client.V1ObjectMeta(
                name = ns_name,
                labels = {
                    "created_by": field_manager
                }
            )
        )
    try:
        api_response = api_instance.create_namespace(body, pretty=pretty, field_manager=field_manager, _request_timeout=1)
        flash("Namespace Created Successfully", "success")
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "create namespace - %s " % error.status)
    except Exception as error:
        ERROR = "k8sNamespaceCreate: %s" % error
        ErrorHandler(logger, "error", ERROR)

def k8sNamespaceDelete(username_role, user_token, ns_name):
    """Delete a namespace
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Returns:
        success (bool): True if namespace is deleted successfully, False otherwise
    """
    k8sClientConfigGet(username_role, user_token)
    pretty = 'true'
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CoreV1Api(api_client)
    try:
        api_response = api_instance.delete_namespace(ns_name, pretty=pretty, _request_timeout=1)
        flash("Namespace Deleted Successfully", "success")
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "create namespace - %s " % error.status)
    except Exception as error:
        ERROR = "k8sNamespaceDelete: %s" % error
        ErrorHandler(logger, "error", ERROR)