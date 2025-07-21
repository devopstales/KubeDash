from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations
from lib.components import cache, short_cache_time, long_cache_time

from . import logger
from .server import k8sClientConfigGet

##############################################################
## Ingresses Class
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sIngressClassListGet(username_role, user_token):
    """Get the list of IngressClass

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        ingress_class_list (list): List of IngressClass objects
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    ING_LIST = list()
    try:
        ingress_class_list = k8s_client.NetworkingV1Api().list_ingress_class(_request_timeout=1, timeout_seconds=1)
        for ic in ingress_class_list.items:
            ING_INFO = {
                "name": ic.metadata.name,
                "created": ic.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(ic.metadata.annotations),
                "labels": ic.metadata.labels,
                "controller": ic.spec.controller,
            }
            if ic.spec.parameters:
                ING_INFO["parameters"] = ic.spec.parameters.to_dict()
            ING_LIST.append(ING_INFO)
        return ING_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get ingress class list - %s" % error.status)
        return ING_LIST
    except Exception as error:
        ERROR = "k8sIngressClassListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return ING_LIST

##############################################################
## Ingress
##############################################################

@cache.memoize(timeout=short_cache_time)
def k8sIngressListGet(username_role, user_token, ns):
    """Get the list of Ingresses for a given namespace

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Return:
        ingress_list (list): List of Ingress objects
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    ING_LIST = list()
    try:
        ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(ns, _request_timeout=1, timeout_seconds=1)
        for ingress in ingress_list.items:
            ig = ingress.status.load_balancer.ingress
            rules = list()
            for rule in ingress.spec.rules:
                for r in rule.http.paths:
                    rules.append(r.to_dict())
            ING_INFO = {
                "name": ingress.metadata.name,
                "ingressClass": ingress.spec.ingress_class_name,
                "rules": rules,
                "created": ingress.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(ingress.metadata.annotations),
                "labels": ingress.metadata.labels,
                "tls": ingress.spec.tls,
                "status": ingress.status,
            }
            if ig:
                ING_INFO["endpoint"] = ig[0].ip
            if rules:
                HOSTS = list()
                for rule in ingress.spec.rules:
                    HOSTS.append(rule.host)
                ING_INFO["hosts"] = HOSTS
            ING_LIST.append(ING_INFO)
        return ING_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get ingress list - %s" % error.status)
        return ING_LIST
    except Exception as error:
        ERROR = "k8sIngressListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return ING_LIST
    
##############################################################
# Service
##############################################################

@cache.memoize(timeout=short_cache_time)
def k8sServiceListGet(username_role, user_token, ns):
    """Get the list of Services for a given namespace

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace of the
        
    Return:
        service_list (list): List of Service objects
        error (str): Error message if any
    """  
    k8sClientConfigGet(username_role, user_token)
    SERVICE_LIST = list()
    try:
        service_list = k8s_client.CoreV1Api().list_namespaced_service(ns, _request_timeout=1, timeout_seconds=1)
        for service in service_list.items:
            SERVICE_INFO = {
                "name": service.metadata.name,
                "type": service.spec.type,
                "created": service.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(service.metadata.annotations),
                "labels": service.metadata.labels,
                "selector": service.spec.selector,
                "ports": service.spec.ports,
                "cluster_ip": service.spec.cluster_ip,
            }
            if service.spec.type == "LoadBalancer":
                SERVICE_INFO["external_ip"] = service.status.load_balancer.ingress[0].ip
            else:
                SERVICE_INFO["external_ip"] = None
            SERVICE_LIST.append(SERVICE_INFO)
        return SERVICE_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get service list - %s" % error.status)
        return SERVICE_LIST
    except Exception as error:
        ERROR = "k8sServiceListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return SERVICE_LIST

@cache.memoize(timeout=long_cache_time)
def k8sPodSelectorListGet(username_role, user_token, ns, selectors):
    """Get the list of Pods based on a label selector

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace of the pods
        selectors (dict): Dictionary of label selectors
        
    Return:
        pod_list (list): List of Pod objects
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    POD_LIST = list()
    label_selector = ""
    for i, (key, value) in enumerate(selectors.items()):
        if i == len(selectors) - 1:
            label_selector  = label_selector + f"{key}={value}"
        else:
            label_selector  = label_selector + f"{key}={value},"
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns, label_selector=label_selector, _request_timeout=1, timeout_seconds=1)
        for pod in pod_list.items:
            POD_INFO = {
                "status": pod.status.phase,
                "name": pod.metadata.name,
                "pod_ip": pod.status.pod_ip,
                "node_name": pod.spec.node_name,
            }
            if pod.metadata.owner_references:
                for owner in pod.metadata.owner_references:
                    POD_INFO['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            POD_LIST.append(POD_INFO)
        return POD_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get pod selector list - %s" % error.status)
        return POD_LIST
    except Exception as error:
        ERROR = "k8sPodSelectorListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return POD_LIST
