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
        ingress_class_list = k8s_client.NetworkingV1Api().list_ingress_class(_request_timeout=1)
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

def serialize_ingress_status(status):
    """
    Convert V1IngressStatus object to dictionary for JSON serialization.
    
    Args:
        status: V1IngressStatus object or None
        
    Returns:
        dict: Serialized status dictionary or None
    """
    if not status:
        return None
    
    if hasattr(status, 'to_dict'):
        # Use to_dict() if available (Kubernetes client library method)
        return status.to_dict()
    elif isinstance(status, dict):
        # Already a dict
        return status
    else:
        # Manual conversion for V1IngressStatus objects
        status_dict = {}
        if hasattr(status, 'load_balancer') and status.load_balancer:
            if hasattr(status.load_balancer, 'ingress') and status.load_balancer.ingress:
                status_dict['load_balancer'] = {
                    'ingress': [
                        {
                            'ip': getattr(ing, 'ip', None),
                            'hostname': getattr(ing, 'hostname', None)
                        }
                        for ing in status.load_balancer.ingress
                    ]
                }
        return status_dict if status_dict else None

def serialize_ingress_tls(tls):
    """
    Convert V1IngressTLS objects to dictionaries for JSON serialization.
    
    Args:
        tls: List of V1IngressTLS objects or None
        
    Returns:
        list: List of serialized TLS dictionaries
    """
    if not tls:
        return []
    
    serialized_tls = []
    for tls_item in tls:
        if hasattr(tls_item, 'to_dict'):
            # Use to_dict() if available
            tls_dict = tls_item.to_dict()
            serialized_tls.append(tls_dict)
        elif isinstance(tls_item, dict):
            # Already a dict
            serialized_tls.append(tls_item)
        else:
            # Manual conversion
            tls_dict = {
                'hosts': list(getattr(tls_item, 'hosts', [])) if hasattr(tls_item, 'hosts') else [],
                'secret_name': getattr(tls_item, 'secret_name', None) or getattr(tls_item, 'secretName', None)
            }
            # Remove None values
            tls_dict = {k: v for k, v in tls_dict.items() if v is not None}
            serialized_tls.append(tls_dict)
    return serialized_tls

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
        ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(ns, _request_timeout=1)
        for ingress in ingress_list.items:
            ig = ingress.status.load_balancer.ingress if ingress.status.load_balancer else None
            rules = list()
            for rule in ingress.spec.rules:
                for r in rule.http.paths:
                    rules.append(r.to_dict())
            
            # Serialize status and TLS
            serialized_status = serialize_ingress_status(ingress.status)
            serialized_tls = serialize_ingress_tls(ingress.spec.tls) if ingress.spec.tls else []
            
            ING_INFO = {
                "name": ingress.metadata.name,
                "ingressClass": ingress.spec.ingress_class_name,
                "rules": rules,
                "created": ingress.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(ingress.metadata.annotations),
                "labels": ingress.metadata.labels,
                "tls": serialized_tls,
                "status": serialized_status,
            }
            if ig and len(ig) > 0:
                ING_INFO["endpoint"] = ig[0].ip if hasattr(ig[0], 'ip') else None
            if rules:
                HOSTS = list()
                for rule in ingress.spec.rules:
                    if rule.host:
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

def serialize_service_ports(ports):
    """
    Convert V1ServicePort objects to dictionaries for JSON serialization.
    
    Args:
        ports: List of V1ServicePort objects or None
        
    Returns:
        list: List of serialized port dictionaries
    """
    if not ports:
        return []
    
    serialized_ports = []
    for port in ports:
        if hasattr(port, 'to_dict'):
            # Use to_dict() if available (Kubernetes client library method)
            port_dict = port.to_dict()
            # Ensure consistent naming (camelCase for JSON)
            serialized_port = {
                'name': port_dict.get('name'),
                'port': port_dict.get('port'),
                'protocol': port_dict.get('protocol'),
                'target_port': port_dict.get('target_port') or port_dict.get('targetPort'),
                'node_port': port_dict.get('node_port') or port_dict.get('nodePort')
            }
            serialized_ports.append(serialized_port)
        elif isinstance(port, dict):
            # Already a dict
            serialized_ports.append(port)
        else:
            # Manual conversion for V1ServicePort objects
            serialized_port = {
                'name': getattr(port, 'name', None),
                'port': getattr(port, 'port', None),
                'protocol': getattr(port, 'protocol', None),
                'target_port': getattr(port, 'target_port', None),
                'node_port': getattr(port, 'node_port', None)
            }
            # Remove None values for cleaner JSON
            serialized_port = {k: v for k, v in serialized_port.items() if v is not None}
            serialized_ports.append(serialized_port)
    return serialized_ports

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
        service_list = k8s_client.CoreV1Api().list_namespaced_service(ns, _request_timeout=1)
        for service in service_list.items:
            SERVICE_INFO = {
                "name": service.metadata.name,
                "type": service.spec.type,
                "created": service.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(service.metadata.annotations),
                "labels": service.metadata.labels,
                "selector": service.spec.selector,
                "ports": [],  # Initialize as empty list
                "cluster_ip": service.spec.cluster_ip,
            }
            # Serialize V1ServicePort objects to dictionaries
            if service.spec.ports:
                SERVICE_INFO['ports'] = serialize_service_ports(service.spec.ports)
            
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
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns, label_selector=label_selector, _request_timeout=1)
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
