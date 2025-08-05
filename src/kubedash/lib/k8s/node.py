
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations
from lib.components import cache, short_cache_time, long_cache_time

from . import logger
from .server import k8sClientConfigGet

##############################################################
## Kubernetes Nodes
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sListNodes(username_role, user_token):
    """Get a list of nodes
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        node_list (list): List of Node objects
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    node_list = list()
    try:
        node_list = k8s_client.CoreV1Api().list_node(_request_timeout=1)
        return node_list, None
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "list nodes - %s " % error.status)
        return node_list, error
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "k8sListNodes: %s" % error)
        return node_list, "CannotConnect"

@cache.memoize(timeout=long_cache_time)
def k8sNodesListGet(username_role, user_token):
    """Get the list of nodes

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        node_list (list): List of Node objects
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    nodes, error = k8sListNodes(username_role, user_token)
    NODE_LIST = []
    if error is None:
        for no in nodes.items:
            NODE_INFO = {
                "status": "",
                "name": "",
                "role": "",
                "version": "",
                "ip": "",
                "os": "",
                "runtime": "",
                "taint": list(),
            }
            NODE_INFO['name'] = no.metadata.name
            taints = no.spec.taints
            if taints:
                for t in taints:
                    if t.value:
                        NODE_INFO["taint"].append(t.key + "=" + t.value)
                    else:
                        NODE_INFO["taint"].append(t.key + "=")
            NODE_INFO['role'] = None
            for label, value in no.metadata.labels.items():
                if label == "kubernetes.io/os":
                    NODE_INFO['os'] = value
                if "node-role.kubernetes.io" in label:
                    NODE_INFO['role'] = label.split('/')[1].capitalize()
                    
            for key, value in no.status.node_info.__dict__.items():
                if key == "_container_runtime_version":
                    NODE_INFO['runtime'] = value
                elif key == "_kubelet_version":
                    NODE_INFO['version'] = value
                    
            for key, value in no.status.addresses[0].__dict__.items():
                if key == "_address":
                    NODE_INFO['ip'] = value

            for key, value in no.status.conditions[-1].__dict__.items():
                if key == "_type":
                    NODE_INFO['status'] = value
                    
            if NODE_INFO['role'] is None:
                NODE_INFO['role'] = "Worker"

            NODE_LIST.append(NODE_INFO)
        return NODE_LIST
    else:
        return NODE_LIST
    
@cache.memoize(timeout=long_cache_time)
def k8sNodeGet(username_role, user_token, no_name):
    """Get a specific node
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        no_name (str): Name of the node
        
    Return:
        node_info (dict): Node details
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    nodes, error = k8sListNodes(username_role, user_token)
    NODE_INFO = {
        "status": "",
        "name": "",
        "role": "",
        "version": "",
        "os": "",
        "pod_cidr": "",
        "runtime": "",
        "taint": list(),
        "annotations": "",
        "labels": "",
        "conditions": {},
    }
    if error is None:
        for no in nodes.items:
            if no.metadata.name == no_name:
                NODE_INFO['name'] = no.metadata.name
                taints = no.spec.taints
                if taints:
                    for t in taints:
                        if t.value:
                            NODE_INFO["taint"].append(t.key + "=" + t.value)
                        else:
                            NODE_INFO["taint"].append(t.key + "=")
                NODE_INFO['role'] = None
                NODE_INFO['annotations'] = trimAnnotations(no.metadata.annotations)
                NODE_INFO['labels'] = no.metadata.labels
                NODE_INFO['pod_cidr'] = no.spec.pod_cidr
                NODE_INFO['os'] = no.status.node_info.os_image
                NODE_INFO['conditions'] = list()
                for co in no.status.conditions:
                    NODE_INFO['conditions'].append([co.type, co.status, co.reason, co.message])
                    
                for label, value in no.metadata.labels.items():
                    if "node-role.kubernetes.io" in label:
                        NODE_INFO['role'] = label.split('/')[1].capitalize()

                for key, value in no.status.node_info.__dict__.items():
                    if key == "_container_runtime_version":
                        NODE_INFO['runtime'] = value
                    elif key == "_kubelet_version":
                        NODE_INFO['version'] = value
                
                for key, value in no.status.conditions[-1].__dict__.items():
                    if key == "_type":
                        NODE_INFO['status'] = value
                        
                if NODE_INFO['role'] is None:
                    NODE_INFO['role'] = "Worker"
        return NODE_INFO
    else:
        return NODE_INFO
