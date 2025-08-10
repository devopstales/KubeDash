import json

from kubernetes import client as k8s_client
from kubernetes.client import CustomObjectsApi, ApiextensionsV1Api
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler, trimAnnotations
from kubedash.lib.components import cache, short_cache_time, long_cache_time

from . import logger
from .server import k8sClientConfigGet

###############################################################
## Helpers
###############################################################

def get_vpa_crd_version(username_role, user_token):
    """Determine the served+storage version of the VPA CRD
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
    Returns:
        str: The version of the VPA CRD
    """
    k8sClientConfigGet(username_role, user_token)  # use actual auth here if needed
    try:
        api_ext = ApiextensionsV1Api()
        crd = api_ext.read_custom_resource_definition("verticalpodautoscalers.autoscaling.k8s.io")

        for version in crd.spec.versions:
            if version.served and version.storage:
                return version.name

        # Fallback if no storage+served version is found
        for version in crd.spec.versions:
            if version.served:
                return version.name

    except Exception as e:
        ErrorHandler(logger, e, "Failed to determine VPA CRD version")
        return None


##############################################################
## VPA
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sVPAListGet(username_role, user_token, ns_name):
    """Get a list of Vertical Pod Autoscalers for a given namespace

    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Namespace name

    Returns:
        VPA_LIST (list): Vertical Pod Autoscaler resources
    """
    k8sClientConfigGet(username_role, user_token)  # use actual auth here if needed
    VPA_LIST = []
    
    api_version = get_vpa_crd_version(username_role, user_token)
    if not api_version:
        return VPA_LIST


    try:
        custom_api = CustomObjectsApi()
        vpas = custom_api.list_namespaced_custom_object(
            group="autoscaling.k8s.io",
            version=api_version,  # <- updated based on CRD
            namespace=ns_name,
            plural="verticalpodautoscalers",
            _request_timeout=1
        )

        for vpa in vpas.get("items", []):
            metadata = vpa.get("metadata", {})
            spec = vpa.get("spec", {})
            status = vpa.get("status", {})

            VPA_DATA = {
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "annotations": trimAnnotations(metadata.get("annotations", {})),
                "labels": metadata.get("labels", {}),
                "spec": spec,
                "status": status,
                "created": metadata.get("creationTimestamp")
            }

            VPA_LIST.append(VPA_DATA)

        return VPA_LIST

    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get Vertical Pod Autoscaler list - {error.status}")
        return VPA_LIST
    except Exception as error:
        return VPA_LIST

##############################################################
## HPA
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sHPAListGet(username_role, user_token, ns_name):
    """Get a list of Horizontal Pod Autoscalers for a given namespace
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Namespace name
        
    Return:
        HPA_LIST (list): Horizontal Pod Autoscalers
    """
    k8sClientConfigGet(username_role, user_token)
    HPA_LIST = list()
    try:
        hpas = k8s_client.AutoscalingV1Api().list_namespaced_horizontal_pod_autoscaler(ns_name, _request_timeout=1)
        for hpa in hpas.items:
            HPA_DATA = {
                "name": hpa.metadata.name,
                "namespace": hpa.metadata.namespace,
                "annotations": trimAnnotations(hpa.metadata.annotations),
                "labels": hpa.metadata.labels,
                "spec": hpa.spec,
                "status": hpa.status,
                "created": hpa.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for key, value in hpa.metadata.annotations.items():
                if key == "autoscaling.alpha.kubernetes.io/conditions":
                    json_value = json.loads(value)
                    HPA_DATA["conditions"] = json_value
            HPA_LIST.append(HPA_DATA)
        return HPA_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get Horizontal Pod Autoscaler list - %s" % error.status)
        return HPA_LIST
    except Exception as error:
        return HPA_LIST

##############################################################
## Pod Disruption Budget
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sPodDisruptionBudgetListGet(username_role, user_token, ns_name):
    """Get a list of k8s Pod Disruption Budgets for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Namespace name
        
    Return:
        PDB_LIST (list): List of Pod Disruption Budgets
    """
    PDB_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        pdbs = k8s_client.PolicyV1Api().list_namespaced_pod_disruption_budget(namespace=ns_name, _request_timeout=1)
        for pdb in pdbs.items:
            PDB_DATA = {
                "name": pdb.metadata.name,
                "namespace": pdb.metadata.namespace,
                "annotations": trimAnnotations(pdb.metadata.annotations),
                "labels": pdb.metadata.labels,
                "selector": pdb.spec.selector.match_labels,
                "max_unavailable": pdb.spec.max_unavailable,
                "min_available": pdb.spec.min_available,
                "status": pdb.status,
                "created": pdb.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            if "unhealthy_pod_eviction_policy" in pdb.spec.to_dict():
                PDB_DATA["unhealthy_pod_eviction_policy"] =  pdb.spec.unhealthy_pod_eviction_policy,
            conditions = pdb.status.conditions
            condition_list = list()
            for condition in conditions:
                condition_list.append(condition.to_dict()) 
            PDB_DATA["conditions"] = condition_list
            PDB_LIST.append(PDB_DATA)
        return PDB_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get DisruptionBudgetList - %s" % error.status)
        return PDB_LIST
    except Exception as error:
        ERROR = "k8sPodDisruptionBudgetListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return PDB_LIST

##############################################################
# Resource Quota
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sQuotaListGet(username_role, user_token, ns_name):
    """Get a list of quotas for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Namespace name
        
    Return:
        RQ_LIST (list): List of quotas
    """
    RQ_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        rqs = k8s_client.CoreV1Api().list_namespaced_resource_quota(namespace=ns_name, _request_timeout=1)
        for rq in rqs.items:
            PQ_DATA = {
                "name": rq.metadata.name,
                "namespace": rq.metadata.namespace,
                "annotations": trimAnnotations(rq.metadata.annotations),
                "labels": rq.metadata.labels,
                "status": rq.status,
                "selectors": None,
                "scope": rq.spec.scopes,
                "created": rq.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            if rq.spec.scope_selector:
                for expressions in rq.spec.scope_selector.match_expressions:
                    PQ_DATA["selectors"] = expressions.to_dict()
            RQ_LIST.append(PQ_DATA)
        return RQ_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get resource quota list - %s" % error.status)
        return RQ_LIST
    except Exception as error:
        ERROR = "k8sQuotaListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return RQ_LIST

##############################################################
# Limit Range
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sLimitRangeListGet(username_role, user_token, ns_name):
    """Get a list of Limit Ranges for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns_name (str): Namespace name
        
    Return:
        LR_LIST (list): List of Limit Ranges
    """
    LR_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        lrs = k8s_client.CoreV1Api().list_namespaced_limit_range(ns_name, _request_timeout=1)
        for lr in lrs.items:
            LR_DATA = {
                "name": lr.metadata.name,
                "namespace": lr.metadata.namespace,
                "annotations": trimAnnotations(lr.metadata.annotations),
                "labels": lr.metadata.labels,
                "limits": lr.spec.limits,
                "created": lr.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            LR_LIST.append(LR_DATA)
        return LR_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get Limit Range list - %s" % error.status)
        return LR_LIST
    except Exception as error:
        ERROR = "k8sLimitRangeListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return LR_LIST


##############################################################
## Priority ClassList
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sPriorityClassList(username_role, user_token):
    """Get a list of Priority Classes.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        
    Return:
        PC_LIST (list): List of Priority Classes
    """
    PC_LIST = list()
    k8sClientConfigGet(username_role, user_token)

    pcs = k8s_client.SchedulingV1Api().list_priority_class(_request_timeout=1)
    for cs in pcs.items:
        PCS_DATA = {
            "name": cs.metadata.name,
            "annotations": trimAnnotations(cs.metadata.annotations),
            "labels": cs.metadata.labels,
            "created": cs.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "preemption_policy": cs.preemption_policy,
            "value": cs.value,
            "description": cs.description,
            "global_default": cs.global_default,
        }
        PC_LIST.append(PCS_DATA)
    return PC_LIST
