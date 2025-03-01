import json

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations

from . import logger
from .server import k8sClientConfigGet

##############################################################
## HPA
##############################################################

def k8sHPAListGet(username_role, user_token, ns_name):
    k8sClientConfigGet("admin", None)
    HPA_LIST = list()
    try:
        hpas = k8s_client.AutoscalingV1Api().list_namespaced_horizontal_pod_autoscaler(ns_name, _request_timeout=5)
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

def k8sPodDisruptionBudgetListGet(username_role, user_token, ns_name):
    PDB_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        pdbs = k8s_client.PolicyV1Api().list_namespaced_pod_disruption_budget(namespace=ns_name, _request_timeout=5)
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

def k8sQuotaListGet(username_role, user_token, ns_name):
    RQ_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        rqs = k8s_client.CoreV1Api().list_namespaced_resource_quota(namespace=ns_name, _request_timeout=5)
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

def k8sLimitRangeListGet(username_role, user_token, ns_name):
    LR_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    try:
        lrs = k8s_client.CoreV1Api().list_namespaced_limit_range(ns_name, _request_timeout=5)
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

def k8sPriorityClassList(username_role, user_token):
    PC_LIST = list()
    k8sClientConfigGet(username_role, user_token)

    pcs = k8s_client.SchedulingV1Api().list_priority_class(_request_timeout=5)
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
