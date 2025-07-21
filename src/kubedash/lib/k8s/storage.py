from datetime import datetime

import kubernetes.client as k8s_client
from kubernetes.client.exceptions import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations

from . import logger
from .server import k8sClientConfigGet

##############################################################
## storage Class
##############################################################

def k8sStorageClassListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    SC_LIST = list()
    try:
        storage_classes = k8s_client.StorageV1Api().list_storage_class(_request_timeout=1, timeout_seconds=1)
        for sc in storage_classes.to_dict()["items"]:
            SC = {
                "name": sc["metadata"]["name"],
                "created": sc["metadata"]["creation_timestamp"].strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(sc["metadata"]["annotations"]),
                "labels": sc["metadata"]["labels"],
                "provisioner": sc["provisioner"],
                "reclaim_policy": sc["reclaim_policy"],
                "volume_binding_mode": sc["volume_binding_mode"],
            }
            if "parameters" in sc:
                SC["parameters"] = sc["parameters"]
            SC_LIST.append(SC)
        return SC_LIST
    except ApiException as error:
        ErrorHandler(logger, error, "get cluster storage Class list - %s" % error.status)
        return SC_LIST
    except Exception as error:
        ERROR = "k8sStorageClassListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return SC_LIST
    
##############################################################
## VolumeSnapshotClass
##############################################################

def k8sSnapshotClassListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    SC_LIST = list()
    try:
        snapshot_classes = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            "snapshot.storage.k8s.io", 
            "v1", 
            "volumesnapshotclasses",
            _request_timeout=1, timeout_seconds=1
        )
        for sc in snapshot_classes["items"]:
            SC = {
                "name": sc["metadata"]["name"],
                "created": datetime.strptime(sc["metadata"]["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ").strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(sc["metadata"]["annotations"]),
                "driver": sc["driver"],
                "deletion_policy": sc["deletionPolicy"],
            }
            if "labels" in sc["metadata"]:
                SC["labels"] = sc["metadata"]["labels"]
            if "parameters" in sc:
                SC["parameters"] = sc["parameters"]
            SC_LIST.append(SC)
        return SC_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster Snapshot Class list - %s" % error.status)
        return SC_LIST
    except Exception as error:
        ERROR = "k8sSnapshotClassListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return SC_LIST

##############################################################
## Persistent Volume Claim
##############################################################

def k8sPersistentVolumeClaimListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    PVC_LIST = list()
    try:
        persistent_volume_clames= k8s_client.CoreV1Api().list_namespaced_persistent_volume_claim(namespace, _request_timeout=1, timeout_seconds=1)
        for pvc in persistent_volume_clames.items:
            PVC = {
                "status": pvc.status.phase,
                "name": pvc.metadata.name,
                "created": pvc.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "annotations": trimAnnotations(pvc.metadata.annotations),
                "labels": pvc.metadata.labels,
                "access_modes": pvc.spec.access_modes,
                "storage_class_name": pvc.spec.storage_class_name,
                "volume_name": pvc.spec.volume_name,
                "volume_mode": pvc.spec.volume_mode,
                "capacity": pvc.status.capacity['storage'],
            }
            PVC_LIST.append(PVC)
        return PVC_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get Persistent Volume ClaimList list - %s" % error.status)
        return PVC_LIST
    except Exception as error:
        ERROR = "k8sPersistentVolumeClaimListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return PVC_LIST

##############################################################
## Persistent Volume
##############################################################

def k8sPersistentVolumeListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    PV_LIST = list()
    try:
        pv_list = k8s_client.CoreV1Api().list_persistent_volume(_request_timeout=1, timeout_seconds=1)
        for pv in pv_list.items:
            if namespace == pv.spec.claim_ref.namespace:
                PV = {
                    "status": pv.status.phase,
                    "name": pv.metadata.name,
                    "created": pv.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    "annotations": trimAnnotations(pv.metadata.annotations),
                    "labels": pv.metadata.labels,
                    "access_modes": pv.spec.access_modes,
                    "storage_class_name": pv.spec.storage_class_name,
                    "volume_claim_name": pv.spec.claim_ref.name,
                    "volume_claim_namespace": pv.spec.claim_ref.namespace,
                    "reclaim_policy": pv.spec.persistent_volume_reclaim_policy,
                    "volume_mode": pv.spec.volume_mode,
                    "capacity": pv.spec.capacity['storage'],
                }
                if pv.metadata.deletion_timestamp:
                    PV.update({"status": "Terminating"})
                    PV.update({"deleted": pv.metadata.deletion_timestamp})
                if pv.spec.csi:
                    PV.update({"csi_driver": pv.spec.csi.driver})
                    PV.update({"fs_type": pv.spec.csi.fs_type})
                    PV.update({"volume_attributes":  pv.spec.csi.volume_attributes})
                if pv.spec.host_path:
                    PV.update({"host_path": pv.spec.host_path.path})
                    continue
                PV_LIST.append(PV)
        return PV_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster Persistent Volume list - %s" % error.status)
        return PV_LIST
    except Exception as error:
        ERROR = "k8sPersistentVolumeListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return PV_LIST 

##############################################################
## Volume Snapshot
##############################################################

def k8sPersistentVolumeSnapshotListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    PVS_LIST = list()
    try:
        snapshot_list = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            "snapshot.storage.k8s.io", 
            "v1", 
            "volumesnapshots", 
            _request_timeout=1, timeout_seconds=1
        )
        for pvs in snapshot_list["items"]:
            PVS = {
            "name": pvs["metadata"]["name"],
            "annotations": trimAnnotations(pvs["metadata"]["annotations"]),
            "created": datetime.strptime(pvs["metadata"]["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ").strftime('%Y-%m-%d %H:%M:%S'),
            "pvc": pvs["spec"]["source"]["persistentVolumeClaimName"],
            "volume_snapshot_class": pvs["spec"]["volumeSnapshotClassName"],
            "volume_snapshot_content": pvs["status"]["boundVolumeSnapshotContentName"],
            "snapshot_creation_time": pvs["status"]["creationTime"],
            "status": pvs["status"]["readyToUse"],
            "restore_size": pvs["status"]["restoreSize"],
            }
            if "labels" in pvs["metadata"]:
                PVS["labels"] = pvs["metadata"]["labels"]
            PVS_LIST.append(PVS)
        return PVS_LIST
    except ApiException as error:
        ErrorHandler(logger, error, "get Volume Snapshot list - %s" % error.status)
        return PVS_LIST
    except Exception as error:
        ERROR = "k8sPersistentVolumeSnapshotListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return PVS_LIST 

##############################################################
## ConfigMap
##############################################################

def k8sConfigmapListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    CONFIGMAP_LIST = list()
    configmap_list = k8s_client.CoreV1Api().list_namespaced_config_map(namespace, _request_timeout=1, timeout_seconds=1)
    for configmap in configmap_list.items:
        CONFIGMAP_DATA = {
            "name": configmap.metadata.name,
            "created": configmap.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "annotations": trimAnnotations(configmap.metadata.annotations),
            "labels": configmap.metadata.labels,
            "data": configmap.data,
            "version": configmap.metadata.resource_version,
        }
        CONFIGMAP_LIST.append(CONFIGMAP_DATA)

    return CONFIGMAP_LIST
