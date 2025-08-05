from flask import flash
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode
from pyvis.network import Network

from lib.helper_functions import ErrorHandler, calcPercent, parse_quantity
from lib.components import cache, short_cache_time, long_cache_time

from . import logger, tracer
from .node import k8sNodesListGet
from .security import k8sPodListVulnsGet
from .server import k8sClientConfigGet
from .workload import (k8sDaemonSetsGet, k8sDeploymentsGet, k8sReplicaSetsGet,
                       k8sStatefulSetsGet)

##############################################################
## Metrics
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sGetClusterMetric():
    """Get cluster metrics from a kubernetes cluster
    
    Returns:
        clusterMetric (dict): Cluster metrics data
        bad_clusterMetric (dict): If any error occurred, return this data instead
    """
    with tracer.start_as_current_span("get-cluster-metrics") as span:
        k8sClientConfigGet("Admin", None)
        tmpTotalPodCount = float()
        totalTotalPodAllocatable = float()
        totalPodAllocatable = float()
        tmpTotalCpuCapacity = int()
        tmpTotalMemoryCapacity = int()
        tmpTotalCpuAllocatable = int()
        tmpTotalMenoryAllocatable = int()
        tmpTotalCpuLimit = float()
        tmpTotalMemoryLimit = float()
        tmpTotalCpuRequest = float()
        tmpTotalMemoryRequest = float()
        total_node_mem_usage = float()
        total_node_cpu_usage = float()
        clusterMetric = {
            "nodes": [],
            "clusterTotals": {}
        }
        bad_clusterMetric = {
            "nodes": [],
            "clusterTotals": {
                "cpu": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercent": 0,
                    "requests": 0,
                    "requestsPercent": 0,
                    "limits": 0,
                    "limitsPercent": 0,
                    "usage": 0,
                    "usagePercent": 0,
                },
                "memory": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercent": 0,
                    "requests": 0,
                    "requestsPercent": 0,
                    "limits": 0,
                    "limitsPercent": 0,
                    "usage": 0,
                    "usagePercent": 0,
                },
                "pod_count": {
                    "current": 0,
                    "allocatable": 0,
                },
            }
        }
        try:
            node_list = k8s_client.CoreV1Api().list_node(_request_timeout=1)
            pod_list = k8s_client.CoreV1Api().list_pod_for_all_namespaces(_request_timeout=1)
            try:
                k8s_nodes = k8s_client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", _request_timeout=1)
            except Exception as error:
                k8s_nodes = None
                flash("Metrics Server is not installed. If you want to see usage date please install Metrics Server.", "warning")
            for node in node_list.items:
                tmpPodCount = int()
                tmpCpuLimit = float()
                tmpMemoryLimit = float()
                tmpCpuRequest = float()
                tmpMemoryRequest = float()
                node_mem_usage = 0
                node_cpu_usage = 0
                for pod in pod_list.items:
                    if pod.spec.node_name == node.metadata.name and pod.status.phase == "Running":
                        tmpPodCount += 1
                        for container in pod.spec.containers:
                            if container.resources.limits:
                                if "cpu" in container.resources.limits:
                                    tmpCpuLimit += float(parse_quantity(container.resources.limits["cpu"]))
                                if "memory" in container.resources.limits:
                                    tmpMemoryLimit += float(parse_quantity(container.resources.limits["memory"]))
                            if container.resources.requests:
                                if "cpu" in container.resources.requests:
                                    tmpCpuRequest += float(parse_quantity(container.resources.requests["cpu"]))
                                if "memory" in container.resources.requests:
                                    tmpMemoryRequest += float(parse_quantity(container.resources.requests["memory"]))
                totalPodAllocatable += float(node.status.allocatable["pods"])
                node_mem_capacity = float(parse_quantity(node.status.capacity["memory"]))
                node_mem_allocatable = float(parse_quantity(node.status.allocatable["memory"]))
                if k8s_nodes:
                    for stats in k8s_nodes['items']:
                        if stats['metadata']['name'] == node.metadata.name:
                            node_mem_usage = float(parse_quantity(stats['usage']['memory']))
                            node_cpu_usage = float(parse_quantity(stats['usage']['cpu']))
                clusterMetric["nodes"].append({
                    "name": node.metadata.name,
                    "cpu": {
                        "capacity": node.status.capacity["cpu"],
                        "allocatable": node.status.allocatable["cpu"],
                        "requests": tmpCpuRequest,
                        "requestsPercent": calcPercent(tmpCpuRequest, int(node.status.capacity["cpu"]), True),
                        "limits": tmpCpuLimit,
                        "limitsPercent": calcPercent(tmpCpuLimit, int(node.status.capacity["cpu"]), True),
                        "usage": node_cpu_usage,
                        "usagePercent": calcPercent(node_cpu_usage, int(node.status.capacity["cpu"]), True),
                    },
                    "memory": {
                        "capacity": node_mem_capacity,
                        "allocatable": node_mem_allocatable,
                        "requests": tmpMemoryRequest,
                        "requestsPercent": calcPercent(tmpMemoryRequest, node_mem_capacity, True),
                        "limits": tmpMemoryLimit,
                        "limitsPercent": calcPercent(tmpMemoryLimit, node_mem_capacity, True),
                        "usage": node_mem_usage,
                        "usagePercent": calcPercent(node_mem_usage, node_mem_capacity, True),
                    },
                    "pod_count": {
                        "current": tmpPodCount,
                        "currentPercent": calcPercent(tmpPodCount, totalPodAllocatable, True),
                        "allocatable": totalPodAllocatable,
                    },
                })
                tmpTotalPodCount += tmpPodCount
                totalTotalPodAllocatable += totalPodAllocatable
                tmpTotalCpuAllocatable += int(node.status.allocatable["cpu"])
                tmpTotalMenoryAllocatable += node_mem_allocatable
                tmpTotalCpuCapacity += int(node.status.capacity["cpu"])
                tmpTotalMemoryCapacity += node_mem_capacity
                tmpTotalCpuLimit += tmpCpuLimit
                tmpTotalMemoryLimit += tmpMemoryLimit
                tmpTotalCpuRequest += tmpCpuRequest
                tmpTotalMemoryRequest += tmpMemoryRequest
                total_node_mem_usage += node_mem_usage
                total_node_cpu_usage += node_cpu_usage
            # clusterTotals
            clusterMetric["clusterTotals"] = {
                    "cpu": {
                        "capacity": tmpTotalCpuCapacity,
                        "allocatable": tmpTotalCpuAllocatable,
                        "requests": tmpTotalCpuRequest,
                        "requestsPercent": calcPercent(tmpTotalCpuRequest, tmpTotalCpuAllocatable, True),
                        "limits": tmpTotalCpuLimit,
                        "limitsPercent": calcPercent(tmpTotalCpuLimit, tmpTotalCpuAllocatable, True),
                        "usage": total_node_cpu_usage,
                        "usagePercent": calcPercent(total_node_cpu_usage, tmpTotalCpuAllocatable, True),
                    },
                    "memory": {
                        "capacity": tmpTotalMemoryCapacity,
                        "allocatable": tmpTotalMenoryAllocatable,
                        "requests": tmpTotalMemoryRequest,
                        "requestsPercent": calcPercent(tmpTotalMemoryRequest, tmpTotalMenoryAllocatable, True),
                        "limits": tmpTotalMemoryLimit,
                        "limitsPercent":  calcPercent(tmpTotalMemoryLimit, tmpTotalMenoryAllocatable, True),
                        "usage": total_node_mem_usage,
                        "usagePercent": calcPercent(total_node_mem_usage, tmpTotalMenoryAllocatable, True),
                    },
                    "pod_count": {
                        "current": tmpTotalPodCount,
                        "currentPercent": calcPercent(tmpTotalPodCount, totalTotalPodAllocatable, True),
                        "allocatable": totalTotalPodAllocatable,
                    },
            }
            return clusterMetric
        except ApiException as error:
            if error.status != 404:
                ErrorHandler(logger, error, "Cannot Connect to Kubernetes - %s " % error.status)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "Cannot Connect to Kubernetes: %s" % error))
            return bad_clusterMetric
        except Exception as error:
            ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "Cannot Connect to Kubernetes: %s" % error))
            return bad_clusterMetric

@cache.memoize(timeout=long_cache_time)
def k8sGetNodeMetric(node_name):
    """Get the node metric for a given node name from the cluster
    
    Args:
        node_name (str): The name of the node
        
    Returns:
        node_metric (dict): The node metric
    """
    k8sClientConfigGet("Admin", None)
    totalPodAllocatable = float()
    try:
        node_list = k8s_client.CoreV1Api().list_node(_request_timeout=1)
        pod_list = k8s_client.CoreV1Api().list_pod_for_all_namespaces(_request_timeout=1)
        try:
            k8s_nodes = k8s_client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", _request_timeout=1)
        except Exception as error:
            k8s_nodes = None
            flash("Metrics Server is not installed. If you want to see usage date please install Metrics Server.", "warning")
        for node in node_list.items:
            tmpPodCount = int()
            tmpCpuLimit = float()
            tmpMemoryLimit = float()
            tmpCpuRequest = float()
            tmpMemoryRequest = float()
            node_mem_usage = 0
            node_cpu_usage = 0
            if node.metadata.name == node_name:
                for pod in pod_list.items:
                    if pod.spec.node_name == node.metadata.name and pod.status.phase == "Running":
                        tmpPodCount += 1
                        for container in pod.spec.containers:
                            if container.resources.limits:
                                if "cpu" in container.resources.limits:
                                    tmpCpuLimit += float(parse_quantity(container.resources.limits["cpu"]))
                                if "memory" in container.resources.limits:
                                    tmpMemoryLimit += float(parse_quantity(container.resources.limits["memory"]))
                            if container.resources.requests:
                                if "cpu" in container.resources.requests:
                                    tmpCpuRequest += float(parse_quantity(container.resources.requests["cpu"]))
                                if "memory" in container.resources.requests:
                                    tmpMemoryRequest += float(parse_quantity(container.resources.requests["memory"]))
                totalPodAllocatable += float(node.status.allocatable["pods"])
                node_mem_capacity = float(parse_quantity(node.status.capacity["memory"]))
                node_mem_allocatable = float(parse_quantity(node.status.allocatable["memory"]))
                if k8s_nodes:
                    for stats in k8s_nodes['items']:
                        if stats['metadata']['name'] == node.metadata.name:
                            node_mem_usage = float(parse_quantity(stats['usage']['memory']))
                            node_cpu_usage = float(parse_quantity(stats['usage']['cpu']))
                node_metric = {
                    "name": node.metadata.name,
                    "cpu": {
                        "capacity":  int(node.status.capacity["cpu"]),
                        "allocatable":  int(node.status.allocatable["cpu"]),
                        "requests": tmpCpuRequest,
                        "requestsPercent": calcPercent(tmpCpuRequest, int(node.status.capacity["cpu"]), True),
                        "limits": tmpCpuLimit,
                        "limitsPercent": calcPercent(tmpCpuLimit, int(node.status.capacity["cpu"]), True),
                        "usage": node_cpu_usage,
                        "usagePercent": calcPercent(node_cpu_usage, int(node.status.capacity["cpu"]), True),
                    },
                    "memory": {
                        "capacity": node_mem_capacity,
                        "allocatable": node_mem_allocatable,
                        "requests": tmpMemoryRequest,
                        "requestsPercent": calcPercent(tmpMemoryRequest, node_mem_capacity, True),
                        "limits": tmpMemoryLimit,
                        "limitsPercent": calcPercent(tmpMemoryLimit, node_mem_capacity, True),
                        "usage": node_mem_usage,
                        "usagePercent": calcPercent(node_mem_usage, node_mem_capacity, True),
                    },
                    "pod_count": {
                        "current": tmpPodCount,
                        "currentPercent": calcPercent(tmpPodCount, totalPodAllocatable, True),
                        "allocatable": totalPodAllocatable,
                    },
                }
                return node_metric
            else:
                return None
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "Cannot Connect to Kubernetes - %s " % error.status)
        return None
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
        return None

@cache.memoize(timeout=long_cache_time)
def k8sPVCMetric(namespace):
    """Get the Persistent Volume Claim metrics for a given namespace
    
    Args:
        namespace (str): The name of the namespace
        
    Returns:
        PVC_LIST (list): The list of Persistent Volume Claim metrics
    """
    k8sClientConfigGet('Admin', None)
    PVC_LIST = list()
    try:
        node_list = k8sNodesListGet("Admin", None)
        for mode in node_list:
            name = mode["name"]
            data = k8s_client.CoreV1Api().connect_get_node_proxy_with_path(name, path="stats/summary", _request_timeout=1)
            data_json = eval(data)
            for pod in data_json["pods"]:
                if 'volume' in pod:
                    for volme in pod['volume']:
                        if "pvcRef" in volme:
                            if namespace == volme['pvcRef']['namespace']:
                                DAT = {
                                    "name": volme['pvcRef']['name'],
                                    "capacityBytes": int(volme['capacityBytes'])/1024,
                                    "usedBytes": int(volme['usedBytes'])/1024,
                                    "availableBytes": int(volme['availableBytes'])/1024,
                                    "percentageUsed": (volme['usedBytes'] / volme['capacityBytes']  * 100),
                                }
                                PVC_LIST.append(DAT)
        return PVC_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get Persistent Volume Claim Metrics - %s" % error.status)
        return PVC_LIST
    except Exception as error:
        return PVC_LIST

#@cache.memoize(timeout=long_cache_time)
def k8sGetClusterEvents(username_role, user_token):
    """Get the cluster events for a given username and user_token
    
    Args:
        username_role (str): The username and role of the user
        user_token (str): The user's token
        
    Returns:
        events (list): The list of cluster events
    """
    k8sClientConfigGet(username_role, user_token)
    try:
        event_list = k8s_client.CoreV1Api().list_event_for_all_namespaces(_request_timeout=1)
        events = []
        for event in event_list.items:
            if event.type != "Normal":
                events.append({
                    "name": event.metadata.name,
                    "involvedObjectName": event.involved_object.name,
                    "involvedObjectKind": event.involved_object.kind,
                    "namespace": event.metadata.namespace,
                    "message": event.message,
                    "reason": event.reason,
                    "type": event.type,
                    "count": event.count,
                    "first_timestamp": event.first_timestamp,
                    "last_timestamp": event.last_timestamp,
                })
        return events
    except ApiException as error:
        ErrorHandler(logger, error, "Cannot Connect to Kubernetes - %s" % error.status)
        return []
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", "Cannot Connect to Kubernetes")
        return []
    

@cache.memoize(timeout=long_cache_time)
def k8sGetPodMap(username_role, user_token, namespace):
    """Get the Pod Map for a given username, user_token, and namespace
    
    Args:
        username_role (str): The username and role of the user
        user_token (str): The user's token
        namespace (str): The name of the namespace
        
    Returns:
        net (NetworkX.classes.digraph): The NetworkX graph representing the Pod Map
        nodes (NetworkX.classes.digraph): The NetworkX graph representing the nodes
        edges (NetworkX.classes.digraph): The NetworkX graph representing the edges
    """
    k8sClientConfigGet(username_role, user_token)
    net = Network(directed=True, layout=True)

    statefulset_list = k8sStatefulSetsGet(username_role, user_token, namespace)
    for sts in statefulset_list:
        if int(sts["desired"]) != 0:
            net.add_node(sts["name"], label=sts["name"], shape="image", group="statefulset")

    daemonset_list = k8sDaemonSetsGet(username_role, user_token, namespace)
    for ds in daemonset_list:
        if int(ds["desired"]) != 0:
            net.add_node(ds["name"], label=ds["name"], shape="image", group="daemonset")

    deployments_list = k8sDeploymentsGet(username_role, user_token, namespace)
    for deploy in deployments_list:
        if int(deploy["desired"]) != 0:
            net.add_node(deploy["name"], label=deploy["name"], shape="image", group="deployment")

    replicaset_list = k8sReplicaSetsGet(username_role, user_token, namespace)
    for rs in replicaset_list:
        if rs["desired"] != 0:
            on_name = rs["owner"].split("/", 1)[1]
            net.add_node(rs["name"], label=rs["name"], shape="image", group="replicaset")
            net.add_edge(on_name, rs["name"], arrowStrikethrough=False, physics=True, valu=1000)

    #has_report, pod_list = k8sPodListVulnsGet(username_role, user_token, namespace)
    #for po in pod_list:
    #    if po["status"] == "Running":
    #        net.add_node(po["name"], label=po["name"], shape="image", group="pod")
    #        if po["owner"]:
    #            if "replicationcontrollers" !=  po["owner"].split("/", 1)[0] and "jobs" != po["owner"].split("/", 1)[0]:
    #                on_name = po["owner"].split("/", 1)[1]
    #                net.add_edge(on_name, po["name"], arrowStrikethrough=False, physics=True, valu=1000)

    nodes = net.get_network_data()[0]
    edges = net.get_network_data()[1]

    return nodes, edges

################################################################
# New Metric Scraper functions
################################################################
"""
# every sec 
# last 11

name	cl06-m101
cpu	    478
memory	10025209856
storage	0
time	2025-03-05 12:24:46

'cl06-m101', 0.286842451, 9529667584.0, 0, '2025-03-08 16:39:50.105399'

name	    atlassian-jira-tst-0
namespace	atlassian-jira
container	jira
cpu	        41
memory	    7323451392
storage	    0
time	    2025-03-05 12:24:46
"""

def getNodeMetrics():
    """Function to get node metrics from K8S API.

    Returns:
        NODE_METRICS (list)): list of node metrics
    """
    k8sClientConfigGet('Admin', None)
    NODE_METRICS = list()
    node_metric = {
        "name": "",
        "cpu": "",
        "memory": "",
        "storage": "",
    }
    
    try:
        k8s_nodes = k8s_client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", _request_timeout=1)
        for node in k8s_nodes['items']:
            node_metric['name']    = node['metadata']['name']
            node_metric['cpu']     = float(parse_quantity(node['usage']['cpu']))
            node_metric['memory']  = float(parse_quantity(node['usage']['memory']))
            node_metric['storage'] = 0
            NODE_METRICS.append(node_metric.copy())
            
    except Exception as error:
        NODE_METRICS = None
        #flash("Metrics Server is not installed. If you want to see usage date please install Metrics Server.", "warning")
    
    return NODE_METRICS

def getPodMetrics():
    """Function to get pod metrics from K8S API.

    Returns:
        POD_METRICS (list): list of pod metrics
    """
    k8sClientConfigGet('Admin', None)
    POD_METRICS = list()
    pod_metric = {
        "name": "",
        "namespace": "",
        "container": "",
        "cpu": "",
        "memory": "",
        "storage": "",
    }
    try:
        k8s_pods = k8s_client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods", _request_timeout=1)
        for pod in k8s_pods['items']:
            for container in pod['containers']:
                pod_metric['name']      = pod['metadata']['name']
                pod_metric['namespace'] = pod['metadata']['namespace']
                pod_metric['container'] = container['name']
                pod_metric['cpu']       = float(parse_quantity(container['usage']['cpu']))
                pod_metric['memory']    = float(parse_quantity(container['usage']['memory']))
                pod_metric['storage']   = 0
                POD_METRICS.append(pod_metric.copy()) 
    except Exception as error:
        POD_METRICS = None
        #flash("Metrics Server is not installed. If you want to see usage date please install Metrics Server.", "warning")
    
    return POD_METRICS