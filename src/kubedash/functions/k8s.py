#!/usr/bin/env python3

import zlib, json, logging, base64
from flask import flash
from flask_login import UserMixin
from itsdangerous import base64_decode, base64_encode
from decimal import Decimal, InvalidOperation
from OpenSSL import crypto
from datetime import datetime, timezone
from pyvis.network import Network
from contextlib import nullcontext

import kubernetes.config as k8s_config
import kubernetes.client as k8s_client
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException
from kubernetes import watch

from functions.components import db, tracer, socketio

from opentelemetry import trace
from opentelemetry.trace.status import Status, StatusCode
from functions.user import email_check

##############################################################
## Helper Functions
##############################################################

logger = logging.getLogger(__name__)
logging.basicConfig(
        level="INFO",
        format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
    )

def parse_quantity(quantity):
    """
    Parse kubernetes canonical form quantity like 200Mi to a decimal number.
    Supported SI suffixes:
    base1024: Ki | Mi | Gi | Ti | Pi | Ei
    base1000: n | u | m | "" | k | M | G | T | P | E
    See https://github.com/kubernetes/apimachinery/blob/master/pkg/api/resource/quantity.go
    Input:
    quantity: string. kubernetes canonical form quantity
    Returns:
    Decimal
    Raises:
    ValueError on invalid or unknown input
    """
    if isinstance(quantity, (int, float, Decimal)):
        return Decimal(quantity)

    exponents = {"n": -3, "u": -2, "m": -1, "K": 1, "k": 1, "M": 2,
                 "G": 3, "T": 4, "P": 5, "E": 6}

    quantity = str(quantity)
    number = quantity
    suffix = None
    if len(quantity) >= 2 and quantity[-1] == "i":
        if quantity[-2] in exponents:
            number = quantity[:-2]
            suffix = quantity[-2:]
    elif len(quantity) >= 1 and quantity[-1] in exponents:
        number = quantity[:-1]
        suffix = quantity[-1:]

    try:
        number = Decimal(number)
    except InvalidOperation:
        raise ValueError("Invalid number format: {}".format(number))

    if suffix is None:
        return number

    if suffix.endswith("i"):
        base = 1024
    elif len(suffix) == 1:
        base = 1000
    else:
        raise ValueError("{} has unknown suffix".format(quantity))

    # handle SI inconsistency
    if suffix == "ki":
        raise ValueError("{} has unknown suffix".format(quantity))

    if suffix[0] not in exponents:
        raise ValueError("{} has unknown suffix".format(quantity))

    exponent = Decimal(exponents[suffix[0]])
    return number * (base ** exponent)

def calPercent(x, y, integer = False):
    """
    Percentage of 4 out of 19: 4 / 19 * 100
    """
    percent = x / y * 100
   
    if integer:
        return int(percent)
    return percent

def ErrorHandler(error, action):
    if hasattr(error, '__iter__'):
        if 'status' in error:
            if error.status == 401:
                flash("401 - Unauthorized: User cannot connect to Kubernetes", "danger")
            elif error.status == 403:
                flash("403 - Forbidden: User cannot %s" % action, "danger")
        else:
            flash(action, "danger")
            logger.error("Exception: %s \n" % action)
    else:
        flash(action, "danger")
        logger.error("Exception: %s \n" % action)

##############################################################
## Kubernetes Cluster Config
##############################################################

class k8sConfig(UserMixin, db.Model):
    __tablename__ = 'k8s_cluster_config'
    id = db.Column(db.Integer, primary_key=True)
    k8s_server_url = db.Column(db.Text, unique=True, nullable=False)
    k8s_context = db.Column(db.Text, unique=True, nullable=False)
    k8s_server_ca = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Kubernetes Server URL %r>' % self.k8s_server_url

def k8sServerConfigGet():
    with tracer.start_as_current_span("list-cluster-configs") if tracer else nullcontext() as span:
        k8s_config_list = k8sConfig.query.get(1)
        return k8s_config_list

def k8sServerConfigList():
    k8s_config_list = k8sConfig.query
    k8s_config_list_length = k8sConfig.query.count()
    return k8s_config_list, k8s_config_list_length

def k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca):
    k8s = k8sConfig.query.filter_by(k8s_server_url=k8s_server_url).first()
    k8s_data = k8sConfig(
        k8s_server_url = k8s_server_url,
        k8s_context = k8s_context,
        k8s_server_ca = k8s_server_ca
    )
    if k8s is None:
        db.session.add(k8s_data)
        db.session.commit()

def k8sServerDelete(k8s_context):
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context).first()
    if k8s:
        db.session.delete(k8s)
        db.session.commit()

def k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca):
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context_old).first()
    if k8s:
        k8s.k8s_server_url = k8s_server_url
        k8s.k8s_context = k8s_context
        k8s.k8s_server_ca = k8s_server_ca
        db.session.commit()

def k8sServerContextsList():
    k8s_contexts = []
    k8s_config_list = k8sConfig.query.all()
    for config in k8s_config_list:
        k8s_contexts.append(config.k8s_context)
    return k8s_contexts


##############################################################
## Kubernetes Namespace
##############################################################

def k8sListNamespaces(username_role, user_token):
    with tracer.start_as_current_span("list-namespaces") if tracer else nullcontext() as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        k8sClientConfigGet(username_role, user_token)
        try:
            namespace_list = k8s_client.CoreV1Api().list_namespace(_request_timeout=1)
            return namespace_list, None
        except ApiException as error:
            ErrorHandler(error, "list namespaces")
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "%s list namespaces" % error))
            namespace_list = ""
            return namespace_list, error
        except Exception as error:
            ErrorHandler("CannotConnect", "k8sListNamespaces: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sListNamespaces: %s" % error))
            namespace_list = ""
            return namespace_list, "CannotConnect"

def k8sNamespaceListGet(username_role, user_token):
    with tracer.start_as_current_span("get-namespace-list") if tracer else nullcontext() as span:
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
            ErrorHandler("CannotConnect", "k8sNamespaceListGet: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sNamespaceListGet: %s" % error))
            return namespace_list, "CannotConnect"
    
def k8sNamespacesGet(username_role, user_token):
    with tracer.start_as_current_span("get-namespace") if tracer else nullcontext() as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        k8sClientConfigGet(username_role, user_token)
        NAMESPACE_LIST = []
        try:
            namespaces, error = k8sListNamespaces(username_role, user_token)
            if error is None:
                for ns in namespaces.items:
                    NAMESPACE_DADTA = {
                        "name": "",
                        "status": "",
                        "labels": list() 
                    }
                    NAMESPACE_DADTA['name'] = ns.metadata.name
                    NAMESPACE_DADTA['status'] = ns.status.__dict__['_phase']
                    if ns.metadata.labels:
                        for key, value in ns.metadata.labels.items():
                            NAMESPACE_DADTA['labels'].append(key + "=" + value)
                    NAMESPACE_LIST.append(NAMESPACE_DADTA)
                    if tracer and span.is_recording():
                        span.set_attribute("namespace.name", ns.metadata.name)
                        span.set_attribute("namespace.role", ns.status.__dict__['_phase'])
                return NAMESPACE_LIST
            else:
                return NAMESPACE_LIST
        except Exception as error:
            ErrorHandler("CannotConnect", "k8sNamespacesGet: %s" % error)
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "k8sNamespacesGet: %s" % error))
            return NAMESPACE_LIST
    
def k8sNamespaceCreate(username_role, user_token, ns_name):
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
        api_response = api_instance.create_namespace(body, pretty=pretty, field_manager=field_manager)
        flash("Namespace Created Successfully", "success")
    except ApiException as error:
        ErrorHandler(error, "create namespace")
    except Exception as error:
        return

def k8sNamespaceDelete(username_role, user_token, ns_name):
    k8sClientConfigGet(username_role, user_token)
    pretty = 'true'
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CoreV1Api(api_client)
    try:
        api_response = api_instance.delete_namespace(ns_name, pretty=pretty)
        flash("Namespace Deleted Successfully", "success")
    except ApiException as error:
        ErrorHandler(error, "create namespace")
    except Exception as error:
        return

##############################################################
## Kubernetes Client Config
##############################################################

def k8sClientConfigGet(username_role, user_token):
    with tracer.start_as_current_span("load-client-configs") if tracer else nullcontext() as span:
        if tracer and span.is_recording():
            span.set_attribute("user.role", username_role)
        if username_role == "Admin":
            try:
                k8s_config.load_kube_config()
                if tracer and span.is_recording():
                    span.set_attribute("client.config", "local")
            except Exception as error:
                try:
                    k8s_config.load_incluster_config()
                    if tracer and span.is_recording():
                        span.set_attribute("client.config", "incluster")
                except k8s_config.ConfigException as error:
                    ErrorHandler(error, "Could not configure kubernetes python client")
                    if tracer and span.is_recording():
                        span.set_status(Status(StatusCode.ERROR, "Could not configure kubernetes python client: %s" % error))
        elif username_role == "User":
            k8sConfig = k8sServerConfigGet()
            k8s_server_url = k8sConfig.k8s_server_url
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            if k8s_server_ca:
                file = open("CA.crt", "w+")
                file.write( k8s_server_ca )
                file.close 

            configuration = k8s_client.Configuration()
            configuration.host = k8s_server_url
            configuration.verify_ssl = True
            configuration.ssl_ca_cert = 'CA.crt'
            configuration.debug = False
            configuration.api_key_prefix['authorization'] = 'Bearer'
            configuration.api_key["authorization"] = str(user_token["id_token"])
            if tracer and span.is_recording():
                span.set_attribute("client.config", "oidc")
            k8s_client.Configuration.set_default(configuration)

##############################################################
## Metrics
##############################################################

def k8sGetClusterMetric():
    with tracer.start_as_current_span("get-cluster-metrics") if tracer else nullcontext() as span:
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
                        "requestsPercent": calPercent(tmpCpuRequest, int(node.status.capacity["cpu"]), True),
                        "limits": tmpCpuLimit,
                        "limitsPercent": calPercent(tmpCpuLimit, int(node.status.capacity["cpu"]), True),
                        "usage": node_cpu_usage,
                        "usagePercent": calPercent(node_cpu_usage, int(node.status.capacity["cpu"]), True),
                    },
                    "memory": {
                        "capacity": node_mem_capacity,
                        "allocatable": node_mem_allocatable,
                        "requests": tmpMemoryRequest,
                        "requestsPercent": calPercent(tmpMemoryRequest, node_mem_capacity, True),
                        "limits": tmpMemoryLimit,
                        "limitsPercent": calPercent(tmpMemoryLimit, node_mem_capacity, True),
                        "usage": node_mem_usage,
                        "usagePercent": calPercent(node_mem_usage, node_mem_capacity, True),
                    },
                    "pod_count": {
                        "current": tmpPodCount,
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
                        "requestsPercent": calPercent(tmpTotalCpuRequest, tmpTotalCpuAllocatable, True),
                        "limits": tmpTotalCpuLimit,
                        "limitsPercent": calPercent(tmpTotalCpuLimit, tmpTotalCpuAllocatable, True),
                        "usage": total_node_cpu_usage,
                        "usagePercent": calPercent(total_node_cpu_usage, tmpTotalCpuAllocatable, True),
                    },
                    "memory": {
                        "capacity": tmpTotalMemoryCapacity,
                        "allocatable": tmpTotalMenoryAllocatable,
                        "requests": tmpTotalMemoryRequest,
                        "requestsPercent": calPercent(tmpTotalMemoryRequest, tmpTotalMenoryAllocatable, True),
                        "limits": tmpTotalMemoryLimit,
                        "limitsPercent":  calPercent(tmpTotalMemoryLimit, tmpTotalMenoryAllocatable, True),
                        "usage": total_node_mem_usage,
                        "usagePercent": calPercent(total_node_mem_usage, tmpTotalMenoryAllocatable, True),
                    },
                    "pod_count": {
                        "current": tmpTotalPodCount,
                        "allocatable": totalTotalPodAllocatable,
                    },
            }
            return clusterMetric
        except ApiException as error:
            ErrorHandler(error, "Cannot Connect to Kubernetes")
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "Cannot Connect to Kubernetes: %s" % error))
            return bad_clusterMetric
        except Exception as error:
            ErrorHandler("CannotConnect", "Cannot Connect to Kubernetes")
            if tracer and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, "Cannot Connect to Kubernetes: %s" % error))
            return bad_clusterMetric

def k8sGetNodeMetric(node_name):
    k8sClientConfigGet("Admin", None)
    totalPodAllocatable = float()
    try:
        node_list = k8s_client.CoreV1Api().list_node()
        pod_list = k8s_client.CoreV1Api().list_pod_for_all_namespaces()
        try:
            k8s_nodes = k8s_client.CustomObjectsApi().list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
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
                        "requestsPercent": calPercent(tmpCpuRequest, int(node.status.capacity["cpu"]), True),
                        "limits": tmpCpuLimit,
                        "limitsPercent": calPercent(tmpCpuLimit, int(node.status.capacity["cpu"]), True),
                        "usage": node_cpu_usage,
                        "usagePercent": calPercent(node_cpu_usage, int(node.status.capacity["cpu"]), True),
                    },
                    "memory": {
                        "capacity": node_mem_capacity,
                        "allocatable": node_mem_allocatable,
                        "requests": tmpMemoryRequest,
                        "requestsPercent": calPercent(tmpMemoryRequest, node_mem_capacity, True),
                        "limits": tmpMemoryLimit,
                        "limitsPercent": calPercent(tmpMemoryLimit, node_mem_capacity, True),
                        "usage": node_mem_usage,
                        "usagePercent": calPercent(node_mem_usage, node_mem_capacity, True),
                    },
                    "pod_count": {
                        "current": tmpPodCount,
                        "allocatable": totalPodAllocatable,
                    },
                }
                return node_metric
            else:
                return None
    except ApiException as error:
        ErrorHandler(error, "Cannot Connect to Kubernetes")
        return None
    except Exception as error:
        ErrorHandler("CannotConnect", "Cannot Connect to Kubernetes")
        return None

def k8sPVCMetric(namespace):
    k8sClientConfigGet('Admin', None)
    PVC_LIST = list()

    node_list = k8sNodesListGet("Admin", None)
    for mode in node_list:
        name = mode["name"]
        try:
            data = k8s_client.CoreV1Api().connect_get_node_proxy_with_path(name, path="stats/summary")
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
        except Exception as error:
            continue
    return PVC_LIST

def k8sGetPodMap(username_role, user_token, namespace):
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

    has_report, pod_list = k8sPodListVulnsGet(username_role, user_token, namespace)
    for po in pod_list:
        if po["status"] == "Running":
            net.add_node(po["name"], label=po["name"], shape="image", group="pod")
            if "replicationcontrollers" !=  po["owner"].split("/", 1)[0] and "jobs" != po["owner"].split("/", 1)[0]:
                on_name = po["owner"].split("/", 1)[1]
                net.add_edge(on_name, po["name"], arrowStrikethrough=False, physics=True, valu=1000)

    nodes = net.get_network_data()[0]
    edges = net.get_network_data()[1]

    return nodes, edges

##############################################################
## Kubernetes User
##############################################################

def k8sCreateUserCSR(username_role, user_token, username, user_csr_base64):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        body = k8s_client.V1CertificateSigningRequest(
            api_version = "certificates.k8s.io/v1",
            kind = "CertificateSigningRequest",
            metadata = k8s_client.V1ObjectMeta(
                name = "kubedash-user-"+username,
            ),
            spec = k8s_client.V1CertificateSigningRequestSpec(
                groups = ["system:authenticated"],
                request = user_csr_base64,
                usages = [
                    "digital signature",
                    "key encipherment",
                    "client auth",
                ],
                signer_name = "kubernetes.io/kube-apiserver-client",
                expiration_seconds = 315360000, # 10 years
            ),
        )
    pretty = "true"
    field_manager = 'KubeDash'
    try:
        api_response = api_instance.create_certificate_signing_request(body, pretty=pretty, field_manager=field_manager)
        return True, None
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->create_certificate_signing_request: %s\n" % e)
        return False, e

def k8sApproveUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    certs_api = k8s_client.CertificatesV1Api()
    csr_name = "kubedash-user-"+username
    body = certs_api.read_certificate_signing_request_status(csr_name)
    approval_condition = k8s_client.V1CertificateSigningRequestCondition(
        last_update_time=datetime.now(timezone.utc).astimezone(),
        message='This certificate was approved by KubeDash',
        reason='KubeDash',
        type='Approved',
        status='True',
    )
    body.status.conditions = [approval_condition]
    response = certs_api.replace_certificate_signing_request_approval(csr_name, body) 

def k8sReadUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        pretty = "true"
        name = "kubedash-user-"+username
    try:
        response = api_response = api_instance.read_certificate_signing_request(name, pretty=pretty)
        user_certificate_base64 = response.status.certificate
        return user_certificate_base64
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->read_certificate_signing_request: %s\n" % e)

def k8sDeleteUserCSR(username_role, user_token, username):
    k8sClientConfigGet(username_role, user_token)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CertificatesV1Api(api_client)
        pretty = "true"
        name = "kubedash-user-"+username
    try:
        api_response = api_instance.delete_certificate_signing_request(name, pretty=pretty)
    except ApiException as e:
        logger.error("Exception when calling CertificatesV1Api->delete_certificate_signing_request: %s\n" % e)

def k8sCreateUser(username, username_role='Admin', user_token=None):
    if email_check(username):
        user = username.split("@")[0]
    else:
        user = username
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    # private key
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    private_key_base64 = base64.b64encode(private_key).decode('ascii')

    # Certificate Signing Request
    req = crypto.X509Req()
    req.get_subject().CN = user
    req.set_pubkey(pkey)
    req.sign(pkey, 'sha256')
    user_csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    user_csr_base64 = base64.b64encode(user_csr).decode('ascii')

    k8sCreateUserCSR(username_role, user_token, user, user_csr_base64)
    k8sApproveUserCSR(username_role, user_token, user)
    user_certificate_base64 = k8sReadUserCSR(username_role, user_token, user)
    k8sDeleteUserCSR(username_role, user_token, user)

    return private_key_base64, user_certificate_base64

##############################################################
## Kubernetes User Role template
##############################################################

def k8sUserClusterRoleTemplateListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role()
        try:
            for cr in cluster_roles.items:
                if "template-cluster-resources___" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("___")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")
    except Exception as error:
        return
    
def k8sUserRoleTemplateListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role()
        try:
            for cr in cluster_roles.items:
                if "template-namespaced-resources___" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("___")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")
    except Exception as error:
        return
    
##############################################################
## Kubernetes Cluster Role
##############################################################

def k8sClusterRoleGet(name):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_cluster_role(
            name, pretty=pretty
        )
        return True, None
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when testing ClusterRole - %s : %s\n" % (name, e))
            return True, e
        else:
            return False, None
    except Exception as error:
        return False, None
    
def k8sClusterRoleCreate(name, body):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
    try:
        api_response = api_instance.create_cluster_role(
            body, pretty=pretty, field_manager=field_manager
        )
        return True
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when testing ClusterRole - %s : %s\n" % (name, e))
            return False
        else:
            return False
    except Exception as error:
        return False
    
def k8sClusterRolesAdd():
    admin = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-cluster-resources___admin"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = [
                        "get",
                        "list",
                        "watch"
                    ],
                    resources = [
                    "componentstatuses",
                    "namespaces",
                    "nodes",
                    "persistentvolumes",
                    "mutatingwebhookconfigurations",
                    "validatingwebhookconfigurations",
                    "customresourcedefinitions",
                    "apiservices",
                    "tokenreviews",
                    "selfsubjectaccessreviews",
                    "selfsubjectrulesreviews",
                    "subjectaccessreviews",
                    "certificatesigningrequests",
                    "runtimeclasses",
                    "podsecuritypolicies",
                    "clusterrolebindings",
                    "clusterroles",
                    "priorityclasses",
                    "csidrivers",
                    "csinodes",
                    "storageclasses",
                    "volumeattachment",
                    ]
                ),
            ]
    )
    reader = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-cluster-resources___reader"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = [
                        "get",
                        "list",
                        "watch"
                    ],
                    resources = [
                    "componentstatuses",
                    "namespaces",
                    "nodes",
                    "persistentvolumes",
                    "mutatingwebhookconfigurations",
                    "validatingwebhookconfigurations",
                    "customresourcedefinitions",
                    "apiservices",
                    "tokenreviews",
                    "selfsubjectaccessreviews",
                    "selfsubjectrulesreviews",
                    "subjectaccessreviews",
                    "certificatesigningrequests",
                    "runtimeclasses",
                    "podsecuritypolicies",
                    "clusterrolebindings",
                    "clusterroles",
                    "priorityclasses",
                    "csidrivers",
                    "csinodes",
                    "storageclasses",
                    "volumeattachment",
                    ]
                ),
            ]
    )
    developer = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___developer"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = ["*"],
                    resources = [
                    "configmaps",
                    "endpoints",
                    "pods",
                    "pods/log",
                    "pods/portforward",
                    "podtemplates",
                    "replicationcontrollers",
                    "resourcequotas",
                    "secrets",
                    "services",
                    "events",
                    "daemonsets",
                    "deployments",
                    "replicasets",
                    "ingresses",
                    "networkpolicies",
                    "poddisruptionbudgets",
                    ]
                ),
            ]
    )
    deployer = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___deployer"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["", "extensions", "apps", "networking.k8s.io", "autoscaling"],
                    verbs = ["*"],
                    resources = ["*"]
                ),
                k8s_client.V1PolicyRule(
                    api_groups = ["batch"],
                    verbs = ["*"],
                    resources = ["jobs", "cronjobs"]
                ),
            ]
    )
    operation = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___operation"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = ["*"],
                    resources = ["*"]
                ),
            ]
    )
    cluster_role_list = ["admin", "reader"]
    namespaced_role_list = ["developer", "deployer", "operation"]
    roleVars = locals()

    for role in cluster_role_list:
        name = "template-cluster-resources___" + role
        is_clusterrole_exists, error = k8sClusterRoleGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

    for role in namespaced_role_list:
        name = "template-namespaced-resources___" + role
        is_clusterrole_exists, error = k8sClusterRoleGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

##############################################################
## Kubernetes Nodes
##############################################################

def k8sListNodes(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    node_list = list()
    try:
        node_list = k8s_client.CoreV1Api().list_node(_request_timeout=1)
        return node_list, None
    except ApiException as error:
        ErrorHandler(error, "list nodes")
        return node_list, error
    except Exception as error:
        ErrorHandler("CannotConnect", "k8sListNodes: %s" % error)
        return node_list, "CannotConnect"
    
def k8sNodesListGet(username_role, user_token):
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
                else:
                    NODE_INFO['role'] = "Worker"
            for key, value in no.status.node_info.__dict__.items():
                if key == "_container_runtime_version":
                    NODE_INFO['runtime'] = value
                elif key == "_kubelet_version":
                    NODE_INFO['version'] = value
            
            for key, value in no.status.conditions[-1].__dict__.items():
                if key == "_type":
                    NODE_INFO['status'] = value
            if NODE_INFO['role'] == None:
                NODE_INFO['role'] = "Worker"
            NODE_LIST.append(NODE_INFO)
        return NODE_LIST
    else:
        return NODE_LIST
    
def k8sNodeGet(username_role, user_token, no_name):
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
                NODE_INFO['labels'] = no.metadata.labels
                NODE_INFO['pod_cidr'] = no.spec.pod_cidr
                NODE_INFO['os'] = no.status.node_info.os_image
                NODE_INFO['conditions'] = list()
                for co in no.status.conditions:
                    NODE_INFO['conditions'].append([co.type, co.status, co.reason, co.message])
                for label, value in no.metadata.labels.items():
                    if "node-role.kubernetes.io" in label:
                        NODE_INFO['role'] = label.split('/')[1].capitalize()
                    else:
                        NODE_INFO['role'] = "Worker"
                for key, value in no.status.node_info.__dict__.items():
                    if key == "_container_runtime_version":
                        NODE_INFO['runtime'] = value
                    elif key == "_kubelet_version":
                        NODE_INFO['version'] = value
                
                for key, value in no.status.conditions[-1].__dict__.items():
                    if key == "_type":
                        NODE_INFO['status'] = value
                if NODE_INFO['role'] == None:
                    NODE_INFO['role'] = "Worker"
        return NODE_INFO
    else:
        return NODE_INFO

##############################################################
# Workloads
##############################################################
## StatefulSets
##############################################################

def k8sStatefulSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    STATEFULSET_LIST = list()
    try:
        statefulset_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(ns)
        for sfs in statefulset_list.items:
            STATEFULSET_DATA = {
                "name": sfs.metadata.name,
                "desired": "",
                "current": "",
                "ready": "",
            }
            if sfs.status.replicas:
                STATEFULSET_DATA['desired'] = sfs.status.replicas
            else:
                STATEFULSET_DATA['desired'] = 0
            if sfs.status.current_replicas:
                STATEFULSET_DATA['current'] = sfs.status.current_replicas
            else:
                STATEFULSET_DATA['current'] = 0
            if sfs.status.ready_replicas:
                STATEFULSET_DATA['ready'] = sfs.status.ready_replicas
            else:
                STATEFULSET_DATA['ready'] = 0
            STATEFULSET_LIST.append(STATEFULSET_DATA)
        return STATEFULSET_LIST
    except ApiException as error:
        ErrorHandler(error, "get statefullsets list")
        return STATEFULSET_LIST
    except Exception as error:
        return STATEFULSET_LIST

##############################################################
## DaemonSets
##############################################################

def k8sDaemonSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DAEMONSET_LIST = list()
    try:
        daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(ns)
        for ds in daemonset_list.items:
            DAEMONSET_DATA = {
                "name": ds.metadata.name,
                "desired": "",
                "current": "",
                "ready": "",
            }
            if ds.status.desired_number_scheduled:
                DAEMONSET_DATA['desired'] = ds.status.desired_number_scheduled
            else:
                DAEMONSET_DATA['desired'] = 0
            if ds.status.current_number_scheduled:
                DAEMONSET_DATA['current'] = ds.status.current_number_scheduled
            else:
                DAEMONSET_DATA['current'] = 0
            if ds.status.number_ready:
                DAEMONSET_DATA['ready'] = ds.status.number_ready
            else:
                DAEMONSET_DATA['ready'] = 0
            DAEMONSET_LIST.append(DAEMONSET_DATA)
        return DAEMONSET_LIST
    except ApiException as error:
        ErrorHandler(error, "get daemonsets list")
        return DAEMONSET_LIST
    except Exception as error:
        return DAEMONSET_LIST

##############################################################
## Deployments
##############################################################

def k8sDeploymentsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DEPLOYMENT_LIST = list()
    ready_replicas = 0
    replicas = 0
    try:
        deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(ns)
        for d in deployment_list.items:
            DEPLOYMENT_DATA = {
                "name": d.metadata.name,
                "status": "",
                "labels": list(),
                "desired": "",
                "updated": "",
                "ready": "",
            }
            if d.status.ready_replicas:
                DEPLOYMENT_DATA['ready']  = d.status.ready_replicas
            else:
                DEPLOYMENT_DATA['ready']  = 0
            if d.status.replicas:
                DEPLOYMENT_DATA['desired'] = d.status.replicas
            else:
                DEPLOYMENT_DATA['desired'] = 0
            if d.status.updated_replicas:
                DEPLOYMENT_DATA['updated'] = d.status.updated_replicas
            else:
                DEPLOYMENT_DATA['desired'] = 0
            for key, value in d.metadata.labels.items():
                DEPLOYMENT_DATA['labels'].append(key + "=" + value)
            DEPLOYMENT_LIST.append(DEPLOYMENT_DATA)
        return DEPLOYMENT_LIST
    except ApiException as error:
        ErrorHandler(error, "get deployments list")
        return DEPLOYMENT_LIST
    except Exception as error:
        return DEPLOYMENT_LIST

##############################################################
## ReplicaSets
##############################################################

def k8sReplicaSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    REPLICASET_LIST = list()
    try:
        replicaset_list = k8s_client.AppsV1Api().list_namespaced_replica_set(ns)
        for rs in replicaset_list.items:
            REPLICASET_DATA = {
                "name": rs.metadata.name,
                "owner": "",
                "desired": "",
                "current": "",
                "ready": "",
            }
            if rs.status.fully_labeled_replicas:
                REPLICASET_DATA['desired'] = rs.status.fully_labeled_replicas
            else:
                REPLICASET_DATA['desired'] = 0
            if rs.status.available_replicas:
                REPLICASET_DATA['current'] = rs.status.available_replicas
            else:
                REPLICASET_DATA['current'] = 0
            if rs.status.ready_replicas:
                REPLICASET_DATA['ready'] = rs.status.ready_replicas
            else:
                REPLICASET_DATA['ready'] = 0
            if rs.metadata.owner_references:
                for owner in rs.metadata.owner_references:
                    REPLICASET_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            REPLICASET_LIST.append(REPLICASET_DATA)
        return REPLICASET_LIST
    except ApiException as error:
        ErrorHandler(error, "get replicasets list")
        return REPLICASET_LIST
    except Exception as error:
        return REPLICASET_LIST

##############################################################
## Pods
##############################################################

def k8sPodListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POD_LIST = list()
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
        for pod in pod_list.items:
            POD_SUM = {
                "name": pod.metadata.name,
                "status": pod.status.phase,
                "owner": "",
                "pod_ip": pod.status.pod_ip,
            }
            if pod.metadata.owner_references:
                for owner in pod.metadata.owner_references:
                    POD_SUM['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            POD_LIST.append(POD_SUM)
        return POD_LIST
    except ApiException as error:
        ErrorHandler(error, "get pod list")
        return POD_LIST

def k8sPodGet(username_role, user_token, ns, po):
    k8sClientConfigGet(username_role, user_token)
    POD_DATA = {}
    try: 
        pod_data = k8s_client.CoreV1Api().read_namespaced_pod(po, ns)
        POD_DATA = {
            # main
            "name": po,
            "namespace": ns,
            "labels": list(),
            "owner": "",
            "node": pod_data.spec.node_name,
            "priority": pod_data.spec.priority,
            "priority_class_name": pod_data.spec.priority_class_name,
            "runtime_class_name": pod_data.spec.runtime_class_name,
            # Containers
            "containers": list(),
            "init_containers": list(),
            #  Related Resources
            "image_pull_secrets": [],
            "service_account": pod_data.spec.service_account_name,
            "pvc": list(),
            "cm": list(),
            "secrets": list(),
            # Security
            "security_context": pod_data.spec.security_context.to_dict(),
            # Conditions
            "conditions": list(),
        }
        if pod_data.metadata.labels:
            for key, value in pod_data.metadata.labels.items():
                label = {
                    key: value
                }
                POD_DATA['labels'].append(label)
        if pod_data.metadata.owner_references:
            for owner in pod_data.metadata.owner_references:
                POD_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
        for c in  pod_data.spec.containers:
            if c.env:
                for e in c.env:
                    ed = e.to_dict()
                    for name, val in ed.items():
                        if "value_from" in name and val is not None:
                            for key, value in val.items():
                                if "secret_key_ref" in key and value:
                                    for n, v in value.items():
                                        if "name" in n:
                                            POD_DATA['secrets'].append(v)
            for cs in pod_data.status.container_statuses:
                if cs.name == c.name:
                    if cs.ready:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": "Running",
                            "restarts": cs.restart_count,
                        }
                    else:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": cs.state.waiting.reason,
                            "restarts": cs.restart_count,
                        }
            POD_DATA['containers'].append(CONTAINERS)
        if pod_data.spec.init_containers:
            for ic in pod_data.spec.init_containers:
                for ics in pod_data.status.init_container_statuses:
                    if ics.name == ic.name:
                        if ics.ready:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.terminated.reason,
                                "restarts": ics.restart_count,
                            }
                        else:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.waiting.reason,
                                "restarts": ics.restart_count,
                            }
                        POD_DATA['init_containers'].append(CONTAINERS)
        if pod_data.spec.image_pull_secrets:
            for ips in pod_data.spec.image_pull_secrets:
                POD_DATA['image_pull_secrets'].append(ips.to_dict())
        for v in pod_data.spec.volumes:
            # secret
            if v.persistent_volume_claim:
                POD_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
            if v.config_map:
                POD_DATA['cm'].append(v.config_map.name)
            if v.secret:
                POD_DATA['secrets'].append(v.secret.secret_name)
        for c in pod_data.status.conditions:
            CONDITION = {
                c.type: c.status
            }
            POD_DATA['conditions'].append(CONDITION)
        return POD_DATA
    except ApiException as error:
        ErrorHandler(error, "get pods in this namespace")
        return POD_DATA
    except Exception as error:
        return POD_DATA

def k8sPodListVulnsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POD_VULN_LIST = list()
    HAS_REPORT = False
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")
        return HAS_REPORT, POD_VULN_LIST
    except Exception as error:
        return HAS_REPORT, POD_VULN_LIST
    try:
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object("trivy-operator.devopstales.io", "v1", ns, "vulnerabilityreports")
        HAS_REPORT = True
    except Exception as error:
        vulnerabilityreport_list = False

    for pod in pod_list.items:
        POD_VULN_SUM = {
            "name": pod.metadata.name,
            "status": pod.status.phase,
            "owner": "",
            "pod_ip": pod.status.pod_ip,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_status": None,
        }
        if pod.metadata.owner_references:
            for owner in pod.metadata.owner_references:
                POD_VULN_SUM['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
        
        if vulnerabilityreport_list:
            for vr in vulnerabilityreport_list['items']:
                if vr['metadata']['labels']['trivy-operator.pod.name'] == pod.metadata.name:
                    POD_VULN_SUM['critical'] += vr['report']['summary']['criticalCount']
                    POD_VULN_SUM['high'] += vr['report']['summary']['highCount']
                    POD_VULN_SUM['medium'] += vr['report']['summary']['mediumCount']
                    POD_VULN_SUM['low'] += vr['report']['summary']['lowCount']

        if POD_VULN_SUM['critical'] > 0 or POD_VULN_SUM['high'] > 0 or POD_VULN_SUM['medium'] > 0 or POD_VULN_SUM['low'] > 0:
            POD_VULN_SUM['scan_status'] = "OK"
        POD_VULN_LIST.append(POD_VULN_SUM)

    return HAS_REPORT, POD_VULN_LIST

def k8sPodVulnsGet(username_role, user_token, ns, pod):
    k8sClientConfigGet(username_role, user_token)
    POD_VULNS = {}
    HAS_REPORT = False
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")
        return HAS_REPORT, POD_VULNS
    except Exception as error:
        return HAS_REPORT, POD_VULNS
    try:
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object("trivy-operator.devopstales.io", "v1", ns, "vulnerabilityreports")
    except Exception as error:
        vulnerabilityreport_list = None

    for po in pod_list.items:
        POD_VULNS = {}
        if po.metadata.name == pod:
            if vulnerabilityreport_list is not None:
                for vr in vulnerabilityreport_list['items']:
                    if vr['metadata']['labels']['trivy-operator.pod.name'] == po.metadata.name:
                        HAS_REPORT = True
                        VULN_LIST = list()
                        for vuln in vr['report']['vulnerabilities']:
                            VULN_LIST.append({
                                "vulnerabilityID": vuln['vulnerabilityID'],
                                "severity": vuln['severity'],
                                "score": vuln['score'],
                                "resource": vuln['resource'],
                                "installedVersion": vuln['installedVersion'],
                                #"publishedDate": vuln['publishedDate'],
                                #"fixedVersion": vuln['fixedVersion'],
                            })
                        POD_VULNS.update({vr['metadata']['labels']['trivy-operator.container.name']: VULN_LIST})
                return HAS_REPORT, POD_VULNS
            else:
                return False, None

        # PublishedDate, FixedVersion
##############################################################
## Pod Logs
##############################################################

def k8sPodLogsStream(username_role, user_token, namespace, pod_name):
    k8sClientConfigGet(username_role, user_token)
    w = watch.Watch()
    for line in w.stream(k8s_client.CoreV1Api().read_namespaced_pod_log, name=pod_name, namespace=namespace):
        socketio.emit('response',
                            {'data': str(line)}, namespace="/log")

##############################################################
## Pod Exec
##############################################################

def k8sPodExecSocket(username_role, user_token, namespace, pod_name):
    k8sClientConfigGet(username_role, user_token)
    wsclient = stream(k8s_client.CoreV1Api().connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=['/bin/sh'],
            stderr=True, stdin=True,
            stdout=True, tty=True,
            _preload_content=False)
    return wsclient

def k8sPodExecStream(wsclient):
    while True:
        socketio.sleep(0.01)
        wsclient.update(timeout=1)
        """Read from wsclient"""
        output = wsclient.read_all()
        if output:
            """write back to socket"""
            socketio.emit(
                "response", {"output": output}, namespace="/exec")

##############################################################
# Security
##############################################################
## Service Account
##############################################################

def k8sSaListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    SA_LIST = list()
    try:
        service_accounts = k8s_client.CoreV1Api().list_namespaced_service_account(ns)
        for sa in service_accounts.items:
            SA_INFO = {
                "name": sa.metadata.name,
                "secret": "",
                "pull_secret": "",
            }
            try:
                SA_INFO['pull_secret'] = sa.image_pull_secrets[0].name
            except:
                SA_INFO['pull_secret'] = sa.image_pull_secrets
            try:
                SA_INFO['secret'] = sa.secrets[0].name
            except:
                SA_INFO['secret'] = sa.secrets
            SA_LIST.append(SA_INFO)
        return SA_LIST
    except ApiException as error:
        ErrorHandler(error, "get service account list")
        return SA_LIST
    except Exception as error:
        return SA_LIST

##############################################################
## Role
##############################################################

def k8sRoleListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    ROLE_LIST = list()
    try:
        role_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role(ns)
        for role in role_list.items:
            ROLE_INFO = {
                "name": role.metadata.name,
                "annotations": role.metadata.annotations,
                "labels": role.metadata.labels,
                "rules": role.rules,
            }
            ROLE_LIST.append(ROLE_INFO)
        return ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get roles list")
        return ROLE_LIST
    except Exception as error:
        return ROLE_LIST

##############################################################
##  Role Binding
##############################################################

def k8sRoleBindingListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    ROLE_BINDING_LIST = list()
    try:
        role_binding_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role_binding(ns)
        for rb in role_binding_list.items:
            ROLE_BINDING_INFO = {
            "name": rb.metadata.name,
            "role": list(),
            "user": list(),
            "group": list(),
            "ServiceAccount": list(),
            }
            if type(rb.role_ref) == list:
                for role in rb.role_ref:
                    ROLE_BINDING_INFO['role'].append({role.kind: role.name})
            else:
                ROLE_BINDING_INFO['role'].append({rb.role_ref.kind: rb.role_ref.name})
            for obj in rb.subjects:
                if obj.kind == "User":
                    ROLE_BINDING_INFO['user'].append(obj.name)
                elif obj.kind == "Group":
                    ROLE_BINDING_INFO['group'].append(obj.name)
                elif obj.kind == "ServiceAccount":
                    ROLE_BINDING_INFO['ServiceAccount'].append({obj.name: obj.namespace})
            ROLE_BINDING_LIST.append(ROLE_BINDING_INFO)    
        return ROLE_BINDING_LIST
    except ApiException as error:
        ErrorHandler(error, "get role bindings list")
        return ROLE_BINDING_LIST
    except Exception as error:
        return ROLE_BINDING_LIST

def k8sRoleBindingGet(obeject_name, namespace):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_namespaced_role_binding(
            obeject_name, namespace, pretty=pretty
        )
        return True, None
    except ApiException as e:
        if e.status == 404:
            return False, None
        else:
            logger.error("Exception when testing NamespacedRoleBinding - %s in %s: %s\n" % (obeject_name, namespace, e))
            return None, e
    except Exception as error:
        logger.error("Unknow Error")
        return None, "Unknow Error"

def k8sRoleBindingCreate(user_role, namespace, username):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
        if email_check(username):
            user = username.split("@")[0]
        else:
            user = username
        obeject_name = user + "___" + "kubedash" + "___" + user_role
        body = k8s_client.V1RoleBinding(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "RoleBinding",
            metadata = k8s_client.V1ObjectMeta(
                name = obeject_name,
                namespace = namespace
            ),
            role_ref = k8s_client.V1RoleRef(
                api_group = "rbac.authorization.k8s.io",
                kind = "ClusterRole",
                name = "template-namespaced-resources___" + user_role,
            ),
            subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "User",
                    name = username,
                    namespace = namespace,
                )
            ]
        )
    try:
        api_response = api_instance.create_namespaced_role_binding(
            namespace, body, pretty=pretty, field_manager=field_manager
        )
        return True, None
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when creating RoleBinding - %s in %s: %s\n" % (obeject_name, namespace, e))
            return True, e
        else:
            return False, None


def k8sRoleBindingAdd(user_role, username, user_namespaces, user_all_namespaces):
    if email_check(username):
        user = username.split("@")[0]
    else:
        user = username
    obeject_name = user + "___" + "kubedash" + "___" + user_role
    if user_all_namespaces:
        namespace_list, error = k8sNamespaceListGet("Admin", None)
    else:
        namespace_list = user_namespaces
    for namespace in namespace_list:
        is_rolebinding_exists, error = k8sRoleBindingGet(obeject_name, namespace)
        if error:
            ErrorHandler(error, "get RoleBinding %s" % obeject_name)
        else:
            if is_rolebinding_exists:
                ErrorHandler("CannotConnect", "RoleBinding %s alredy exists in %s namespace" % (obeject_name, namespace))
                logger.info("RoleBinding %s alredy exists" % obeject_name) # WARNING
            else:
                k8sRoleBindingCreate(user_role, namespace, username)


##############################################################
## Cluster Role
##############################################################

def k8sClusterRoleListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role()
        try:
            for cr in cluster_roles.items:
                CLUSTER_ROLE_DATA = {
                    "name": cr.metadata.name,
                    "annotations": cr.metadata.annotations,
                    "labels": cr.metadata.labels,
                    "rules": cr.rules,
                }
                CLUSTER_ROLE_LIST.append(CLUSTER_ROLE_DATA)
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster role list")
        return CLUSTER_ROLE_LIST
    except Exception as error:
        return CLUSTER_ROLE_LIST

##############################################################
## Cluster Role Bindings
##############################################################

def k8sClusterRoleBindingListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_BINDING_LIST = []
    try:
        cluster_role_bindings = k8s_client.RbacAuthorizationV1Api().list_cluster_role_binding()
        for crb in cluster_role_bindings.items:
            CLUSTER_ROLE_BINDING_INFO = {
            "name": crb.metadata.name,
            "role": list(),
            "user": list(),
            "group": list(),
            "ServiceAccount": list(),
            }
            if type(crb.role_ref) == list:
                for role in crb.role_ref:
                    CLUSTER_ROLE_BINDING_INFO['role'].append({role.kind: role.name})
            else:
                CLUSTER_ROLE_BINDING_INFO['role'].append({crb.role_ref.kind: crb.role_ref.name})
            if crb.subjects:
                for obj in crb.subjects:
                    if obj.kind == "User":
                        CLUSTER_ROLE_BINDING_INFO['user'].append(obj.name)
                    elif obj.kind == "Group":
                        CLUSTER_ROLE_BINDING_INFO['group'].append(obj.name)
                    elif obj.kind == "ServiceAccount":
                        CLUSTER_ROLE_BINDING_INFO["ServiceAccount"].append({obj.name: obj.namespace})

                    CLUSTER_ROLE_BINDING_LIST.append(CLUSTER_ROLE_BINDING_INFO)
        return CLUSTER_ROLE_BINDING_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster role bindings list")
        return CLUSTER_ROLE_BINDING_LIST
    except Exception as error:
        return CLUSTER_ROLE_BINDING_LIST

def k8sClusterRoleBindingGet(obeject_name):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_cluster_role_binding(
            obeject_name, pretty=pretty
        )
        return True, None
    except ApiException as e:
        if e.status == 404:
            return False, None
        else:
            logger.error("Exception when testing ClusterRoleBinding - %s: %s\n" % (obeject_name, e))
            return None, e
    except Exception as error:
        logger.error("Unknow Error")
        return None, "Unknow Error"

def k8sClusterRoleBindingCreate(user_cluster_role, username):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
        if email_check(username):
            user = username.split("@")[0]
        else:
            user = username
        obeject_name = user + "___" + "kubedash" + "___" + user_cluster_role
        body = k8s_client.V1ClusterRoleBinding(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRoleBinding",
            metadata = k8s_client.V1ObjectMeta(
                name = obeject_name,
            ),
            role_ref = k8s_client.V1RoleRef(
                api_group = "rbac.authorization.k8s.io",
                kind = "ClusterRole",
                name = "template-cluster-resources___" + user_cluster_role,
            ),
            subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "User",
                    name = username,
                )
            ]
        )
    try:
        pi_response = api_instance.create_cluster_role_binding(
            body, pretty=pretty, field_manager=field_manager
        )
        flash("User Role Created Successfully", "success")
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when creating ClusterRoleBinding - %s: %s\n" % (user_cluster_role, e))
        else:
            logger.info("ClusterRoleBinding %s alredy exists" % obeject_name) # WARNING

def k8sClusterRoleBindingAdd(user_cluster_role, username):
    if email_check(username):
        user = username.split("@")[0]
    else:
        user = username
    obeject_name = user + "___" + "kubedash" + "___" + user_cluster_role
    is_clusterrolebinding_exists, error = k8sClusterRoleBindingGet(obeject_name)
    if error:
        ErrorHandler(error, "get ClusterRoleBinding %s" % obeject_name)
    else:
        if is_clusterrolebinding_exists:
            ErrorHandler("CannotConnect", "ClusterRoleBinding %s alredy exists" % obeject_name)
            logger.info("ClusterRoleBinding %s alredy exists" % obeject_name) # WARNING
        else:
            k8sClusterRoleBindingCreate(user_cluster_role, username)

##############################################################
## Secrets
##############################################################

def k8sSecretListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    SECRET_LIST = list()
    secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace)
    for secret in secret_list.items:
        SECRET_DATA = {
            "name": secret.metadata.name,
            "type": secret.type,
            "annotations": secret.metadata.annotations,
            "labels": secret.metadata.labels,
            "data": secret.data,
            "created": secret.metadata.creation_timestamp,
            "version": secret.metadata.resource_version,
        }
        SECRET_LIST.append(SECRET_DATA)

    return SECRET_LIST

##############################################################
# Network
##############################################################
## Ingresses Class
##############################################################

def k8sIngressClassListGet(username_role, user_token,):
    k8sClientConfigGet(username_role, user_token)
    ING_LIST = list()
    try:
        ingress_class_list = k8s_client.NetworkingV1Api().list_ingress_class()
        for ic in ingress_class_list.items:
            ING_INFO = {
                "name": ic.metadata.name,
                "created": ic.metadata.creation_timestamp,
                "annotations": ic.metadata.annotations,
                "labels": ic.metadata.labels,
                "controller": ic.spec.controller,
                "parameters": ic.spec.parameters.to_dict(),
            }
            ING_LIST.append(ING_INFO)
        return ING_LIST
    except ApiException as error:
        ErrorHandler(error, "get ingress class list")
        return ING_LIST
    except Exception as error:
        return ING_LIST

##############################################################
## Ingress
##############################################################

def k8sIngressListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    ING_LIST = list()
    #try:
    ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(ns)
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
            "created": ingress.metadata.creation_timestamp,
            "annotations": ingress.metadata.annotations,
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
    #except ApiException as error:
    #    ErrorHandler(error, "get ingress list")
    #    return ING_LIST
    #except Exception as error:
    #    return ING_LIST
    
##############################################################
## Network Policy
##############################################################

def k8sNetworkPolicyListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POLICY_LIST = list()
    try:
        policy_list = k8s_client.NetworkingV1beta1Api().list_namespaced_network_policy(ns)
        for policy in policy_list.items:
            POLICY_INFO = {
                "name": policy.metadata.name,
                "created": policy.metadata.creation_timestamp,
                "annotations": policy.metadata.annotations,
                "labels": policy.metadata.labels,
                "policy_type": policy.spec.policy_type,
                "egress": policy.spec.egress,
                "ingress": policy.spec.ingress,
                "pod_selector": policy.spec.pod_selector,
            }
            POLICY_LIST.append(POLICY_INFO)
        return POLICY_LIST
    except ApiException as error:
        ErrorHandler(error, "get network policy list")
        return POLICY_LIST
    except Exception as error:
        return POLICY_LIST

##############################################################
# Storage
##############################################################
## Stotage Class
##############################################################

def k8sStorageClassListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    SC_LIST = list()
    try:
        storage_classes = k8s_client.StorageV1Api().list_storage_class()
        for sc in storage_classes.items:
            SC = {
                "name": sc.metadata.name,
                "created": sc.metadata.creation_timestamp,
                "annotations": sc.metadata.annotations,
                "labels": sc.metadata.labels,
                "parameters": sc.parameters,
                "provisioner": sc.provisioner,
                "reclaim_policy": sc.reclaim_policy,
                "volume_binding_mode": sc.volume_binding_mode,
            }
            SC_LIST.append(SC)
        return SC_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster Stotage Class list")
        return SC_LIST
    except Exception as error:
        return SC_LIST   

##############################################################
## Persistent Volume Claim
##############################################################

def k8sPersistentVolumeClaimListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    PVC_LIST = list()
    persistent_volume_clames= k8s_client.CoreV1Api().list_namespaced_persistent_volume_claim(namespace)
    for pvc in persistent_volume_clames.items:
        PVC = {
            "status": pvc.status.phase,
            "name": pvc.metadata.name,
            "created": pvc.metadata.creation_timestamp,
            "annotations": pvc.metadata.annotations,
            "labels": pvc.metadata.labels,
            "access_modes": pvc.spec.access_modes,
            "storage_class_name": pvc.spec.storage_class_name,
            "volume_name": pvc.spec.volume_name,
            "volume_mode": pvc.spec.volume_mode,
            "capacity": pvc.status.capacity['storage'],
        }
        PVC_LIST.append(PVC)

    return PVC_LIST

##############################################################
## Persistent Volume
##############################################################

def k8sPersistentVolumeListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    PV_LIST = list()
    try:
        pv_list = k8s_client.CoreV1Api().list_persistent_volume()
        for pv in pv_list.items:
            if namespace == pv.spec.claim_ref.namespace:
                PV = {
                    "status": pv.status.phase,
                    "name": pv.metadata.name,
                    "created": pv.metadata.creation_timestamp,
                    "annotations": pv.metadata.annotations,
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
        ErrorHandler(error, "get cluster Persistent Volume list")
        return PV_LIST
    except Exception as error:
        return PV_LIST 

##############################################################
## ConfigMap
##############################################################

def k8sConfigmapListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    CONFIGMAP_LIST = list()
    configmap_list = k8s_client.CoreV1Api().list_namespaced_config_map(namespace)
    for configmap in configmap_list.items:
        CONFIGMAP_DATA = {
            "name": configmap.metadata.name,
            "created": configmap.metadata.creation_timestamp,
            "annotations": configmap.metadata.annotations,
            "labels": configmap.metadata.labels,
            "data": configmap.data,
            "version": configmap.metadata.resource_version,
        }
        CONFIGMAP_LIST.append(CONFIGMAP_DATA)

    return CONFIGMAP_LIST

##############################################################
## Helm Charts
##############################################################

def k8sHelmChartListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    HAS_CHART = False
    CHART_LIST = {}
    CHART_DATA = list()
    try:
        secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, _request_timeout=1)
        for secret in secret_list.items:

            if secret.type == 'helm.sh/release.v1':
                base64_secret_data = str(base64_decode(secret.data['release']), 'UTF-8')
                secret_data = json.loads(zlib.decompress(base64_decode(base64_secret_data), 16 + zlib.MAX_WBITS).decode('utf-8'))
                if 'icon' in secret_data['chart']['metadata']:
                    helm_icon = secret_data['chart']['metadata']['icon']
                else:
                    helm_icon = None
                if 'appVersion' in secret_data['chart']['metadata']:
                    helm_api_version = secret_data['chart']['metadata']['appVersion']
                else:
                    helm_api_version = None

                # Get the Kubernetes resources for the release
                chart_name = secret_data['chart']['metadata']['name']
                release_name = secret_data['name']
                label_selector = f"app.kubernetes.io/instance={release_name},app.kubernetes.io/name={chart_name}"
                pod_list = k8s_client.CoreV1Api().list_namespaced_pod(namespace, label_selector=label_selector).items
                svc_list = k8s_client.CoreV1Api().list_namespaced_service(namespace, label_selector=label_selector).items
                deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(namespace, label_selector=label_selector).items

                CHART_DATA.append({
                    'icon': helm_icon,
                    'status': secret_data['info']['status'],
                    'chart': chart_name + "-" + secret_data['chart']['metadata']['version'],
                    'appVersion': helm_api_version,
                    'revision': secret_data['version'],
                    'updated': secret_data['info']['last_deployed'],
                    "pods": [pod.metadata.name for pod in pod_list],
                    "services": [svc.metadata.name for svc in svc_list],
                    "deployments": [deployment.metadata.name for deployment in deployment_list],
                    "templates": secret_data["chart"]['templates'],
                })
                HAS_CHART = True
                CHART_LIST.update({secret_data['name']: CHART_DATA})
            
        return HAS_CHART, CHART_LIST
    except ApiException as error:
        ErrorHandler(error, "get helm release")
        return HAS_CHART, CHART_LIST
    except Exception as error:
        ErrorHandler("CannotConnect", "Cannot Connect to Kubernetes")
        return HAS_CHART, CHART_LIST
 
##############################################################
## User Priviliges
##############################################################


def k8sUserPriviligeList(username_role="Admin", user_token=None, user="admin"):
    ROLE_LIST = []
    CLUSTER_ROLE_LIST = []
    USER_ROLES = []
    USER_CLUSTER_ROLES = []

    k8sClientConfigGet(username_role, user_token)

    namespaces, error = k8sNamespaceListGet(username_role, user_token)
    if not error:
        for ns in namespaces:
            role_binding_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role_binding(ns)
            for rb in role_binding_list.items:
                for obj in rb.subjects:
                    if obj.kind == "User" and obj.name == user:
                        if rb.role_ref.kind == "ClusterRole":
                            CLUSTER_ROLE_LIST.append(rb.role_ref.name)
                        elif rb.role_ref.kind == "Role":
                            ROLE_LIST.append([rb.role_ref.namespace, rb.role_ref.name])

    cluster_role_bindings = k8s_client.RbacAuthorizationV1Api().list_cluster_role_binding()
    for crb in cluster_role_bindings.items:
        if crb.subjects:
            for obj in crb.subjects:
                if obj.kind == "User" and obj.name == user:
                    CLUSTER_ROLE_LIST.append(crb.role_ref.name)

    for r in ROLE_LIST:
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
            pretty = 'true'
        try:
            ROLE = api_instance.read_namespaced_role(r[1], r[0], pretty=pretty)
            for rr in ROLE.rules:
                USER_ROLES.append({r[1]: rr})
        except:
            continue
    
    for cr in CLUSTER_ROLE_LIST:
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
            pretty = 'true'
        try:
            CLUSTER_ROLE = api_instance.read_cluster_role(cr, pretty=pretty)
            for crr in CLUSTER_ROLE.rules:
                USER_CLUSTER_ROLES.append(crr)
        except Exception as error:
            continue
    return USER_CLUSTER_ROLES, USER_ROLES

##############################################################

