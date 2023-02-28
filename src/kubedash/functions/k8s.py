import kubernetes.config as k8s_config
import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException


from itsdangerous import base64_decode
from decimal import Decimal, InvalidOperation
from flask import flash
from flask_login import UserMixin

from functions.components import db

##############################################################
## Helper Functions
##############################################################

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
    if 'status' in error:
        if error.status == 401:
            flash("401 - Unauthorized: User cannot connect to Kubernetes", "danger")
        elif error.status == 403:
            flash("403 - Forbidden: User cannot %s" % action, "danger")
    else:
        flash(action, "danger")
        #app.logger.error("Exception: %s \n" % action)

##############################################################
## Kubernetes Config
##############################################################

class k8sConfig(UserMixin, db.Model):
    __tablename__ = 'k8s_config'
    id = db.Column(db.Integer, primary_key=True)
    k8s_server_url = db.Column(db.Text, unique=True, nullable=False)
    k8s_context = db.Column(db.Text, unique=True, nullable=False)
    k8s_server_ca = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Kubernetes Server URL %r>' % self.k8s_server_url

def k8sServerConfigGet():
    # User.query.filter_by(username=current_username).first()
    k8s_config_list = k8sConfig.query.get(1)
    return k8s_config_list

##############################################################
## Kubernetes Client Config
##############################################################

def k8sClientConfigGet(username_role, user_token):
    if username_role == "Admin":
        # k8s_config.load_incluster_config()
        k8s_config.load_kube_config()
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
        k8s_client.Configuration.set_default(configuration)

##############################################################
## Metrics
##############################################################

def k8sGetNodeMetric():
    k8sClientConfigGet("Admin", None)
    totalPodAllocatable = float()
    tmpTotalCpuCapacity = int()
    tmpTotalMemoryCapacity = int()
    tmpTotalCpuAllocatable = int()
    tmpTotalMenoryAllocatable = int()
    tmpTotalCpuLimit = float()
    tmpTotalMemoryLimit = float()
    tmpTotalCpuRequest = float()
    tmpTotalMemoryRequest = float()
    clusterMetric = {
        "nodes": [],
        "clusterTotals": {}
    }
    try:
        node_list = k8s_client.CoreV1Api().list_node()
        pod_list = k8s_client.CoreV1Api().list_pod_for_all_namespaces()

        for node in node_list.items:
            tmpPodCount = int()
            tmpCpuLimit = float()
            tmpMemoryLimit = float()
            tmpCpuRequest = float()
            tmpMemoryRequest = float()
            for pod in pod_list.items:
                if pod.spec.node_name == node.metadata.name and pod.status.phase == 'Running':
                    tmpPodCount += 1
                    for container in pod.spec.containers:
                        if container.resources.limits:
                            if 'cpu' in container.resources.limits:
                                tmpCpuLimit += float(parse_quantity(container.resources.limits['cpu']))
                            if 'memory' in container.resources.limits:
                                tmpMemoryLimit += float(parse_quantity(container.resources.limits['memory']))
                        if container.resources.requests:
                            if 'cpu' in container.resources.requests:
                                #print("base: %s" % container.resources.requests['cpu'])
                                #print("convert: %s" % float(parse_quantity(container.resources.requests['cpu'])))
                                tmpCpuRequest += float(parse_quantity(container.resources.requests['cpu']))
                            if 'memory' in container.resources.requests:
                                tmpMemoryRequest += float(parse_quantity(container.resources.requests['memory']))

            totalPodAllocatable += float(node.status.allocatable['pods'])
            node_mem_capacity = float(parse_quantity(node.status.capacity['memory']))
            node_mem_allocatable = float(parse_quantity(node.status.allocatable['memory']))
            clusterMetric["nodes"].append({
                "name": node.metadata.name,
                "cpu": {
                    "capacity": int(node.status.capacity['cpu']),
                    "allocatable": int(node.status.allocatable['cpu']),
                    "allocatablePercentage": calPercent(int(node.status.allocatable['cpu']), int(node.status.capacity['cpu']), True),
                    "requests": tmpCpuRequest,
                    "requestsPercent": calPercent(tmpCpuRequest, int(node.status.capacity['cpu']), True),
                    "limits": tmpCpuLimit,
                    "limitsPercent": calPercent(tmpCpuLimit, int(node.status.capacity['cpu']), True),
                },
                "memory": {
                    "capacity": node_mem_capacity,
                    "allocatable": node_mem_allocatable,
                    "allocatablePercentage": calPercent(node_mem_allocatable, node_mem_capacity, True),
                    "requests": tmpMemoryRequest,
                    "requestsPercent": calPercent(tmpMemoryRequest, node_mem_capacity, True),
                    "limits": tmpMemoryLimit,
                    "limitsPercent": calPercent(tmpMemoryLimit, node_mem_capacity, True),
                },
                "pod_count": {
                    "current": tmpPodCount,
                    "allocatable": totalPodAllocatable,
                    "allocatablePercentage": calPercent(tmpPodCount, totalPodAllocatable, True),
                },
                # clusterTotals
            })
            tmpTotalCpuAllocatable += int(node.status.allocatable['cpu'])
            tmpTotalMenoryAllocatable += node_mem_allocatable
            tmpTotalCpuCapacity += int(node.status.capacity['cpu'])
            tmpTotalMemoryCapacity += node_mem_capacity
            tmpTotalCpuLimit += tmpCpuLimit
            tmpTotalMemoryLimit += tmpMemoryLimit
            tmpTotalCpuRequest += tmpCpuRequest
            tmpTotalMemoryRequest += tmpMemoryRequest
        clusterMetric["clusterTotals"] = {
                "cpu": {
                    "capacity": tmpTotalCpuCapacity,
                    "allocatable": tmpTotalCpuAllocatable,
                    "allocatablePercentage": calPercent(tmpTotalCpuAllocatable, tmpTotalCpuCapacity, True),
                    "requests": tmpTotalCpuRequest,
                    "requestsPercentage": calPercent(tmpTotalCpuRequest, tmpTotalCpuCapacity, True),
                    "limits": tmpTotalCpuLimit,
                    "limitsPercentage": calPercent(tmpTotalCpuLimit, tmpTotalCpuCapacity, True),
                },
                "memory": {
                    "capacity": tmpTotalMemoryCapacity,
                    "allocatable": tmpTotalMenoryAllocatable,
                    "allocatablePercentage": calPercent(tmpTotalMenoryAllocatable, tmpTotalMemoryCapacity, True),
                    "requests": tmpTotalMemoryRequest,
                    "requestsPercentage": calPercent(tmpTotalMemoryRequest, tmpTotalMemoryCapacity, True),
                    "limits": tmpTotalMemoryLimit,
                    "limitsPercentage":  calPercent(tmpTotalMemoryLimit, tmpTotalMemoryCapacity, True),
                },
        }
        #json_formatted_str = json.dumps(clusterMetric, indent=2)
        #print(json_formatted_str)
        return clusterMetric
    except ApiException as error:
        ErrorHandler(error, "get cluster role bindings list")
        clusterMetric = {
            "nodes": [],
            "clusterTotals": {
                "cpu": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercentage": 0,
                    "requests": 0,
                    "requestsPercentage": 0,
                    "limits": 0,
                    "limitsPercentage": 0,
                },
                "memory": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercentage": 0,
                    "requests": 0,
                    "requestsPercentage": 0,
                    "limits": 0,
                    "limitsPercentage": 0,
                },
            }
        }
        return clusterMetric
    except:
        ErrorHandler("CannotConnect", "Cannot Connect to Kubernetes")
        clusterMetric = {
            "nodes": [],
            "clusterTotals": {
                "cpu": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercentage": 0,
                    "requests": 0,
                    "requestsPercentage": 0,
                    "limits": 0,
                    "limitsPercentage": 0,
                },
                "memory": {
                    "capacity": 0,
                    "allocatable": 0,
                    "allocatablePercentage": 0,
                    "requests": 0,
                    "requestsPercentage": 0,
                    "limits": 0,
                    "limitsPercentage": 0,
                },
            }
        }
        return clusterMetric