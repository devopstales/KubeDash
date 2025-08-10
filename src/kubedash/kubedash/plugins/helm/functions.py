
import json
import zlib
from logging import getLogger

import kubernetes.client as k8s_client
from itsdangerous import base64_decode
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler, json2yaml
from kubedash.lib.k8s.server import k8sClientConfigGet
from kubedash.lib.components import cache, short_cache_time, long_cache_time

logger = getLogger(__name__)

##############################################################
## Helm Charts functions
##############################################################

def decode_secret_date(secret_data):
    secret = None
    try:
        # Decode the base64 encoded release data
        base64_secret_data = str(base64_decode(secret_data.data['release']), 'UTF-8')
        secret = json.loads(zlib.decompress(base64_decode(base64_secret_data), 16 + zlib.MAX_WBITS).decode('utf-8'))
    except (ValueError, zlib.error) as error:
        ErrorHandler(logger, error, f"Error decoding secret data for {secret_data.metadata['name']}: {error}")
    
    return secret


@cache.memoize(timeout=long_cache_time)
def k8sHelmChartListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    latest_releases = {}
    
    HAS_CHART = False
    CHART_LIST = {}
    CHART_DATA = list()
    try:
        secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, _request_timeout=1, timeout_seconds=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get helm release - %s" % error.status)
    
    if secret_list:
        # 1 Find The Latest Helm Release
        for secret in secret_list.items:
            if secret.type == 'helm.sh/release.v1':
                parts = secret.metadata.name.split('.')
                if len(parts) >= 6:  # sh.helm.release.v1.chart.vX
                    chart_name = parts[4]
                    version = int(parts[5][1:])  # Remove the 'v' prefix and convert to int
                    
                    # Check if this is a newer version than what we have
                    if chart_name not in latest_releases or version > latest_releases[chart_name][1]:
                        latest_releases[chart_name] = (secret, version)
                
    # 2 Get the latest Helm Release Data
    for chart_name, (secret, version) in latest_releases.items():
        if secret.data and 'release' in secret.data:
            secret_data = decode_secret_date(secret)
            
            if secret_data:
                if 'icon' in secret_data['chart']['metadata']:
                    helm_icon = secret_data['chart']['metadata']['icon']
                else:
                    helm_icon = None
                if 'appVersion' in secret_data['chart']['metadata']:
                    helm_api_version = secret_data['chart']['metadata']['appVersion']
                else:
                    helm_api_version = None

                ## Get the Kubernetes resources for the release
                chart_name = secret_data['chart']['metadata']['name']
                release_name = secret_data['name']
                label_selector = f"app.kubernetes.io/instance={release_name}"
                deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                stateful_set_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                svc_list = k8s_client.CoreV1Api().list_namespaced_service(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                sa_list =  k8s_client.CoreV1Api().list_namespaced_service_account(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                configma_list = k8s_client.CoreV1Api().list_namespaced_config_map(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                pvc_list =  k8s_client.CoreV1Api().list_namespaced_persistent_volume_claim(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                dependencies = None
                if "lock" in secret_data['chart']:
                    if secret_data['chart']["lock"] and "dependencies" in secret_data['chart']["lock"]:
                        dependencies = secret_data['chart']["lock"]["dependencies"]

                # Add the chart data to the list
                CHART_DATA.append({
                    'icon': helm_icon, # X
                    'status': secret_data['info']['status'], # X
                    'release_name': release_name, # X
                    'release_version': version, # X
                    'chart_name': chart_name, # X
                    'chart_version': secret_data['chart']['metadata']['version'], # X
                    'app_version': helm_api_version, # X
                    'updated': secret_data['info']['last_deployed'], # X
                    # Resources
                    "deployments": [deployment.metadata.name for deployment in deployment_list],
                    "daemonset": [daemonset.metadata.name for daemonset in daemonset_list],
                    "statefulsets": [ss.metadata.name for ss in stateful_set_list],
                    "services": [svc.metadata.name for svc in svc_list],
                    "ingresses": [ingress.metadata.name for ingress in ingress_list],
                    "secrets": [secret.metadata.name for secret in secret_list],
                    "configmaps": [configmap.metadata.name for configmap in configma_list],
                    "service_accounts": [sa.metadata.name for sa in sa_list],
                    "persistent_volume_claims": [pvc.metadata.name for pvc in pvc_list],
                    "values": json2yaml(secret_data['chart']["values"]),
                    "manifests": secret_data["manifest"],
                    #"dependencies": dependencies
                })
                HAS_CHART = True

    # 3 Create a dictionary of charts by release name
    for chart in CHART_DATA:
        if chart['release_name'] not in CHART_LIST.keys():
            CHART_LIST[chart['release_name']] = list()
        CHART_LIST[chart['release_name']].append(chart)
    return HAS_CHART, CHART_LIST
    
    #except ApiException as error:
    #    if error.status != 404:
    #        ErrorHandler(logger, error, "get helm release - %s" % error.status)
    #    return HAS_CHART, CHART_LIST
    #except Exception as error:
    #    ERROR = "k8sHelmChartListGet: %s" % error
    #    ErrorHandler(logger, "error", ERROR)
    #    return HAS_CHART, CHART_LIST
 
##############################################################
## Get Chart Release
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sHelmChartReleaseGet(username_role, user_token, namespace, release_name, release_version):
    k8sClientConfigGet(username_role, user_token)
    CHART_DATA = None
    secret_data = None
    
    # sh.helm.release.v1.chart.vX
    secret_name = f"sh.helm.release.v1.{release_name}.v{release_version}"
    
    try:
        secret = k8s_client.CoreV1Api().read_namespaced_secret(
                          namespace=namespace,
                          name=secret_name
                      )
    except Exception as error:
        if error.status != 404:
            ErrorHandler(logger, error, "k8sHelmChartReleaseGet: get helm release - %s" % error.status)
        else:
            ERROR = "k8sHelmChartReleaseGet: %s" % error
            ErrorHandler(logger, "error", ERROR)
         
    if secret:   
        secret_data = decode_secret_date(secret)
           
    if secret_data:
                if 'icon' in secret_data['chart']['metadata']:
                    helm_icon = secret_data['chart']['metadata']['icon']
                else:
                    helm_icon = None
                if 'appVersion' in secret_data['chart']['metadata']:
                    helm_api_version = secret_data['chart']['metadata']['appVersion']
                else:
                    helm_api_version = None

                ## Get the Kubernetes resources for the release
                chart_name = secret_data['chart']['metadata']['name']
                release_name = secret_data['name']
                label_selector = f"app.kubernetes.io/instance={release_name}"
                deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                stateful_set_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                svc_list = k8s_client.CoreV1Api().list_namespaced_service(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                sa_list =  k8s_client.CoreV1Api().list_namespaced_service_account(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                configma_list = k8s_client.CoreV1Api().list_namespaced_config_map(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                pvc_list =  k8s_client.CoreV1Api().list_namespaced_persistent_volume_claim(namespace, label_selector=label_selector, _request_timeout=1, timeout_seconds=1).items
                dependencies = None
                if "lock" in secret_data['chart']:
                    if secret_data['chart']["lock"] and "dependencies" in secret_data['chart']["lock"]:
                        dependencies = secret_data['chart']["lock"]["dependencies"]

                # Add the chart data to the list
                CHART_DATA = {
                    'icon': helm_icon, # X
                    'status': secret_data['info']['status'], # X
                    'release_name': release_name, # X
                    'release_version': release_version, # X
                    'chart_name': chart_name, # X
                    'chart_version': secret_data['chart']['metadata']['version'], # X
                    'app_version': helm_api_version, # X
                    'updated': secret_data['info']['last_deployed'], # X
                    # Resources
                    "deployments": [deployment.metadata.name for deployment in deployment_list],
                    "daemonset": [daemonset.metadata.name for daemonset in daemonset_list],
                    "statefulsets": [ss.metadata.name for ss in stateful_set_list],
                    "services": [svc.metadata.name for svc in svc_list],
                    "ingresses": [ingress.metadata.name for ingress in ingress_list],
                    "secrets": [secret.metadata.name for secret in secret_list],
                    "configmaps": [configmap.metadata.name for configmap in configma_list],
                    "service_accounts": [sa.metadata.name for sa in sa_list],
                    "persistent_volume_claims": [pvc.metadata.name for pvc in pvc_list],
                    "values": json2yaml(secret_data['chart']["values"]),
                    "manifests": secret_data["manifest"],
                    #"dependencies": dependencies
                }
                
    return CHART_DATA
