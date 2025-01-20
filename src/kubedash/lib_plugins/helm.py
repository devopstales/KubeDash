#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sClientConfigGet
from lib_functions.helper_functions import ErrorHandler, json2yaml

from lib_functions.helper_functions import get_logger

import zlib, json, yaml
from itsdangerous import base64_decode, base64_encode

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

##############################################################
## variables
##############################################################

helm = Blueprint("helm", __name__)
logger = get_logger()

##############################################################
# Helm Functions
##############################################################

def k8sHelmChartListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    HAS_CHART = False
    CHART_LIST = {}
    CHART_DATA = list()
    try:
        secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, _request_timeout=5)
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

                ## Get the Kubernetes resources for the release
                chart_name = secret_data['chart']['metadata']['name']
                release_name = secret_data['name']
                label_selector = f"app.kubernetes.io/instance={release_name}"
                deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(namespace, label_selector=label_selector, _request_timeout=5).items
                daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(namespace, label_selector=label_selector, _request_timeout=5).items
                stateful_set_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(namespace, label_selector=label_selector, _request_timeout=5).items
                svc_list = k8s_client.CoreV1Api().list_namespaced_service(namespace, label_selector=label_selector, _request_timeout=5).items
                ingress_list = k8s_client.NetworkingV1Api().list_namespaced_ingress(namespace, label_selector=label_selector, _request_timeout=5).items
                sa_list =  k8s_client.CoreV1Api().list_namespaced_service_account(namespace, label_selector=label_selector, _request_timeout=5).items
                secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, label_selector=label_selector, _request_timeout=5).items
                configma_list = k8s_client.CoreV1Api().list_namespaced_config_map(namespace, label_selector=label_selector, _request_timeout=5).items
                pvc_list =  k8s_client.CoreV1Api().list_namespaced_persistent_volume_claim(namespace, label_selector=label_selector, _request_timeout=5).items
                dependencies = None
                if "lock" in secret_data['chart']:
                    if secret_data['chart']["lock"] and "dependencies" in secret_data['chart']["lock"]:
                        dependencies = secret_data['chart']["lock"]["dependencies"]

                CHART_DATA.append({
                    'icon': helm_icon, # X
                    'status': secret_data['info']['status'], # X
                    'release_name': release_name, # X
                    'chart_name': chart_name, # X
                    'chart_version': secret_data['chart']['metadata']['version'], # X
                    'app_version': helm_api_version, # X
                    'revision': secret_data['version'],
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
        for chart in CHART_DATA:
            if chart['release_name'] not in CHART_LIST.keys():
                CHART_LIST[chart['release_name']] = list()
            CHART_LIST[chart['release_name']].append(chart)
        return HAS_CHART, CHART_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get helm release - %s" % error.status)
        return HAS_CHART, CHART_LIST
    except Exception as error:
        ERROR = "k8sHelmChartListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return HAS_CHART, CHART_LIST

##############################################################
# Helm Routes
##############################################################

@helm.route('/charts', methods=['GET', 'POST'])
@login_required
def charts():
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')


    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, session['ns_select'])
    else:
        chart_list = []
        has_chart = None

    return render_template(
        'charts.html.j2',
        namespaces = namespace_list,
        has_chart = has_chart,
        chart_list = chart_list,
    )

@helm.route('/charts/data', methods=['GET', 'POST'])
@login_required
def charts_data():
    if request.method == 'POST':
        selected = request.form.get('selected')
        user_token = get_user_token(session)

        has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, session['ns_select'])
        chart_data = None
        chart_name = None
        if has_chart:
            for name, release in chart_list.items():
                if name == selected:
                    chart_name = name
                    chart_data = release

        return render_template(
            'chart-data.html.j2',
            chart_name = chart_name,
            chart_data = chart_data,
        )
    else:
        return redirect(url_for('helm.login'))