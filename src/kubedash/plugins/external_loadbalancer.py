#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required

from functions.helper_functions import get_logger, ErrorHandler
from functions.sso import get_user_token
from functions.k8s import k8sClientConfigGet, k8sNamespaceListGet

from kubernetes.client.rest import ApiException
import kubernetes.client as k8s_client
import ast

##############################################################
## Helper Functions
##############################################################

exlb_routes = Blueprint("external_loadbalancer", __name__)
logger = get_logger(__name__)

def ipaddresspoolTest(namespace):
    k8s_object_error, k8s_object_list = ipaddresspoolsGet(namespace)
    if k8s_object_error:
        k8s_object_error, k8s_object_list = ciliumloadbalancerippoolsGet(namespace)
        if k8s_object_error:
            return list()
        else:
            return k8s_object_list
    else:
        return k8s_object_list
    
def l2advertisementsTest(namespace):
    k8s_object_error, k8s_object_list = l2advertisementsGet(namespace)
    if k8s_object_error:
        k8s_object_error, k8s_object_list = ciliuml2announcementpoliciesGet(namespace)
        if k8s_object_error:
            return list()
        else:
            return k8s_object_list
    else:
        return k8s_object_list
    
def bgpadvertisementsTest(namespace):
    k8s_object_error, k8s_object_list = bgpadvertisementsGet(namespace)
    if k8s_object_error:
        k8s_object_error, k8s_object_list = ciliumbgppeeringpoliciesGet(namespace)
        if k8s_object_error:
            return list()
        else:
            return k8s_object_list
    else:
        return k8s_object_list
##############################################################
# exLB Functions MetalLB
##############################################################

"""ipaddresspools.metallb.io"""
def ipaddresspoolsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "ipaddresspools"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "addresses": k8s_object['spec']['addresses'],
                "autoAssign": k8s_object['spec']['autoAssign'],
                "avoidBuggyIPs": k8s_object['spec']['avoidBuggyIPs'],
            }
            if 'serviceAllocation' in k8s_object['spec']:
                k8s_object_data["ServiceAllocation_priority"] = k8s_object['spec']['serviceAllocation']['priority']
                if "namespaces" in k8s_object['spec']['serviceAllocation']:
                    k8s_object_data["ServiceAllocation_namespaces"] = k8s_object['spec']['serviceAllocation']["namespaces"]
                if "namespaceSelectors" in k8s_object['spec']['serviceAllocation']:
                    k8s_object_data["ServiceAllocation_namespaceSelectors"] = k8s_object['spec']['serviceAllocation']["namespaceSelectors"]
                if "serviceSelectors" in k8s_object['spec']['serviceAllocation']:
                    k8s_object_data["ServiceAllocation_serviceSelectors"] = k8s_object['spec']['serviceAllocation']["serviceSelectors"]
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
        k8s_object_error = True
        return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ipaddresspoolsGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""l2advertisements.metallb.io"""
def l2advertisementsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "l2advertisements"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "ipAddressPools": k8s_object['spec']['ipAddressPools'],
            }
            if 'interfaces' in k8s_object['spec']:
                k8s_object_data["interfaces"] = k8s_object['spec']['interfaces']
            if 'ipAddressPoolSelectors' in k8s_object['spec']:
                k8s_object_data["ipAddressPoolSelectors"] = k8s_object['spec']['ipAddressPoolSelectors']
            if 'nodeSelectors' in k8s_object['spec']:
                k8s_object_data["nodeSelectors"] = k8s_object['spec']['nodeSelectors']
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "l2advertisementsGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""communities.metallb.io"""
def communitiesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "communities"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "communities": k8s_object['spec']['communities'],
            }
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "communitiesGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

"""bgppeers.metallb.io"""
def bgppeersGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "bgppeers"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "myASN": k8s_object['spec']['myASN'],
                "peerAddress": k8s_object['spec']['peerAddress'],
            }
            if 'sourceAddress' in k8s_object['spec']:
                k8s_object_data["sourceAddress"] = k8s_object['spec']['sourceAddress']
            if 'peerPort' in k8s_object['spec']:
                k8s_object_data["peerPort"] = k8s_object['spec']['peerPort']
            if 'holdTime' in k8s_object['spec']:
                k8s_object_data["holdTime"] = k8s_object['spec']['holdTime']
            if 'keepaliveTime' in k8s_object['spec']:
                k8s_object_data["keepaliveTime"] = k8s_object['spec']['keepaliveTime']
            if 'connectTime' in k8s_object['spec']:
                k8s_object_data["connectTime"] = k8s_object['spec']['connectTime']
            if 'routerID' in k8s_object['spec']:
                k8s_object_data["routerID"] = k8s_object['spec']['routerID']
            if 'nodeSelectors' in k8s_object['spec']:
                k8s_object_data["nodeSelectors"] = k8s_object['spec']['nodeSelectors']
            if 'password' in k8s_object['spec']:
                k8s_object_data["password"] = k8s_object['spec']['password']
            if 'passwordSecret' in k8s_object['spec']:
                k8s_object_data["passwordSecret"] = k8s_object['spec']['passwordSecret']
            if 'bfdProfile' in k8s_object['spec']:
                k8s_object_data["bfdProfile"] = k8s_object['spec']['bfdProfile']
            if 'ebgpMultiHop' in k8s_object['spec']:
                k8s_object_data["ebgpMultiHop"] = k8s_object['spec']['ebgpMultiHop']
            if 'vrf' in k8s_object['spec']:
                k8s_object_data["vrf"] = k8s_object['spec']['vrf']
            if 'disableMP' in k8s_object['spec']:
                k8s_object_data["disableMP"] = k8s_object['spec']['disableMP']
            k8s_object_list.append(k8s_object_data)
        k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bgppeersGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""bgpadvertisements.metallb.io"""
def bgpadvertisementsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "bgpadvertisements"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
            }
            if 'aggregationLength' in k8s_object['spec']:
                k8s_object_data["aggregationLength"] = k8s_object['spec']['aggregationLength']
            if 'aggregationLengthV6' in k8s_object['spec']:
                k8s_object_data["aggregationLengthV6"] = k8s_object['spec']['aggregationLengthV6']
            if 'localPref' in k8s_object['spec']:
                k8s_object_data["localPref"] = k8s_object['spec']['localPref']
            if 'communities' in k8s_object['spec']:
                k8s_object_data["communities"] = k8s_object['spec']['communities']
            if 'ipAddressPools' in k8s_object['spec']:
                k8s_object_data["ipAddressPools"] = k8s_object['spec']['ipAddressPools']
            if 'ipAddressPoolSelectors' in k8s_object['spec']:
                k8s_object_data["ipAddressPoolSelectors"] = k8s_object['spec']['ipAddressPoolSelectors']
            if 'nodeSelectors' in k8s_object['spec']:
                k8s_object_data["nodeSelectors"] = k8s_object['spec']['nodeSelectors']
            if 'peers' in k8s_object['spec']:
                k8s_object_data["peers"] = k8s_object['spec']['peers']
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bgpadvertisementsGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""bfdprofiles.metallb.io"""
def bfdprofilesGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "bfdprofiles"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
            }
            k8s_object_list.append(k8s_object_data)
            if 'receiveInterval' in k8s_object['spec']:
                k8s_object_data["receiveInterval"] = k8s_object['spec']['receiveInterval']
            if 'transmitInterval' in k8s_object['spec']:
                k8s_object_data["transmitInterval"] = k8s_object['spec']['transmitInterval']
            if 'detectMultiplier' in k8s_object['spec']:
                k8s_object_data["detectMultiplier"] = k8s_object['spec']['detectMultiplier']
            if 'echoInterval' in k8s_object['spec']:
                k8s_object_data["echoInterval"] = k8s_object['spec']['echoInterval']
            if 'echoMode' in k8s_object['spec']:
                k8s_object_data["echoMode"] = k8s_object['spec']['echoMode']
            if 'passiveMode' in k8s_object['spec']:
                k8s_object_data["passiveMode"] = k8s_object['spec']['passiveMode']
            if 'minimumTtl' in k8s_object['spec']:
                k8s_object_data["minimumTtl"] = k8s_object['spec']['minimumTtl']
        return k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bfdprofilesGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

# FRR-k8s ???
# https://github.com/metallb/metallb/blob/main/design/splitfrr-proposal.md

##############################################################
# exLB Functions Cilium
##############################################################

"""ciliumloadbalancerippools.cilium.io"""
def ciliumloadbalancerippoolsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "cilium.io"
    api_version = "v2alpha1"
    api_plural = "ciliumloadbalancerippools"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "cilium",
                "name": k8s_object['metadata']['name'],
                "blocks": k8s_object['spec']['blocks'],
            }
            if 'allowFirstLastIPs' in k8s_object['spec']:
                k8s_object_data["allowFirstLastIPs"] = k8s_object['spec']['allowFirstLastIPs']
            if 'disabled' in k8s_object['spec']:
                k8s_object_data["disabled"] = k8s_object['spec']['disabled']
            if 'ipAddressPoolSelectors' in k8s_object['spec']:
                k8s_object_data["ipAddressPoolSelectors"] = k8s_object['spec']['ipAddressPoolSelectors']
            if 'serviceSelector' in k8s_object['spec']:
                k8s_object_data["serviceSelector"] = k8s_object['spec']['serviceSelector']
            if 'ipFamilyPolicy' in k8s_object['spec']:
                k8s_object_data["ipFamilyPolicy"] = k8s_object['spec']['ipFamilyPolicy']
            if 'ipFamilies' in k8s_object['spec']:
                k8s_object_data["ipFamilies"] = k8s_object['spec']['ipFamilies']
            if 'conditions' in k8s_object['status']:
                k8s_object_data["status"] = k8s_object['status']['conditions']
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ciliumloadbalancerippoolsGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""ciliuml2announcementpolicies.cilium.io"""
def ciliuml2announcementpoliciesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "cilium.io"
    api_version = "v2alpha1"
    api_plural = "ciliuml2announcementpolicies"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "cilium",
                "name": k8s_object['metadata']['name'],
            }
            if 'serviceSelector' in k8s_object['spec']:
                k8s_object_data["serviceSelector"] = k8s_object['spec']['serviceSelector']
            if 'nodeSelector' in k8s_object['spec']:
                k8s_object_data["nodeSelector"] = k8s_object['spec']['nodeSelector']
            if 'interfaces' in k8s_object['spec']:
                k8s_object_data["interfaces"] = k8s_object['spec']['interfaces']
            if 'externalIPs' in k8s_object['spec']:
                k8s_object_data["externalIPs"] = k8s_object['spec']['externalIPs']
            if 'loadBalancerIPs' in k8s_object['spec']:
                k8s_object_data["loadBalancerIPs"] = k8s_object['spec']['loadBalancerIPs']
            if 'conditions' in k8s_object['status']:
                k8s_object_data["status"] = k8s_object['status']['conditions']
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ciliuml2announcementpoliciesGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

"""ciliumbgppeeringpolicies.cilium.io"""
def ciliumbgppeeringpoliciesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "cilium.io"
    api_version = "v2alpha1"
    api_plural = "ciliumbgppeeringpolicies"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=5)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "cilium",
                "name": k8s_object['metadata']['name'],
                "virtual_routers": list(),
            }
            if 'nodeSelector' in k8s_object['spec']:
                k8s_object_data["nodeSelector"] = k8s_object['spec']['nodeSelector']
            if 'virtualRouters' in k8s_object['spec']:
                for virtual_router in k8s_object['spec']['virtualRouters']:
                    virtual_router_data = {
                        "localASN": virtual_router['localASN'],
                        "exportPodCIDR": virtual_router['exportPodCIDR'],
                        "neighbors": list(),
                    }
                    if 'serviceSelector' in virtual_router:
                        virtual_router_data['serviceSelector'] = virtual_router['serviceSelector']
                    if 'podIPPoolSelector' in virtual_router:
                        virtual_router_data['podIPPoolSelector'] = virtual_router['podIPPoolSelector']
                    if 'neighbors' in virtual_router:
                        for neighbor in virtual_router['neighbors']:
                            neighbor_data = {
                                "peerAddress": neighbor['peerAddress'],
                                "peerASN": neighbor['peerASN'],
                            }

                            if "eBGPMultihopTTL" in neighbor:
                                neighbor_data["eBGPMultihopTTL"] = neighbor["eBGPMultihopTTL"]
                            if "connectRetryTimeSeconds" in neighbor:
                                neighbor_data["connectRetryTimeSeconds"] = neighbor["connectRetryTimeSeconds"]
                            if "holdTimeSeconds" in neighbor:
                                neighbor_data["holdTimeSeconds"] = neighbor["holdTimeSeconds"]
                            if "keepAliveTimeSeconds" in neighbor:
                                neighbor_data["keepAliveTimeSeconds"] = neighbor["keepAliveTimeSeconds"]
                            if "gracefulRestart" in neighbor:
                                if neighbor['gracefulRestart']['enabled']: 
                                    neighbor_data["gracefulRestartTimeSeconds"] = neighbor['gracefulRestart']["restartTimeSeconds"]

                            if "advertisedPathAttributes" in neighbor:
                                neighbor_data['advertisedPathAttributes'] = list()
                                for path_atribute in neighbor['advertisedPathAttributes']:
                                    path_atribute_data = {
                                        "selectorType": path_atribute['selectorType']
                                    }
                                    if "localPreference" in path_atribute:
                                        path_atribute_data['localPreference'] = path_atribute['localPreference']
                                    if "communities" in path_atribute:
                                        path_atribute_data['communities'] = path_atribute['communities']
                                    if "selector" in path_atribute:
                                        path_atribute_data['selector'] = path_atribute['selector']

                                    neighbor_data['advertisedPathAttributes'].append(path_atribute_data)
                            virtual_router_data['neighbors'].append(neighbor_data)
                    k8s_object_data["virtual_routers"].append(virtual_router_data)
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get %s" % api_plural)
            k8s_object_error = True
            return k8s_object_error, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ciliumbgppeeringpoliciesGet", "Cannot Connect to Kubernetes")
        k8s_object_error = True
        return k8s_object_error, k8s_object_list

##############################################################
# exLB Routes
##############################################################

@exlb_routes.route('/external-loadbalancer', methods=['GET', 'POST'])
@login_required
def external_loadbalancer():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        ipaddresspool_list = ipaddresspoolTest(session['ns_select'])
        l2advertisement_list = l2advertisementsTest(session['ns_select'])
        bgpadvertisement_list = bgpadvertisementsTest(session['ns_select'])
        k8s_object_error, bgppeers_list = bgppeersGet(session['ns_select'])
        if k8s_object_error:
            bgppeers_list = list()
    else:
        ipaddresspool_list = list()
        l2advertisement_list = list()
        bgpadvertisement_list = list()

    return render_template(
        'external-loadbalancer.html.j2',
        namespaces = namespace_list,
        ipaddresspool_list=ipaddresspool_list,
        l2advertisement_list=l2advertisement_list,
        bgpadvertisement_list=bgpadvertisement_list,
        bgppeers_list=bgppeers_list,
        selected=selected,
    )

@exlb_routes.route('/external-loadbalancer/data', methods=['GET', 'POST'])
@login_required
def external_loadbalancer_data():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        object_type = request.form.get('object_type')
        object_data_str = request.form.get('object_data')


        return render_template(
            'external-loadbalancer-data.html.j2',
            object_type=object_type,
            object_data=ast.literal_eval(object_data_str),
            selected=selected,
        )

    else:
        return redirect(url_for('routes.login'))