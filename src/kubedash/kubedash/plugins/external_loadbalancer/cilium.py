from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler
from kubedash.lib.k8s.server import k8sClientConfigGet

logger = getLogger(__name__)

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
    #try:
    k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=1)
    for k8s_object in k8s_objects['items']:
        k8s_object_data = {
            "type": "cilium",
            "name": k8s_object['metadata']['name'],
            "blocks": k8s_object['spec']['cidrs'],
        }
        if 'allowFirstLastIPs' in k8s_object['spec']:
            k8s_object_data["allowFirstLastIPs"] = k8s_object['spec']['allowFirstLastIPs']
        else:
            k8s_object_data["allowFirstLastIPs"] = False
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
    #except ApiException as error:
    #    if error.status == 404:
    #        return True, k8s_object_list
    #    else:
    #        ErrorHandler(logger, error, "get %s" % api_plural)
    #        return True, k8s_object_list
    #except Exception as error:
    #    ErrorHandler(logger, "ciliumloadbalancerippoolsGet", "Cannot Connect to Kubernetes")
    #    return True, k8s_object_list

"""ciliuml2announcementpolicies.cilium.io"""
def ciliuml2announcementpoliciesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "cilium.io"
    api_version = "v2alpha1"
    api_plural = "ciliuml2announcementpolicies"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=1)
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
            k8s_object_list.append(k8s_object_data)
            k8s_object_error = False
        return k8s_object_error, k8s_object_list
    except ApiException as error:
        if error.status == 404:
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ciliuml2announcementpoliciesGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list

"""ciliumbgppeeringpolicies.cilium.io"""
def ciliumbgppeeringpoliciesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "cilium.io"
    api_version = "v2alpha1"
    api_plural = "ciliumbgppeeringpolicies"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(api_group, api_version, api_plural, _request_timeout=1)
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
        if error.status == 404:
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ciliumbgppeeringpoliciesGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list
