from logging import getLogger

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from kubedash.lib.helper_functions import ErrorHandler
from kubedash.lib.k8s.server import k8sClientConfigGet

logger = getLogger(__name__)

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
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        if error.status == 404:
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "ipaddresspoolsGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list

"""l2advertisements.metallb.io"""
def l2advertisementsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "l2advertisements"
    k8s_object_list = list()
    k8s_object_error = False
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        if error.status == 404:
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "l2advertisementsGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list

"""communities.metallb.io"""
def communitiesGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "communities"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "communities": k8s_object['spec']['communities'],
            }
            k8s_object_list.append(k8s_object_data)
        return k8s_object_list
    except ApiException as error:
        if error.status == 404:
            return k8s_object_list
        else:
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
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
        for k8s_object in k8s_objects['items']:
            k8s_object_data = {
                "type": "metallb",
                "name": k8s_object['metadata']['name'],
                "myASN": k8s_object['spec']['myASN'],
                "peerASN": k8s_object['spec']['peerASN'],
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
        if error.status == 404:
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bgppeersGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list

"""bgpadvertisements.metallb.io"""
def bgpadvertisementsGet(namespace):
    k8sClientConfigGet("Admin", None)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "bgpadvertisements"
    k8s_object_list = list()
    k8s_object_error = None
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        if error.status == 404:            
            return True, k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return True, k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bgpadvertisementsGet", "Cannot Connect to Kubernetes")
        return True, k8s_object_list

"""bfdprofiles.metallb.io"""
def bfdprofilesGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    api_group = "metallb.io"
    api_version = "v1beta1"
    api_plural = "bfdprofiles"
    k8s_object_list = list()
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, namespace, api_plural, _request_timeout=1)
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
        if error.status == 404:
            return k8s_object_list
        else:
            ErrorHandler(logger, error, "get %s" % api_plural)
            return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "bfdprofilesGet", "Cannot Connect to Kubernetes")
        return k8s_object_list

# FRR-k8s ???
# https://github.com/metallb/metallb/blob/main/design/splitfrr-proposal.md
