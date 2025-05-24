
from flask import session

from .cilium import (ciliumbgppeeringpoliciesGet,
                     ciliuml2announcementpoliciesGet,
                     ciliumloadbalancerippoolsGet)
from .metallb import (bgpadvertisementsGet, bgppeersGet, ipaddresspoolsGet,
                      l2advertisementsGet)

##############################################################
## Helper Functions
##############################################################

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
        return list()
    else:
        return k8s_object_list
    
def bgppeersTest(namespace):
    k8s_object_error, k8s_object_list = bgppeersGet(session['ns_select'])
    if k8s_object_error:
        k8s_object_error, k8s_object_list = ciliumbgppeeringpoliciesGet(namespace)
        if k8s_object_error:
            return list()
        else:
            return k8s_object_list
    else:
        return k8s_object_list
