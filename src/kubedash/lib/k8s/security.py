from flask import flash
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, email_check, trimAnnotations
from lib.components import cache, short_cache_time, long_cache_time

from . import logger
from .namespace import k8sNamespaceListGet
from .server import k8sClientConfigGet

################################
# Pod Vulnerability Assessment #
################################

@cache.memoize(timeout=long_cache_time)
def k8sPodListVulnsGet(username_role, user_token, ns):
    """Get a list of vulnerabilities in pods for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        HAS_REPORT (bool): True if a vulnerability report exists, False otherwise
        POD_VULN_LIST (list): List of vulnerabilities in pods
    """
    k8sClientConfigGet(username_role, user_token)
    POD_VULN_LIST = list()
    HAS_REPORT = False
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster roles - %s" % error.status)
        return HAS_REPORT, POD_VULN_LIST
    except Exception as error:
        ERROR = "k8sPodListVulnsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return HAS_REPORT, POD_VULN_LIST
    try:
        api_group = "trivy-operator.devopstales.io"
        api_version = "v1"
        api_plural = "vulnerabilityreports"
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, ns, api_plural, _request_timeout=1)
        HAS_REPORT = True
    except Exception as error:
        vulnerabilityreport_list = None
        ERROR = "vulnerabilityreport_list exeption: %s" % error
        #####################################################
        # aquasecurity trivy operator functions
        #####################################################
        if error.status == 404:
            try:
                api_group = "aquasecurity.github.io"
                api_version = "v1alpha1"
                api_plural = "vulnerabilityreports"
                vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, ns, api_plural, _request_timeout=1)
                HAS_REPORT = True
            except Exception as error2:
                vulnerabilityreport_list = None
                ERROR = "vulnerabilityreport_list exeption: %s" % error2
                if error2.status != 404:
                    ERROR = "k8sPodListVulnsGet: %s" % error2
                ErrorHandler(logger, "error", ERROR)
        #####################################################
        else:
            ERROR = "k8sPodListVulnsGet: %s" % error
            ErrorHandler(logger, "error", ERROR)

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
                if 'trivy-operator.pod.name' in vr['metadata']['labels']:
                    if vr['metadata']['labels']['trivy-operator.pod.name'] == pod.metadata.name:
                        POD_VULN_SUM['critical'] += vr['report']['summary']['criticalCount']
                        POD_VULN_SUM['high'] += vr['report']['summary']['highCount']
                        POD_VULN_SUM['medium'] += vr['report']['summary']['mediumCount']
                        POD_VULN_SUM['low'] += vr['report']['summary']['lowCount']
                elif 'trivy-operator.resource.kind' in vr['metadata']['labels']:
                    if  vr['metadata']['labels']['trivy-operator.resource.kind'] == pod.metadata.owner_references[0].kind and \
                        vr['metadata']['labels']['trivy-operator.resource.name'] == pod.metadata.owner_references[0].name:
                            POD_VULN_SUM['critical'] += vr['report']['summary']['criticalCount']
                            POD_VULN_SUM['high'] += vr['report']['summary']['highCount']
                            POD_VULN_SUM['medium'] += vr['report']['summary']['mediumCount']
                            POD_VULN_SUM['low'] += vr['report']['summary']['lowCount']

        if POD_VULN_SUM['critical'] > 0 or POD_VULN_SUM['high'] > 0 or POD_VULN_SUM['medium'] > 0 or POD_VULN_SUM['low'] > 0:
            POD_VULN_SUM['scan_status'] = "OK"
        POD_VULN_LIST.append(POD_VULN_SUM)

    return HAS_REPORT, POD_VULN_LIST

@cache.memoize(timeout=long_cache_time)
def k8sPodVulnsGet(username_role, user_token, ns, pod):
    """Get vulnerability details for a specific pod in a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        pod (str): Pod name
        
    Returns:
        HAS_REPORT (bool): True if a vulnerability report exists, False otherwise
        POD_VULNS (dict): Vulnerability details for the pod
    """
    k8sClientConfigGet(username_role, user_token)
    POD_VULNS = {}
    HAS_REPORT = False
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns, _request_timeout=1)
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster roles - %s" % error.status)
        return HAS_REPORT, POD_VULNS
    except Exception as error:
        ERROR = "k8sPodVulnsGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return HAS_REPORT, POD_VULNS
    
    try:
        api_group = "trivy-operator.devopstales.io"
        api_version = "v1"
        api_plural = "vulnerabilityreports"
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, ns, api_plural, _request_timeout=1)
    except ApiException as error:
        #####################################################
        # aquasecurity trivy operator functions
        #####################################################
        if error.status == 404:
            try:
                api_group = "aquasecurity.github.io"
                api_version = "v1alpha1"
                api_plural = "vulnerabilityreports"
                vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object(api_group, api_version, ns, api_plural, _request_timeout=1)
            except ApiException as error2:
                vulnerabilityreport_list = None
                if error2.status != 404:
                    ERROR = "k8sPodVulnsGet: %s" % error2
                    ErrorHandler(logger, "error", ERROR)
            except Exception as error2:
                ErrorHandler(logger, "error", error2)
                vulnerabilityreport_list = None
        #####################################################
        else:
            vulnerabilityreport_list = None
            ERROR = "k8sPodVulnsGet: %s" % error
            ErrorHandler(logger, "error", ERROR)
    except Exception as error:
        ErrorHandler(logger, "error", error)
        vulnerabilityreport_list = None

    for po in pod_list.items:
        POD_VULNS = {}
        if po.metadata.name == pod:
            if vulnerabilityreport_list is not None:
                for vr in vulnerabilityreport_list['items']:
                    fixedVersion = None
                    publishedDate = None
                    vuln_scoe = None
                    if 'trivy-operator.pod.name' in vr['metadata']['labels']:
                        if vr['metadata']['labels']['trivy-operator.pod.name'] == po.metadata.name:
                            HAS_REPORT = True
                            VULN_LIST = list()
                            for vuln in vr['report']['vulnerabilities']:
                                if 'fixedVersion' in vuln:
                                    fixedVersion = vuln['fixedVersion']
                                if 'publishedDate' in vuln:
                                    publishedDate = vuln['publishedDate']
                                if 'score' in vuln:
                                    vuln_scoe = vuln['score']
                                VULN_LIST.append({
                                    "vulnerabilityID": vuln['vulnerabilityID'],
                                    "severity": vuln['severity'],
                                    "score": vuln_scoe,
                                    "resource": vuln['resource'],
                                    "installedVersion": vuln['installedVersion'],
                                    "fixedVersion": fixedVersion,
                                    "publishedDate": publishedDate,
                                })
                            POD_VULNS.update({vr['metadata']['labels']['trivy-operator.container.name']: VULN_LIST})
                    elif 'trivy-operator.resource.kind' in vr['metadata']['labels']:
                        if  vr['metadata']['labels']['trivy-operator.resource.kind'] == po.metadata.owner_references[0].kind and \
                            vr['metadata']['labels']['trivy-operator.resource.name'] == po.metadata.owner_references[0].name:
                                HAS_REPORT = True
                                VULN_LIST = list()
                                for vuln in vr['report']['vulnerabilities']:
                                    if 'fixedVersion' in vuln:
                                        fixedVersion = vuln['fixedVersion']
                                    if 'publishedDate' in vuln:
                                        publishedDate = vuln['publishedDate']
                                    if 'score' in vuln:
                                        vuln_scoe = vuln['score']
                                    VULN_LIST.append({
                                        "vulnerabilityID": vuln['vulnerabilityID'],
                                        "severity": vuln['severity'],
                                        "score": vuln_scoe,
                                        "resource": vuln['resource'],
                                        "installedVersion": vuln['installedVersion'],
                                        "fixedVersion": fixedVersion,
                                        "publishedDate": publishedDate,
                                    })
                                POD_VULNS.update({vr['metadata']['labels']['trivy-operator.container.name']: VULN_LIST})
                return HAS_REPORT, POD_VULNS
            else:
                return False, None

##############################################################
## Service Account
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sSaListGet(username_role, user_token, ns):
    """Get a list of Service Accounts for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        SA_LIST (list): List of Service Account objects
        ERROR (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    SA_LIST = list()
    try:
        service_accounts = k8s_client.CoreV1Api().list_namespaced_service_account(ns, _request_timeout=1)
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
        if error.status != 404:
            ErrorHandler(logger, error, "get service account list - %s" % error.status)
        return SA_LIST
    except Exception as error:
        ERROR = "k8sSaListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return SA_LIST

##############################################################
## Role
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sRoleGet(username_role, user_token, role_name, ns):
    """Get a Role for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        role_name (str): Name of the Role
        ns (str): Namespace name
        
    Returns:
        ROLE_INFO (dict): Information about the Role
        ERROR (str): Error message if any
    """
    ROLE_INFO = None
    k8sClientConfigGet(username_role, user_token)
    try:
        role_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role(ns, _request_timeout=1)
        for role in role_list.items:
            if role.metadata.name == role_name:
                ROLE_INFO = {
                    "name": role.metadata.name,
                    "annotations": trimAnnotations(role.metadata.annotations),
                    "labels": role.metadata.labels,
                    "rules": role.rules,
                    "created": role.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                }
        return ROLE_INFO
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get roles list - %s" % error.status)
        return ROLE_INFO
    except Exception as error:
        ERROR = "k8sRoleGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return ROLE_INFO

@cache.memoize(timeout=long_cache_time)
def k8sRoleListGet(username_role, user_token, ns):
    """Get a list of Roles for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        ROLE_LIST (list): List of Role objects
        ERROR (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    ROLE_LIST = list()
    try:
        role_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role(ns, _request_timeout=1)
        for role in role_list.items:
            ROLE_INFO = {
                "name": role.metadata.name,
                "annotations": trimAnnotations(role.metadata.annotations),
                "labels": role.metadata.labels,
                "rules": role.rules,
                "created": role.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            ROLE_LIST.append(ROLE_INFO)
        return ROLE_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get roles list - %s" % error.status)
        return ROLE_LIST
    except Exception as error:
        ERROR = "k8sRoleListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return ROLE_LIST

##############################################################
##  Role Binding
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sRoleBindingListGet(username_role, user_token, ns):
    """Get a list of Role Bindings for a given namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        ROLE_BINDING_LIST (list): List of Role Binding objects
        ERROR (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    ROLE_BINDING_LIST = list()
    try:
        role_binding_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role_binding(ns, _request_timeout=1)
        for rb in role_binding_list.items:
            ROLE_BINDING_INFO = {
            "name": rb.metadata.name,
            "role": list(),
            "user": list(),
            "group": list(),
            "ServiceAccount": list(),
            "created": rb.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
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
        return ROLE_BINDING_LIST, None
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get role bindings list - %s" % error.status)
        return ROLE_BINDING_LIST, error
    except Exception as error:
        ERROR = "k8sRoleBindingListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return ROLE_BINDING_LIST, error

@cache.memoize(timeout=long_cache_time)
def k8sRoleBindingGet(obeject_name, namespace):
    """Get Role Binding object from Kubernetes API
    
    Args:
        obeject_name (str): Name of the Role Binding object
        namespace (str): Namespace of the Role Binding object
        
    Returns:
        is_rolebinding_exists (bool): True if Role Binding exists, False otherwise
        error (str): Error message if any
    """
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_namespaced_role_binding(
            obeject_name, namespace, pretty=pretty, _request_timeout=1
        )
        return True, None
    except ApiException as e:
        if e.status == 404:
            return False, None
        else:
            logger.error("Exception when testing NamespacedRoleBinding - %s in %s: %s\n" % (obeject_name, namespace, e))
            return None, e
    except Exception as error:
        ERROR = "k8sRoleBindingGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return None, "Unknow Error"
    
@cache.memoize(timeout=long_cache_time)
def k8sRoleBindingGroupGet(group_name, username_role, user_token):
    """Get Role Binding objects for a given group in a given namespace.
    
    Args:
        group_name (str): Name of the group
        username_role (str): Role of the current user
        
    Returns:
        group_role_binding (list): List of Role Binding objects for the given group
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    group_role_binding = list()
    namespace_list, error = k8sNamespaceListGet("Admin", None)
    if not error:
        for ns in namespace_list:
            role_binding_list, error = k8sRoleBindingListGet(username_role, user_token, ns)
            if not error:
                for role_binding in role_binding_list:
                    if group_name in role_binding["group"]:
                        role_binding["namespace"] = ns
                        group_role_binding.append(role_binding)
            else:
                break
    return group_role_binding

def k8sRoleBindingCreate(user_role, namespace, username, group_name):
    """Create a Role Binding object in Kubernetes API
    
    Args:
        user_role (str): Role of the current user
        namespace (str): Namespace of the Role Binding object
        username (str): Username or email of the user
        group_name (str): Name of the group
        
    Returns:
        is_rolebinding_created (bool): True if Role Binding created successfully, False otherwise
        error (str): Error message if any
    """
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'

        if username:
            if email_check(username):
                user = username.split("@")[0]
            else:
                user = username

            obeject_name = user + "---" + "kubedash" + "---" + user_role
            body_subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "User",
                    name = username,
                    namespace = namespace,
                )
            ]
        else:
            obeject_name = group_name + "---" + "kubedash" + "---" + user_role
            body_subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "Group",
                    name = group_name,
                    namespace = namespace,
                )
            ]

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
                name = "template-namespaced-resources---" + user_role,
            ),
            subjects = body_subjects
        )
    try:
        api_response = api_instance.create_namespaced_role_binding(
            namespace, body, pretty=pretty, field_manager=field_manager, _request_timeout=1
        )
        return True, None
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when creating RoleBinding - %s in %s: %s\n" % (obeject_name, namespace, e))
            return True, e
        else:
            return False, None


def k8sRoleBindingAdd(user_role, username, group_name, user_namespaces, user_all_namespaces):
    """Add a Role Binding object to Kubernetes API
    
    Args:
        user_role (str): Role of the current user
        username (str): Username or email of the user
        group_name (str): Name of the group
        user_namespaces (list): List of namespaces for the user
        user_all_namespaces (bool): True if all namespaces should be included, False otherwise
        
    Returns:
        None
    """
    if username:
        if email_check(username):
            user = username.split("@")[0]
        else:
            user = username

        obeject_name = user + "---" + "kubedash" + "---" + user_role
    else:
        obeject_name = group_name + "---" + "kubedash" + "---" + user_role

    if user_all_namespaces:
        namespace_list, error = k8sNamespaceListGet("Admin", None)
    else:
        namespace_list = user_namespaces

    for namespace in namespace_list:
        is_rolebinding_exists, error = k8sRoleBindingGet(obeject_name, namespace)
        if error:
            ErrorHandler(logger, error, "get RoleBinding %s - %s" % (obeject_name, error))
        else:
            if is_rolebinding_exists:
                ErrorHandler(logger, "CannotConnect", "RoleBinding %s alredy exists in %s namespace" % (obeject_name, namespace))
                logger.info("RoleBinding %s alredy exists" % obeject_name) # WARNING
            else:
                k8sRoleBindingCreate(user_role, namespace, username, group_name)



##############################################################
## Kubernetes User Role template
##############################################################

#@cache.memoize(timeout=long_cache_time) ## Debug Later
def k8sUserClusterRoleTemplateListGet(username_role, user_token):
    """Get User Cluster Role Template list from Kubernets API
    
    Args:
        username_role (string): The username role
        user_token (string): The user token
        
    Returns:
        CLUSTER_ROLE_LIST (list[dictionary]): The list of user
        error (string): The error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role(_request_timeout=1)
        try:
            for cr in cluster_roles.items:
                if "template-cluster-resources---" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("---")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster roles - %s" % error.status)
    except Exception as error:
        return
    
#@cache.memoize(timeout=long_cache_time) ## Debug Later
def k8sUserRoleTemplateListGet(username_role, user_token):
    """Get User Role Template list from Kubernets API
    
    Args:
        username_role (string): The username role
        user_token (string): The user token
    
    Returns:
        CLUSTER_ROLE_LIST (list[dictionary]): The list of user roles templates"""
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role(_request_timeout=1)
        try:
            for cr in cluster_roles.items:
                if "template-namespaced-resources---" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("---")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster roles - %s" % error.status)
        return CLUSTER_ROLE_LIST
    except Exception as error:
        return CLUSTER_ROLE_LIST
    
##############################################################
## Cluster Role
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sClusterRoleObjectGet(name):
    """Get a ClusterRole
    
    Args:
        name (str): Name of the ClusterRole
        
    Returns:
        is_clusterrole_exists (bool): True if ClusterRole exists, False otherwise
        error (str): Error message if any
    """
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_cluster_role(name, pretty=pretty, _request_timeout=1)
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
    """
    Creates a new ClusterRole in the Kubernetes cluster.

    Parameters:
        name (str): The name of the ClusterRole to be created.
        body (V1ClusterRole): The body of the ClusterRole to be created.

    Returns:
        bool: True if the ClusterRole is created successfully, False otherwise.
    """
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
    try:
        api_response = api_instance.create_cluster_role(
            body, pretty=pretty, field_manager=field_manager, _request_timeout=1
        )
        return True
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when testing ClusterRole - %s : %s\n" % (name, e))
        return False
    except Exception as error:
        return False
    
def k8sClusterRolesAdd():
    """Add predefined ClusterRoles to the Kubernetes API.

    This function creates several ClusterRoles with specific permissions for different
    user types (admin, reader, developer, deployer, and operation). It checks if each
    ClusterRole already exists before creating it.

    The function defines the following ClusterRoles:
    - template-cluster-resources---admin: Cluster-wide read access
    - template-cluster-resources---reader: Cluster-wide read access
    - template-namespaced-resources---developer: Full access to specific namespaced resources
    - template-namespaced-resources---deployer: Full access to deployment-related resources
    - template-namespaced-resources---operation: Full access to all resources

    The function doesn't take any parameters and doesn't return any value. It logs the
    status of each ClusterRole creation attempt.

    Note: This function requires appropriate permissions to create ClusterRoles in the cluster.
    """
    admin = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-cluster-resources---admin"
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
                name = "template-cluster-resources---reader"
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
                name = "template-namespaced-resources---developer"
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
                name = "template-namespaced-resources---deployer"
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
                name = "template-namespaced-resources---operation"
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
        name = "template-cluster-resources---" + role
        is_clusterrole_exists, error = k8sClusterRoleObjectGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

    for role in namespaced_role_list:
        name = "template-namespaced-resources---" + role
        is_clusterrole_exists, error = k8sClusterRoleObjectGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

def k8sClusterRoleGet(username_role, user_token, cluster_role_name=None):
    """Get Cluster Roles from Kubernetes API
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        cluster_role_name (str, optional): Name of the Cluster Role to get. Defaults to None.
        
    Returns:
        CLUSTER_ROLE (list): Cluster Roles
        error (str): Error message if any
    """
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_DATA = None
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role(_request_timeout=1)
        try:
            for cr in cluster_roles.items:
                if cluster_role_name is not None:
                    if cr.metadata.name == cluster_role_name:
                        CLUSTER_ROLE_DATA = {
                            "name": cr.metadata.name,
                            "annotations": trimAnnotations(cr.metadata.annotations),
                            "labels": cr.metadata.labels,
                            "rules": cr.rules,
                            "created": cr.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        }
            return CLUSTER_ROLE_DATA
        except:
            return CLUSTER_ROLE_DATA
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster role %s - %s" % (cluster_role_name, error.status))
        return CLUSTER_ROLE_DATA
    except Exception as error:
        ERROR = "k8sClusterRoleObjectGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return CLUSTER_ROLE_DATA

@cache.memoize(timeout=long_cache_time)
def k8sClusterRoleListGet(username_role, user_token):
    """
    Retrieve a list of ClusterRoles from the Kubernetes API.

    This function fetches all ClusterRoles from the Kubernetes cluster and returns
    them as a list of dictionaries containing relevant information about each ClusterRole.

    Args:
        username_role (str): The role of the user making the request.
        user_token (str): The authentication token of the user making the request.

    Returns:
        list: A list of dictionaries, where each dictionary contains information about a ClusterRole.
              Each dictionary includes the following keys:
              - 'name': The name of the ClusterRole
              - 'annotations': Trimmed annotations of the ClusterRole
              - 'labels': Labels associated with the ClusterRole
              - 'rules': Rules defined for the ClusterRole
              - 'created': Creation timestamp of the ClusterRole

    Raises:
        ApiException: If there's an error in the Kubernetes API call (except 404 errors).
        Exception: For any other unexpected errors during execution.
    """
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role(_request_timeout=1)
        try:
            for cr in cluster_roles.items:
                CLUSTER_ROLE_DATA = {
                    "name": cr.metadata.name,
                    "annotations": trimAnnotations(cr.metadata.annotations),
                    "labels": cr.metadata.labels,
                    "rules": cr.rules,
                    "created": cr.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                }
                CLUSTER_ROLE_LIST.append(CLUSTER_ROLE_DATA)
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster role list - %s" % error.status)
        return CLUSTER_ROLE_LIST
    except Exception as error:
        ERROR = "k8sClusterRoleListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return CLUSTER_ROLE_LIST

##############################################################
## Cluster Role Bindings
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sClusterRoleBindingListGet(username_role, user_token):
    """
    Retrieve a list of ClusterRoleBindings from the Kubernetes API.

    This function fetches all ClusterRoleBindings from the Kubernetes cluster and returns
    them as a list of dictionaries containing relevant information about each ClusterRoleBinding.

    Args:
        username_role (str): The role of the user making the request.
        user_token (str): The authentication token of the user making the request.

    Returns:
        tuple: A tuple containing two elements:
            - list: A list of dictionaries, where each dictionary contains information about a ClusterRoleBinding.
                    Each dictionary includes the following keys:
                    - 'name': The name of the ClusterRoleBinding
                    - 'role': A list of dictionaries representing the roles associated with the binding
                    - 'user': A list of users associated with the binding
                    - 'group': A list of groups associated with the binding
                    - 'ServiceAccount': A list of dictionaries representing the service accounts associated with the binding
                    - 'created': The creation timestamp of the ClusterRoleBinding
            - None or Exception: None if the operation was successful, or an Exception object if an error occurred.

    Raises:
        ApiException: If there's an error in the Kubernetes API call (except 404 errors).
        Exception: For any other unexpected errors during execution.
    """
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_BINDING_LIST = []
    try:
        cluster_role_bindings = k8s_client.RbacAuthorizationV1Api().list_cluster_role_binding(_request_timeout=1)
        for crb in cluster_role_bindings.items:
            CLUSTER_ROLE_BINDING_INFO = {
            "name": crb.metadata.name,
            "role": list(),
            "user": list(),
            "group": list(),
            "ServiceAccount": list(),
            "created": crb.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
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
        return CLUSTER_ROLE_BINDING_LIST, None
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get cluster role bindings list - %s" % error.status)
        return CLUSTER_ROLE_BINDING_LIST, error
    except Exception as error:
        ERROR = "k8sClusterRoleBindingListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return CLUSTER_ROLE_BINDING_LIST, error

@cache.memoize(timeout=long_cache_time)
def k8sClusterRoleBindingGet(obeject_name):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_cluster_role_binding(
            obeject_name, pretty=pretty, _request_timeout=1
        )
        return True, None
    except ApiException as e:
        if e.status == 404:
            return False, None
        else:
            logger.error("Exception when testing ClusterRoleBinding - %s: %s\n" % (obeject_name, e))
            return None, e
    except Exception as error:
        ERROR = "k8sClusterRoleBindingGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return None, "Unknow Error"
    
@cache.memoize(timeout=long_cache_time)
def k8sClusterRoleBindingGroupGet(group_name, username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    cluster_role_binding_list, error = k8sClusterRoleBindingListGet(username_role, user_token)
    group_cluster_role_binding = list()
    if not error:
        for cluster_role_binding in cluster_role_binding_list:
            if group_name in cluster_role_binding["group"]:
                group_cluster_role_binding.append(cluster_role_binding)
    return group_cluster_role_binding

def k8sClusterRoleBindingCreate(user_cluster_role, username, group_name):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
        if username:
            if email_check(username):
                user = username.split("@")[0]
            else:
                user = username

            obeject_name = user + "---" + "kubedash" + "---" + user_cluster_role
            body_subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "User",
                    name = username,
                )
            ]
        else:
            obeject_name = group_name + "---" + "kubedash" + "---" + user_cluster_role
            body_subjects = [
                k8s_client.V1Subject(
                    api_group = "rbac.authorization.k8s.io",
                    kind = "Group",
                    name = group_name,
                )
            ]

        body = k8s_client.V1ClusterRoleBinding(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRoleBinding",
            metadata = k8s_client.V1ObjectMeta(
                name = obeject_name,
            ),
            role_ref = k8s_client.V1RoleRef(
                api_group = "rbac.authorization.k8s.io",
                kind = "ClusterRole",
                name = "template-cluster-resources---" + user_cluster_role,
            ),
            subjects = body_subjects
        )
    try:
        pi_response = api_instance.create_cluster_role_binding(
            body, pretty=pretty, field_manager=field_manager, _request_timeout=1
        )
        flash("User Role Created Successfully", "success")
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when creating ClusterRoleBinding - %s: %s\n" % (user_cluster_role, e))
        else:
            logger.info("ClusterRoleBinding %s alredy exists" % obeject_name) # WARNING

def k8sClusterRoleBindingAdd(user_cluster_role, username, group_name):
    if username:
        if email_check(username):
            user = username.split("@")[0]
        else:
            user = username
        
        obeject_name = user + "---" + "kubedash" + "---" + user_cluster_role
    else:
        obeject_name = group_name  + "---" + "kubedash" + "---" + user_cluster_role

    is_clusterrolebinding_exists, error = k8sClusterRoleBindingGet(obeject_name)
    if error:
        ErrorHandler(logger, error, "get ClusterRoleBinding %s - %s" % (obeject_name, error))
    else:
        if is_clusterrolebinding_exists:
            ErrorHandler(logger, "CannotConnect", "ClusterRoleBinding %s alredy exists" % obeject_name)
            logger.info("ClusterRoleBinding %s alredy exists" % obeject_name) # WARNING
        else:
            k8sClusterRoleBindingCreate(user_cluster_role, username, group_name)

##############################################################
## User Priviliges
##############################################################

@cache.memoize(timeout=long_cache_time)
def k8sUserPriviligeList(username_role="Admin", user_token=None, user="admin"):
    ROLE_LIST = []
    CLUSTER_ROLE_LIST = []
    USER_ROLES = []
    USER_CLUSTER_ROLES = []

    k8sClientConfigGet(username_role, user_token)

    namespaces, error = k8sNamespaceListGet(username_role, user_token)
    if not error:
        for ns in namespaces:
            role_binding_list = k8s_client.RbacAuthorizationV1Api().list_namespaced_role_binding(ns, _request_timeout=1)
            for rb in role_binding_list.items:
                for obj in rb.subjects:
                    if obj.kind == "User" and obj.name == user:
                        if rb.role_ref.kind == "ClusterRole":
                            CLUSTER_ROLE_LIST.append(rb.role_ref.name)
                        elif rb.role_ref.kind == "Role":
                            ROLE_LIST.append([ns, rb.role_ref.name])

    cluster_role_bindings = k8s_client.RbacAuthorizationV1Api().list_cluster_role_binding(_request_timeout=1)
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
            ROLE = api_instance.read_namespaced_role(r[1], r[0], pretty=pretty, _request_timeout=1)
            for rr in ROLE.rules:
                USER_ROLES.append({r[1]: rr})
        except:
            continue
    
    for cr in CLUSTER_ROLE_LIST:
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
            pretty = 'true'
        try:
            CLUSTER_ROLE = api_instance.read_cluster_role(cr, pretty=pretty, _request_timeout=1)
            for crr in CLUSTER_ROLE.rules:
                USER_CLUSTER_ROLES.append(crr)
        except Exception as error:
            ERROR = "k8sUserPriviligeList: %s" % error
            ErrorHandler(logger, "error", ERROR)
    return USER_CLUSTER_ROLES, USER_ROLES

##############################################################
## Secrets
##############################################################

@cache.memoize(timeout=short_cache_time)
def k8sSecretListGet(username_role, user_token, namespace):
    k8sClientConfigGet(username_role, user_token)
    SECRET_LIST = list()
    secret_list = k8s_client.CoreV1Api().list_namespaced_secret(namespace, _request_timeout=1)
    for secret in secret_list.items:
        SECRET_DATA = {
            "name": secret.metadata.name,
            "type": secret.type,
            "annotations": trimAnnotations(secret.metadata.annotations),
            "labels": secret.metadata.labels,
            "data": secret.data,
            "created": secret.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "version": secret.metadata.resource_version,
        }
        SECRET_LIST.append(SECRET_DATA)

    return SECRET_LIST

##############################################################
## Network Policies
##############################################################

@cache.memoize(timeout=short_cache_time)
def k8sPolicyListGet(username_role, user_token, ns_name):
    POLICY_LIST = list()
    k8sClientConfigGet(username_role, user_token)
    policy_list = k8s_client.NetworkingV1Api().list_namespaced_network_policy(ns_name, _request_timeout=1)
    try:
      for policy in policy_list.items:
          POLICY_DATA = {
              "name": policy.metadata.name,
              "namespace": policy.metadata.namespace,
              "annotations": trimAnnotations(policy.metadata.annotations),
              "labels": policy.metadata.labels,
              "pod_selector": policy.spec.pod_selector,
              "policy_types": policy.spec.policy_types,
              "imgress_rules": eval(str(policy.spec.ingress)),
              "egress_rules": eval(str(policy.spec.egress)),
              "created": policy.metadata.creation_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
          }
          POLICY_LIST.append(POLICY_DATA)
      return POLICY_LIST
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get network policy list - %s" % error.status)
        return POLICY_LIST
    except Exception as error:
        ERROR = "k8sNetworkPolicyListGet: %s" % error
        ErrorHandler(logger, "error", ERROR)
        return POLICY_LIST