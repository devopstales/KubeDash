from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler
from lib.components import cache, short_cache_time, long_cache_time

from . import logger, tracer
from .server import k8sClientConfigGet

##############################################################
## Variables
##############################################################

api_client = k8s_client.ApiClient()
discovery  = k8s_client.ApisApi(api_client)
custom_api = k8s_client.CustomObjectsApi(api_client)

##############################################################
## CRD
##############################################################

@cache.memoize(timeout=long_cache_time)
def get_custom_resources(username_role, user_token):
    """Get custom resources from Kubernetes
    Args:
        username_role (str): The role of the user (e.g., 'Admin', 'User').
        user_token (str): The user's authentication token.
        
    Returns:
        list: A list of custom resources (CRDs) available in the Kubernetes cluster.
    """
    crd_list = []
    k8sClientConfigGet(username_role, user_token)
    
    groups = discovery.get_api_versions().groups
    for group in groups:
        group_name = group.name
        for version_info in group.versions:
            version = version_info.version
            try:
                group_version = f"{group_name}/{version}"
                api = custom_api
                resources = api_client.call_api(
                    f'/apis/{group_version}', 'GET',
                    response_type='object'
                )[0]
                
                for resource in resources.get('resources', []):
                    if '/' not in resource['name']:
                        crd_list.append({
                            "name": resource['name'],
                            "kind": resource['kind'],
                            "group": group_name,
                            "version": version,
                            "scope": resource.get('namespaced', True) and "Namespaced" or "Cluster"
                        })
            except ApiException as error:
                if error.status != 404:
                    ErrorHandler(logger, error, "get_custom_resources - %s " % error.status)
            except Exception as error:
                ErrorHandler(logger, "CannotConnect", f"get_custom_resources for {group_name}/{version}: {error}")
    
    return crd_list

@cache.memoize(timeout=short_cache_time)
def get_custom_resource_data(username_role, user_token, namespace, crd_name, crd_group, crd_version):
    try:
        if namespace is not None:
            # Namespaced CRD
            response = custom_api.list_namespaced_custom_object(
                group=crd_group,
                version=crd_version,
                namespace=namespace,
                plural=crd_name
            )
        else:
            # Cluster-scoped CRD
            response = custom_api.list_cluster_custom_object(
                group=crd_group,
                version=crd_version,
                plural=crd_name
            )

        resources = response.get("items", [])
        results = []

        for item in resources:
            metadata = item.get("metadata", {})
            status = item.get("status", {})
            conditions = status.get("conditions", [])

            # Default values
            condition = conditions[0] if conditions else {}
            result = {
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace") if namespace is not None else None,
                "message": condition.get("message"),
                "reason": condition.get("reason"),
                "status": condition.get("status"),
                "type": condition.get("type")
            }
            results.append(result)

        print(results) # Debug
        return results
    
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get_custom_resource_data - %s " % error.status)
            return []
    except Exception as error:
        if namespace is not None:
            ErrorHandler(logger, "CannotConnect", f"get_custom_resource_data for {namespace}/{crd_group}/{crd_version}: {error}")
            return []
        else:
            ErrorHandler(logger, "CannotConnect", f"get_custom_resource_data for {crd_group}/{crd_version} in namespace {namespace}: {error}")
            return []