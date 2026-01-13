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
    k8sClientConfigGet(username_role, user_token)
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
        logger.info(f"Kubernetes API returned {len(resources)} items for CRD {crd_name} (group={crd_group}, version={crd_version}, namespace={namespace})")
        
        if len(resources) == 0:
            logger.debug(f"No resources found for CRD {crd_name}. This is normal if no instances exist.")
        else:
            logger.debug(f"Processing {len(resources)} resources for CRD {crd_name}")
        
        results = []

        for item in resources:
            metadata = item.get("metadata", {})
            status = item.get("status", {})
            spec = item.get("spec", {})
            conditions = status.get("conditions", [])

            # Extract namespace from metadata (always, not just when namespace parameter is provided)
            # This is important because the metadata always contains the namespace for namespaced resources
            item_namespace = metadata.get("namespace")
            
            # Find the "Ready" condition first, or use the first condition if no Ready condition exists
            condition = {}
            ready_condition = None
            for cond in conditions:
                if cond.get("type") == "Ready":
                    ready_condition = cond
                    break
            
            # Use Ready condition if found, otherwise use first condition, otherwise empty dict
            if ready_condition:
                condition = ready_condition
            elif conditions:
                condition = conditions[0]
            
            # Build result with comprehensive data
            result = {
                "name": metadata.get("name") or "",
                "namespace": item_namespace or (None if namespace is None else ""),  # Always extract from metadata
                "uid": metadata.get("uid"),
                "creationTimestamp": metadata.get("creationTimestamp"),
                "generation": metadata.get("generation"),
                "resourceVersion": metadata.get("resourceVersion"),
                # Status fields - try condition first, then status level, then empty string
                "message": condition.get("message") or status.get("message") or "",
                "reason": condition.get("reason") or status.get("reason") or "",
                "status": condition.get("status") or status.get("phase") or status.get("state") or "",
                "type": condition.get("type") or "",
                # Additional status info
                "observedGeneration": status.get("observedGeneration"),
                # Spec summary (first few keys as string)
                "specKeys": list(spec.keys())[:5] if spec else []
            }
            results.append(result)

        logger.info(f"Retrieved {len(results)} items for CRD {crd_name} (group={crd_group}, version={crd_version}) in {namespace or 'cluster'}")
        if len(results) == 0 and len(resources) > 0:
            logger.warning(f"Found {len(resources)} resources but extracted 0 results. This might indicate a data extraction issue.")
        return results
    
    except ApiException as error:
        if error.status == 404:
            # 404 is expected if no resources exist, return empty list
            logger.debug(f"CRD {crd_name} not found (404) - likely no resources exist")
            return []
        else:
            ErrorHandler(logger, error, f"get_custom_resource_data - {error.status}: {error.reason}")
            # Return None to indicate an error (not just empty results)
            return None
    except Exception as error:
        ErrorHandler(logger, "CannotConnect", f"get_custom_resource_data for {crd_group}/{crd_version}/{crd_name} in namespace {namespace}: {error}")
        # Return None to indicate an error
        return None