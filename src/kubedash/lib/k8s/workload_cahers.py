from flask import Flask, current_app
from kubernetes import client, config

from .server import k8sClientConfigGet
from lib.components import cache

##############################################################
## Pods
##############################################################
def check_user_can_get_pods(username_role, user_token, ns):
    """Check if the user can get pods in the specified namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        bool: True if the user can get pods, False otherwise
    """
    k8sClientConfigGet(username_role, user_token)
    
    auth_api = client.AuthorizationV1Api()

    access_review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=ns,
                verb="get",
                resource="pods"
            )
        )
    )

    response = auth_api.create_self_subject_access_review(access_review)

    if response.status.allowed:
        return True
    else:
        return False

def fetch_and_cache_pods_all_namespaces(app: Flask):
    """Fetch all pods across all namespaces and cache them.
    
    Args:
        app (Flask): Flask app
        
    Returns:
        None
    """
    with app.app_context():  # Flask app context
        # Initialize Kubernetes client
        k8sClientConfigGet("admin", None)

        v1 = client.CoreV1Api()

        current_app.logger.info("[ThreadedTicker] Fetching pods from all namespaces")

        # Retrieve all pods across all namespaces
        pods = v1.list_pod_for_all_namespaces(watch=False)

        namespace_pod_map = {}

        # Organize pods by namespace
        for pod in pods.items:
            ns = pod.metadata.namespace

            # Convert the entire pod object to a Python dict (or use pod.to_str() for raw JSON string)
            pod_dict = pod.to_dict()

            if ns not in namespace_pod_map:
                namespace_pod_map[ns] = []
            namespace_pod_map[ns].append(pod_dict)

        # Cache pod lists per namespace (as JSON if you prefer)
        for ns, pod_list in namespace_pod_map.items():
            cache_key = f"pods_in_{ns}"
            cache.set(cache_key, pod_list)

            current_app.logger.info(
                f"[ThreadedTicker] Cached {len(pod_list)} full pod objects in namespace '{ns}' under key '{cache_key}'"
            )

##############################################################
## Deployments
##############################################################

def check_user_can_get_deployments(username_role, user_token, ns):
    """Check if the user can get deployments in the specified namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        bool: True if the user can get deployments, False otherwise
    """
    k8sClientConfigGet(username_role, user_token)
    
    auth_api = client.AuthorizationV1Api()

    access_review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=ns,
                verb="get",
                resource="deployments"
            )
        )
    )

    response = auth_api.create_self_subject_access_review(access_review)

    if response.status.allowed:
        return True
    else:
        return False
    

def fetch_and_cache_deployments_all_namespaces(app: Flask):
    """Fetch all deployments across all namespaces and cache them.
    
    Args:
        app (Flask): Flask app
        
    Returns:
        None
    """
    
    with app.app_context():  # Flask app context
        # Initialize Kubernetes client
        k8sClientConfigGet("admin", None)

        apps_v1 = client.AppsV1Api()

        current_app.logger.info("[ThreadedTicker] Fetching deployments from all namespaces")

        # Retrieve all deployments across all namespaces
        deployments = apps_v1.list_deployment_for_all_namespaces(watch=False)

        namespace_deployment_map = {}

        # Organize deployments by namespace
        for deployment in deployments.items:
            ns = deployment.metadata.namespace

            # Convert the entire deployment object to a Python dict (or use deployment.to_str() for raw JSON string)
            deployment_dict = deployment.to_dict()

            if ns not in namespace_deployment_map:
                namespace_deployment_map[ns] = []
            namespace_deployment_map[ns].append(deployment_dict)

        # Cache deployment lists per namespace (as JSON if you prefer)
        for ns, deployment_list in namespace_deployment_map.items():
            cache_key = f"deployments_in_{ns}"
            cache.set(cache_key, deployment_list)

            current_app.logger.info(
                f"[ThreadedTicker] Cached {len(deployment_list)} full deployment objects in namespace '{ns}' under key '{cache_key}'"
            )

##############################################################
## DaemonSets
##############################################################

def check_user_can_get_daemonsets(username_role, user_token, ns):
    """Check if the user can get daemonsets in the specified namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        bool: True if the user can get daemonsets, False otherwise
    """
    k8sClientConfigGet(username_role, user_token)
    
    auth_api = client.AuthorizationV1Api()

    access_review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=ns,
                verb="get",
                resource="daemonsets"
            )
        )
    )

    response = auth_api.create_self_subject_access_review(access_review)

    if response.status.allowed:
        return True
    else:
        return False
    

def fetch_and_cache_daemonsets_all_namespaces(app: Flask):
    """Fetch all daemonsets across all namespaces and cache them.
    
    Args:
        app (Flask): Flask app
        
    Returns:
        None
    """
    
    with app.app_context():  # Flask app context
        # Initialize Kubernetes client
        k8sClientConfigGet("admin", None)

        apps_v1 = client.AppsV1Api()

        current_app.logger.info("[ThreadedTicker] Fetching daemonsets from all namespaces")

        # Retrieve all daemonsets across all namespaces
        daemonsets = apps_v1.list_daemon_set_for_all_namespaces(watch=False)

        namespace_daemonset_map = {}

        # Organize daemonsets by namespace
        for daemonset in daemonsets.items:
            ns = daemonset.metadata.namespace

            # Convert the entire daemonset object to a Python dict (or use daemonset.to_str() for raw JSON string)
            daemonset_dict = daemonset.to_dict()

            if ns not in namespace_daemonset_map:
                namespace_daemonset_map[ns] = []
            namespace_daemonset_map[ns].append(daemonset_dict)

        # Cache daemonset lists per namespace (as JSON if you prefer)
        for ns, daemonset_list in namespace_daemonset_map.items():
            cache_key = f"daemonsets_in_{ns}"
            cache.set(cache_key, daemonset_list)

            current_app.logger.info(
                f"[ThreadedTicker] Cached {len(daemonset_list)} full daemonset objects in namespace '{ns}' under key '{cache_key}'"
            )
        
##############################################################
## StatefulSets
##############################################################

def check_user_can_get_statefulsets(username_role, user_token, ns):
    """Check if the user can get statefulsets in the specified namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        bool: True if the user can get statefulsets, False otherwise
    """
    
    k8sClientConfigGet(username_role, user_token)
    
    auth_api = client.AuthorizationV1Api()

    access_review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=ns,
                verb="get",
                resource="statefulsets"
            )
        )
    )

    response = auth_api.create_self_subject_access_review(access_review)

    if response.status.allowed:
        return True
    else:
        return False
    

def fetch_and_cache_statefulsets_all_namespaces(app: Flask):
    """Fetch all statefulsets across all namespaces and cache them.
    
    Args:
        app (Flask): Flask app
        
    Returns:
        None
    """
    
    with app.app_context():  # Flask app context
        # Initialize Kubernetes client
        k8sClientConfigGet("admin", None)

        apps_v1 = client.AppsV1Api()
        current_app.logger.info("[ThreadedTicker] Fetching statefulsets from all namespaces")
        # Retrieve all statefulsets across all namespaces
        statefulsets = apps_v1.list_stateful_set_for_all_namespaces(watch=False)
        namespace_statefulset_map = {}
        # Organize statefulsets by namespace
        for statefulset in statefulsets.items:
            ns = statefulset.metadata.namespace
            # Convert the entire statefulset object to a Python dict (or use statefulset.to_str() for raw JSON string)
            statefulset_dict = statefulset.to_dict()
            if ns not in namespace_statefulset_map:
                namespace_statefulset_map[ns] = []
            namespace_statefulset_map[ns].append(statefulset_dict)
        # Cache statefulset lists per namespace (as JSON if you prefer)
        for ns, statefulset_list in namespace_statefulset_map.items():
            cache_key = f"statefulsets_in_{ns}"
            cache.set(cache_key, statefulset_list)
            current_app.logger.info(
                f"[ThreadedTicker] Cached {len(statefulset_list)} full statefulset objects in namespace '{ns}' under key '{cache_key}'"
            )
        
##############################################################
## ReplicaSets
##############################################################

def check_user_can_get_replicasets(username_role, user_token, ns):
    """Check if the user can get replicasets in the specified namespace.
    
    Args:
        username_role (str): Role of the current user
        user_token (str): Auth token of the current user
        ns (str): Namespace name
        
    Returns:
        bool: True if the user can get replicasets, False otherwise
    """
    
    k8sClientConfigGet(username_role, user_token)
    
    auth_api = client.AuthorizationV1Api()

    access_review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                namespace=ns,
                verb="get",
                resource="replicasets"
            )
        )
    )

    response = auth_api.create_self_subject_access_review(access_review)

    if response.status.allowed:
        return True
    else:
        return False
    

def fetch_and_cache_replicasets_all_namespaces(app: Flask):
    """Fetch all replicasets across all namespaces and cache them.
    
    Args:
        app (Flask): Flask app
        
    Returns:
        None
    """
    
    with app.app_context():  # Flask app context
        # Initialize Kubernetes client
        k8sClientConfigGet("admin", None)

        apps_v1 = client.AppsV1Api()
        current_app.logger.info("[ThreadedTicker] Fetching replicasets from all namespaces")
        # Retrieve all replicasets across all namespaces
        replicasets = apps_v1.list_replica_set_for_all_namespaces(watch=False)
        namespace_replicaset_map = {}
        # Organize replicasets by namespace
        for replicaset in replicasets.items:
            ns = replicaset.metadata.namespace
            # Convert the entire replicaset object to a Python dict (or use replicaset.to_str() for raw JSON string)
            replicaset_dict = replicaset.to_dict()
            if ns not in namespace_replicaset_map:
                namespace_replicaset_map[ns] = []
            namespace_replicaset_map[ns].append(replicaset_dict)
        # Cache replicaset lists per namespace (as JSON if you prefer)
        for ns, replicaset_list in namespace_replicaset_map.items():
            cache_key = f"replicasets_in_{ns}"
            cache.set(cache_key, replicaset_list)
            current_app.logger.info(
                f"[ThreadedTicker] Cached {len(replicaset_list)} full replicaset objects in namespace '{ns}' under key '{cache_key}'"
            )
