"""
Authorization module for Kubernetes Extension API Server.

This module handles authorization checks using Kubernetes SubjectAccessReview API
to determine if a user can access specific namespaces/resources.
"""

from contextlib import nullcontext
from typing import List, Optional

from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode

from . import logger, tracer
from .authentication import AuthenticatedUser
from lib.k8s.server import k8sClientConfigGet

##############################################################
## Authorization Functions
##############################################################

def check_namespace_access(
    user: AuthenticatedUser,
    namespace: str,
    verb: str = "list",
    resource: str = "pods",
    api_group: str = ""
) -> bool:
    """
    Check if a user can access a specific namespace using SubjectAccessReview.
    
    Args:
        user: The authenticated user
        namespace: The namespace to check access for
        verb: The action verb (get, list, watch, create, etc.)
        resource: The resource type to check (pods, configmaps, etc.)
        api_group: The API group ("" for core, "apps" for deployments, etc.)
        
    Returns:
        bool: True if user has access, False otherwise
    """
    with tracer.start_as_current_span(
        "check-namespace-access",
        attributes={
            "authz.user": user.username,
            "authz.namespace": namespace,
            "authz.verb": verb,
            "authz.resource": resource,
        }
    ) if tracer else nullcontext() as span:
        
        try:
            # Use Admin role to perform SubjectAccessReview
            k8sClientConfigGet("Admin", None)
            
            # Create SubjectAccessReview request
            sar = k8s_client.V1SubjectAccessReview(
                spec=k8s_client.V1SubjectAccessReviewSpec(
                    user=user.username,
                    groups=user.groups,
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        namespace=namespace,
                        verb=verb,
                        resource=resource,
                        group=api_group
                    )
                )
            )
            
            # Call SubjectAccessReview API
            api = k8s_client.AuthorizationV1Api()
            result = api.create_subject_access_review(sar, _request_timeout=5)
            
            allowed = result.status.allowed
            
            if tracer and span and span.is_recording():
                span.set_attribute("authz.allowed", allowed)
                if result.status.reason:
                    span.set_attribute("authz.reason", result.status.reason)
            
            logger.debug(
                f"SubjectAccessReview: user={user.username} namespace={namespace} "
                f"verb={verb} resource={resource} allowed={allowed}"
            )
            
            return allowed
            
        except ApiException as e:
            logger.error(f"SubjectAccessReview API error: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"SubjectAccessReview failed: {e.reason}"))
            # Fail closed - deny access on error
            return False
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Authorization error: {e}"))
            return False


def filter_namespaces_by_permission(
    user: AuthenticatedUser,
    namespaces: List[str],
    verb: str = "list",
    resource: str = "pods",
    api_group: str = ""
) -> List[str]:
    """
    Filter a list of namespaces to only those the user can access.
    
    Args:
        user: The authenticated user
        namespaces: List of namespace names to filter
        verb: The action verb to check
        resource: The resource type to check
        api_group: The API group
        
    Returns:
        List[str]: Filtered list of namespaces the user can access
    """
    with tracer.start_as_current_span(
        "filter-namespaces-by-permission",
        attributes={
            "authz.user": user.username,
            "authz.namespace_count": len(namespaces),
            "authz.verb": verb,
            "authz.resource": resource,
        }
    ) if tracer else nullcontext() as span:
        
        allowed_namespaces = []
        
        for ns in namespaces:
            if check_namespace_access(user, ns, verb, resource, api_group):
                allowed_namespaces.append(ns)
        
        if tracer and span and span.is_recording():
            span.set_attribute("authz.allowed_count", len(allowed_namespaces))
        
        logger.debug(
            f"Filtered namespaces for {user.username}: "
            f"{len(allowed_namespaces)}/{len(namespaces)} allowed"
        )
        
        return allowed_namespaces


def can_user_list_all_namespaces(user: AuthenticatedUser) -> bool:
    """
    Check if user has cluster-wide namespace list permission.
    
    This is useful to determine if we need to filter namespaces at all,
    or if the user is a cluster admin with full access.
    
    Args:
        user: The authenticated user
        
    Returns:
        bool: True if user can list all namespaces, False otherwise
    """
    with tracer.start_as_current_span(
        "check-cluster-namespace-access",
        attributes={
            "authz.user": user.username,
        }
    ) if tracer else nullcontext() as span:
        
        try:
            k8sClientConfigGet("Admin", None)
            
            # Check for cluster-wide namespace list permission
            sar = k8s_client.V1SubjectAccessReview(
                spec=k8s_client.V1SubjectAccessReviewSpec(
                    user=user.username,
                    groups=user.groups,
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        verb="list",
                        resource="namespaces",
                        group=""
                    )
                )
            )
            
            api = k8s_client.AuthorizationV1Api()
            result = api.create_subject_access_review(sar, _request_timeout=5)
            
            logger.debug(
                f"SubjectAccessReview for {user.username} (groups={user.groups}): "
                f"list namespaces = {result.status.allowed}"
            )
            
            if tracer and span and span.is_recording():
                span.set_attribute("authz.cluster_admin", result.status.allowed)
            
            return result.status.allowed
            
        except Exception as e:
            logger.error(f"Cluster namespace access check error for {user.username}: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return False


def check_self_subject_access(
    namespace: str,
    verb: str,
    resource: str,
    api_group: str = "",
    user_token: str = None
) -> bool:
    """
    Check access using SelfSubjectAccessReview (uses the caller's credentials).
    
    This is an alternative to SubjectAccessReview that doesn't require
    impersonation permissions.
    
    Args:
        namespace: The namespace to check
        verb: The action verb
        resource: The resource type
        api_group: The API group
        user_token: The user's bearer token
        
    Returns:
        bool: True if the caller has access, False otherwise
    """
    with tracer.start_as_current_span(
        "check-self-subject-access",
        attributes={
            "authz.namespace": namespace,
            "authz.verb": verb,
            "authz.resource": resource,
        }
    ) if tracer else nullcontext() as span:
        
        try:
            # Configure client with user's token if provided
            if user_token:
                from lib.k8s.server import k8sServerConfigGet
                k8s_config = k8sServerConfigGet()
                if k8s_config:
                    from itsdangerous import base64_decode
                    configuration = k8s_client.Configuration()
                    configuration.host = k8s_config.k8s_server_url
                    k8s_server_ca = str(base64_decode(k8s_config.k8s_server_ca), 'UTF-8')
                    if k8s_server_ca:
                        with open("CA.crt", "w+") as f:
                            f.write(k8s_server_ca)
                        configuration.ssl_ca_cert = 'CA.crt'
                    configuration.api_key_prefix['authorization'] = 'Bearer'
                    configuration.api_key["authorization"] = user_token
                    k8s_client.Configuration.set_default(configuration)
            else:
                k8sClientConfigGet("Admin", None)
            
            # Create SelfSubjectAccessReview
            ssar = k8s_client.V1SelfSubjectAccessReview(
                spec=k8s_client.V1SelfSubjectAccessReviewSpec(
                    resource_attributes=k8s_client.V1ResourceAttributes(
                        namespace=namespace,
                        verb=verb,
                        resource=resource,
                        group=api_group
                    )
                )
            )
            
            api = k8s_client.AuthorizationV1Api()
            result = api.create_self_subject_access_review(ssar, _request_timeout=5)
            
            if tracer and span and span.is_recording():
                span.set_attribute("authz.allowed", result.status.allowed)
            
            return result.status.allowed
            
        except Exception as e:
            logger.error(f"SelfSubjectAccessReview error: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return False
