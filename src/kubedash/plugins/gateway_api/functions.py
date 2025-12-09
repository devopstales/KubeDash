"""
Gateway API Plugin Functions

This module provides functions to fetch and process Gateway API resources
from a Kubernetes cluster. It supports both standard (v1) and experimental
(v1alpha2) Gateway API resources.

Standard Resources (v1):
- GatewayClass
- Gateway
- HTTPRoute
- ReferenceGrant

Experimental Resources (v1alpha2):
- GRPCRoute
- TCPRoute
- TLSRoute
- UDPRoute
- BackendTLSPolicy
"""

from logging import getLogger
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations
from lib.k8s.server import k8sClientConfigGet

logger = getLogger(__name__)

# API Group and versions
API_GROUP = "gateway.networking.k8s.io"
API_VERSION_STANDARD = "v1"
API_VERSION_EXPERIMENTAL = "v1alpha2"


def calculate_age(creation_timestamp: str) -> str:
    """Calculate age from creation timestamp to human readable format."""
    if not creation_timestamp:
        return "Unknown"
    
    try:
        # Parse ISO format timestamp
        if isinstance(creation_timestamp, str):
            created = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
        else:
            created = creation_timestamp
        
        now = datetime.now(timezone.utc)
        delta = now - created
        
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        
        if days > 0:
            return f"{days}d"
        elif hours > 0:
            return f"{hours}h"
        else:
            return f"{minutes}m"
    except Exception:
        return "Unknown"


def get_condition_status(conditions: list, condition_type: str) -> dict:
    """
    Extract status for a specific condition type from conditions list.
    
    Returns dict with 'status', 'reason', and 'message'.
    """
    if not conditions:
        return {"status": "Unknown", "reason": "NoConditions", "message": "No conditions available"}
    
    for condition in conditions:
        if condition.get("type") == condition_type:
            return {
                "status": condition.get("status", "Unknown"),
                "reason": condition.get("reason", ""),
                "message": condition.get("message", "")
            }
    
    # Return the last condition if type not found
    last = conditions[-1] if conditions else {}
    return {
        "status": last.get("status", "Unknown"),
        "reason": last.get("reason", ""),
        "message": last.get("message", "")
    }


##############################################################
# Check if Gateway API CRDs are installed
##############################################################

def check_gateway_api_installed(username_role, user_token) -> dict:
    """
    Check if Gateway API CRDs are installed in the cluster.
    
    Returns a dict with:
    - installed: bool indicating if any Gateway API CRDs exist
    - standard: list of installed standard CRDs
    - experimental: list of installed experimental CRDs
    """
    k8sClientConfigGet(username_role, user_token)
    
    standard_crds = ["gatewayclasses", "gateways", "httproutes", "referencegrants"]
    experimental_crds = ["grpcroutes", "tcproutes", "tlsroutes", "udproutes", "backendtlspolicies"]
    
    result = {
        "installed": False,
        "standard": [],
        "experimental": []
    }
    
    try:
        # Check standard resources
        for crd in standard_crds:
            try:
                k8s_client.CustomObjectsApi().list_cluster_custom_object(
                    API_GROUP, API_VERSION_STANDARD, crd, 
                    _request_timeout=1, limit=1
                )
                result["standard"].append(crd)
            except ApiException:
                pass
        
        # Check experimental resources
        for crd in experimental_crds:
            try:
                k8s_client.CustomObjectsApi().list_cluster_custom_object(
                    API_GROUP, API_VERSION_EXPERIMENTAL, crd,
                    _request_timeout=1, limit=1
                )
                result["experimental"].append(crd)
            except ApiException:
                pass
        
        result["installed"] = len(result["standard"]) > 0 or len(result["experimental"]) > 0
        
    except Exception as error:
        ErrorHandler(logger, "check_gateway_api_installed", str(error))
    
    return result


##############################################################
# GatewayClass Functions (Cluster-scoped, Standard v1)
##############################################################

def GatewayApiGetGatewayClasses(username_role, user_token) -> list:
    """
    List all GatewayClass resources (cluster-scoped).
    
    Returns list of dicts with:
    - name: GatewayClass name
    - controller: Controller name
    - description: Description from spec
    - status: Accepted/Pending status
    - status_reason: Reason for status
    - parameters_ref: Parameter reference (if any)
    - age: Age of the resource
    """
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            API_GROUP, API_VERSION_STANDARD, "gatewayclasses", 
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            # Get accepted condition
            conditions = status.get('conditions', [])
            accepted = get_condition_status(conditions, 'Accepted')
            
            # Get parameters reference
            params_ref = spec.get('parametersRef', {})
            params_str = ""
            if params_ref:
                params_str = f"{params_ref.get('group', '')}/{params_ref.get('kind', '')}:{params_ref.get('name', '')}"
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "controller": spec.get('controllerName', ''),
                "description": spec.get('description', ''),
                "status": accepted['status'],
                "status_reason": accepted['reason'],
                "status_message": accepted['message'],
                "parameters_ref": params_str,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj  # Store raw object for detail view
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get gatewayclasses")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetGatewayClasses", str(error))
        return k8s_object_list


def GatewayApiGetGatewayClass(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific GatewayClass by name."""
    k8sClientConfigGet(username_role, user_token)
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            API_GROUP, API_VERSION_STANDARD, "gatewayclasses", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        spec = obj.get('spec', {})
        status = obj.get('status', {})
        
        conditions = status.get('conditions', [])
        accepted = get_condition_status(conditions, 'Accepted')
        
        params_ref = spec.get('parametersRef', {})
        
        return {
            "name": metadata.get('name', ''),
            "controller": spec.get('controllerName', ''),
            "description": spec.get('description', ''),
            "status": accepted['status'],
            "status_reason": accepted['reason'],
            "status_message": accepted['message'],
            "parameters_ref": params_ref,
            "conditions": conditions,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": metadata.get('labels') or {},
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get gatewayclass {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetGatewayClass", str(error))
        return None


##############################################################
# Gateway Functions (Namespaced, Standard v1)
##############################################################

def GatewayApiGetGateways(username_role, user_token, namespace: str = None) -> list:
    """
    List Gateway resources.
    
    If namespace is None or "all", lists from all namespaces.
    
    Returns list of dicts with gateway information.
    """
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_STANDARD, namespace, "gateways",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_STANDARD, "gateways",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            # Get conditions
            conditions = status.get('conditions', [])
            programmed = get_condition_status(conditions, 'Programmed')
            accepted = get_condition_status(conditions, 'Accepted')
            
            # Get addresses
            addresses = status.get('addresses', [])
            address_list = [f"{addr.get('type', '')}:{addr.get('value', '')}" for addr in addresses]
            
            # Get listeners summary
            listeners = spec.get('listeners', [])
            listener_summary = []
            for listener in listeners:
                protocol = listener.get('protocol', '')
                port = listener.get('port', '')
                hostname = listener.get('hostname', '*')
                listener_summary.append({
                    "name": listener.get('name', ''),
                    "protocol": protocol,
                    "port": port,
                    "hostname": hostname,
                    "tls": listener.get('tls', {}),
                    "allowedRoutes": listener.get('allowedRoutes', {})
                })
            
            # Count attached routes from listener status
            listener_statuses = status.get('listeners', [])
            attached_routes = sum(ls.get('attachedRoutes', 0) for ls in listener_statuses)
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "gateway_class": spec.get('gatewayClassName', ''),
                "listeners": listener_summary,
                "listeners_count": len(listeners),
                "addresses": address_list,
                "attached_routes": attached_routes,
                "programmed_status": programmed['status'],
                "programmed_reason": programmed['reason'],
                "accepted_status": accepted['status'],
                "accepted_reason": accepted['reason'],
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get gateways")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetGateways", str(error))
        return k8s_object_list


def GatewayApiGetGateway(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific Gateway by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            API_GROUP, API_VERSION_STANDARD, namespace, "gateways", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        spec = obj.get('spec', {})
        status = obj.get('status', {})
        
        conditions = status.get('conditions', [])
        
        # Process listeners with their statuses
        listeners = spec.get('listeners', [])
        listener_statuses = {ls.get('name'): ls for ls in status.get('listeners', [])}
        
        processed_listeners = []
        for listener in listeners:
            name_l = listener.get('name', '')
            ls = listener_statuses.get(name_l, {})
            
            processed_listeners.append({
                "name": name_l,
                "protocol": listener.get('protocol', ''),
                "port": listener.get('port', ''),
                "hostname": listener.get('hostname', '*'),
                "tls": listener.get('tls', {}),
                "allowedRoutes": listener.get('allowedRoutes', {}),
                "attachedRoutes": ls.get('attachedRoutes', 0),
                "conditions": ls.get('conditions', [])
            })
        
        addresses = status.get('addresses', [])
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "gateway_class": spec.get('gatewayClassName', ''),
            "listeners": processed_listeners,
            "addresses": addresses,
            "conditions": conditions,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": metadata.get('labels', {}),
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get gateway {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetGateway", str(error))
        return None


##############################################################
# HTTPRoute Functions (Namespaced, Standard v1)
##############################################################

def get_route_match_summary(match: dict) -> str:
    """Summarize an HTTPRoute match for display."""
    parts = []
    
    if match.get('path'):
        path = match['path']
        path_type = path.get('type', 'PathPrefix')
        value = path.get('value', '/')
        parts.append(f"{path_type}: {value}")
    
    if match.get('headers'):
        for header in match['headers']:
            h_type = header.get('type', 'Exact')
            parts.append(f"Header({h_type}): {header.get('name', '')}={header.get('value', '')}")
    
    if match.get('queryParams'):
        for qp in match['queryParams']:
            qp_type = qp.get('type', 'Exact')
            parts.append(f"Query({qp_type}): {qp.get('name', '')}={qp.get('value', '')}")
    
    if match.get('method'):
        parts.append(f"Method: {match['method']}")
    
    return " AND ".join(parts) if parts else "Match All"


def GatewayApiGetHTTPRoutes(username_role, user_token, namespace: str = None) -> list:
    """
    List HTTPRoute resources.
    
    If namespace is None or "all", lists from all namespaces.
    """
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_STANDARD, namespace, "httproutes",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_STANDARD, "httproutes",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            # Get parent gateways
            parent_refs = spec.get('parentRefs', [])
            gateways = []
            for ref in parent_refs:
                gw_ns = ref.get('namespace', metadata.get('namespace', ''))
                gw_name = ref.get('name', '')
                gateways.append(f"{gw_ns}/{gw_name}")
            
            # Get hostnames
            hostnames = spec.get('hostnames', ['*'])
            
            # Get rules summary
            rules = spec.get('rules', [])
            backends = set()
            for rule in rules:
                for backend in rule.get('backendRefs', []):
                    backend_ns = backend.get('namespace', metadata.get('namespace', ''))
                    backend_name = backend.get('name', '')
                    backend_port = backend.get('port', '')
                    backends.add(f"{backend_name}:{backend_port}")
            
            # Get parent statuses
            parent_statuses = status.get('parents', [])
            accepted_parents = sum(1 for ps in parent_statuses 
                                   for c in ps.get('conditions', []) 
                                   if c.get('type') == 'Accepted' and c.get('status') == 'True')
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "hostnames": hostnames,
                "gateways": gateways,
                "rules_count": len(rules),
                "backends": list(backends),
                "accepted_parents": accepted_parents,
                "total_parents": len(parent_refs),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get httproutes")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetHTTPRoutes", str(error))
        return k8s_object_list


def GatewayApiGetHTTPRoute(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific HTTPRoute by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            API_GROUP, API_VERSION_STANDARD, namespace, "httproutes", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        spec = obj.get('spec', {})
        status = obj.get('status', {})
        
        # Process parent refs
        parent_refs = spec.get('parentRefs', [])
        processed_parents = []
        parent_statuses = {
            (ps.get('parentRef', {}).get('namespace', metadata.get('namespace', '')), 
             ps.get('parentRef', {}).get('name', '')): ps
            for ps in status.get('parents', [])
        }
        
        for ref in parent_refs:
            gw_ns = ref.get('namespace', metadata.get('namespace', ''))
            gw_name = ref.get('name', '')
            ps = parent_statuses.get((gw_ns, gw_name), {})
            
            processed_parents.append({
                "namespace": gw_ns,
                "name": gw_name,
                "sectionName": ref.get('sectionName', ''),
                "conditions": ps.get('conditions', [])
            })
        
        # Process rules
        rules = spec.get('rules', [])
        processed_rules = []
        for i, rule in enumerate(rules):
            matches = rule.get('matches', [{}])
            match_summaries = [get_route_match_summary(m) for m in matches]
            
            # Process backend refs
            backend_refs = []
            for backend in rule.get('backendRefs', []):
                backend_refs.append({
                    "kind": backend.get('kind', 'Service'),
                    "namespace": backend.get('namespace', metadata.get('namespace', '')),
                    "name": backend.get('name', ''),
                    "port": backend.get('port', ''),
                    "weight": backend.get('weight', 1)
                })
            
            # Process filters
            filters = rule.get('filters', [])
            
            processed_rules.append({
                "index": i + 1,
                "matches": matches,
                "match_summaries": match_summaries,
                "backendRefs": backend_refs,
                "filters": filters,
                "timeouts": rule.get('timeouts', {})
            })
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "hostnames": spec.get('hostnames', ['*']),
            "parents": processed_parents,
            "rules": processed_rules,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": metadata.get('labels', {}),
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get httproute {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetHTTPRoute", str(error))
        return None


##############################################################
# GRPCRoute Functions (Namespaced, Experimental v1alpha2)
##############################################################

def GatewayApiGetGRPCRoutes(username_role, user_token, namespace: str = None) -> list:
    """List GRPCRoute resources (experimental)."""
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, namespace, "grpcroutes",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, "grpcroutes",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            parent_refs = spec.get('parentRefs', [])
            gateways = [f"{ref.get('namespace', metadata.get('namespace', ''))}/{ref.get('name', '')}" 
                        for ref in parent_refs]
            
            hostnames = spec.get('hostnames', ['*'])
            rules = spec.get('rules', [])
            
            # Get gRPC services/methods
            services = set()
            for rule in rules:
                for match in rule.get('matches', []):
                    method = match.get('method', {})
                    svc = method.get('service', '*')
                    mth = method.get('method', '*')
                    services.add(f"{svc}/{mth}")
            
            backends = set()
            for rule in rules:
                for backend in rule.get('backendRefs', []):
                    backends.add(f"{backend.get('name', '')}:{backend.get('port', '')}")
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "hostnames": hostnames,
                "gateways": gateways,
                "services": list(services),
                "backends": list(backends),
                "rules_count": len(rules),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "experimental": True,
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get grpcroutes")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetGRPCRoutes", str(error))
        return k8s_object_list


##############################################################
# TCPRoute Functions (Namespaced, Experimental v1alpha2)
##############################################################

def GatewayApiGetTCPRoutes(username_role, user_token, namespace: str = None) -> list:
    """List TCPRoute resources (experimental)."""
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, namespace, "tcproutes",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, "tcproutes",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            parent_refs = spec.get('parentRefs', [])
            gateways = [f"{ref.get('namespace', metadata.get('namespace', ''))}/{ref.get('name', '')}" 
                        for ref in parent_refs]
            
            rules = spec.get('rules', [])
            backends = set()
            for rule in rules:
                for backend in rule.get('backendRefs', []):
                    backends.add(f"{backend.get('name', '')}:{backend.get('port', '')}")
            
            parent_statuses = status.get('parents', [])
            accepted_parents = sum(1 for ps in parent_statuses 
                                   for c in ps.get('conditions', []) 
                                   if c.get('type') == 'Accepted' and c.get('status') == 'True')
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "gateways": gateways,
                "backends": list(backends),
                "rules_count": len(rules),
                "accepted_parents": accepted_parents,
                "total_parents": len(parent_refs),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "experimental": True,
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get tcproutes")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetTCPRoutes", str(error))
        return k8s_object_list


##############################################################
# TLSRoute Functions (Namespaced, Experimental v1alpha2)
##############################################################

def GatewayApiGetTLSRoutes(username_role, user_token, namespace: str = None) -> list:
    """List TLSRoute resources (experimental)."""
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, namespace, "tlsroutes",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, "tlsroutes",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            parent_refs = spec.get('parentRefs', [])
            gateways = [f"{ref.get('namespace', metadata.get('namespace', ''))}/{ref.get('name', '')}" 
                        for ref in parent_refs]
            
            hostnames = spec.get('hostnames', ['*'])
            
            rules = spec.get('rules', [])
            backends = set()
            for rule in rules:
                for backend in rule.get('backendRefs', []):
                    backends.add(f"{backend.get('name', '')}:{backend.get('port', '')}")
            
            parent_statuses = status.get('parents', [])
            accepted_parents = sum(1 for ps in parent_statuses 
                                   for c in ps.get('conditions', []) 
                                   if c.get('type') == 'Accepted' and c.get('status') == 'True')
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "hostnames": hostnames,
                "gateways": gateways,
                "backends": list(backends),
                "rules_count": len(rules),
                "accepted_parents": accepted_parents,
                "total_parents": len(parent_refs),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "experimental": True,
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get tlsroutes")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetTLSRoutes", str(error))
        return k8s_object_list


##############################################################
# ReferenceGrant Functions (Namespaced, Standard v1)
##############################################################

def GatewayApiGetReferenceGrants(username_role, user_token, namespace: str = None) -> list:
    """List ReferenceGrant resources."""
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_STANDARD, namespace, "referencegrants",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_STANDARD, "referencegrants",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            
            # Process "from" references
            from_refs = spec.get('from', [])
            from_summary = []
            for ref in from_refs:
                from_summary.append({
                    "group": ref.get('group', ''),
                    "kind": ref.get('kind', ''),
                    "namespace": ref.get('namespace', '')
                })
            
            # Process "to" references
            to_refs = spec.get('to', [])
            to_summary = []
            for ref in to_refs:
                to_summary.append({
                    "group": ref.get('group', ''),
                    "kind": ref.get('kind', ''),
                    "name": ref.get('name', '')
                })
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "from": from_summary,
                "to": to_summary,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get referencegrants")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetReferenceGrants", str(error))
        return k8s_object_list


##############################################################
# BackendTLSPolicy Functions (Namespaced, Experimental v1alpha2)
##############################################################

def GatewayApiGetBackendTLSPolicies(username_role, user_token, namespace: str = None) -> list:
    """List BackendTLSPolicy resources (experimental)."""
    k8sClientConfigGet(username_role, user_token)
    k8s_object_list = []
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, namespace, "backendtlspolicies",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                API_GROUP, API_VERSION_EXPERIMENTAL, "backendtlspolicies",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            spec = obj.get('spec', {})
            status = obj.get('status', {})
            
            # Get target reference
            target_ref = spec.get('targetRef', {})
            target_str = f"{target_ref.get('kind', '')}/{target_ref.get('name', '')}"
            
            # Get TLS settings
            tls = spec.get('tls', {})
            hostname = tls.get('hostname', '')
            
            # Get conditions
            conditions = status.get('conditions', [])
            accepted = get_condition_status(conditions, 'Accepted')
            
            k8s_object_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "target": target_str,
                "hostname": hostname,
                "status": accepted['status'],
                "status_reason": accepted['reason'],
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "experimental": True,
                "raw": obj
            }
            k8s_object_list.append(k8s_object_data)
            
        return k8s_object_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get backendtlspolicies")
        return k8s_object_list
    except Exception as error:
        ErrorHandler(logger, "GatewayApiGetBackendTLSPolicies", str(error))
        return k8s_object_list


##############################################################
# Events Functions
##############################################################

def GatewayApiGetEvents(
    kind: str,
    name: str,
    namespace: str,
    username_role: str,
    user_token: str,
    uid: str = None,
    limit: int = 50
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Fetch Kubernetes events related to a Gateway API object.
    
    Args:
        kind: The Gateway API object kind (e.g., Gateway, HTTPRoute, GatewayClass)
        name: The name of the object
        namespace: The namespace of the object (use None for cluster-scoped resources)
        username_role: User role for authorization
        user_token: User token for authentication
        uid: Optional UID of the object for more precise matching
        limit: Maximum number of events to return
        
    Returns:
        Tuple of (events_list, error_message)
        - On success: (events_list, None)
        - On error: ([], error_message)
    """
    k8sClientConfigGet(username_role, user_token)
    core_api = k8s_client.CoreV1Api()
    
    try:
        # Field selector to filter events by involved object
        # Try with UID first if available (more precise), otherwise use name+kind
        if uid:
            field_selector = f"involvedObject.uid={uid}"
        else:
            field_selector = f"involvedObject.name={name},involvedObject.kind={kind}"
        
        # For cluster-scoped resources (GatewayClass), use list_event_for_all_namespaces
        if namespace:
            events = core_api.list_namespaced_event(
                namespace=namespace,
                field_selector=field_selector,
                limit=limit,
                _request_timeout=5
            )
        else:
            # For cluster-scoped resources, search all namespaces
            events = core_api.list_event_for_all_namespaces(
                field_selector=field_selector,
                limit=limit,
                _request_timeout=5
            )
        
        # Convert to list of dicts and sort by last timestamp (newest first)
        event_list = []
        for event in events.items:
            # Additional filter: ensure the event actually matches our object
            # (field selector might match multiple objects with same name in different namespaces)
            if event.involved_object.name == name and event.involved_object.kind == kind:
                if namespace is None or event.involved_object.namespace == namespace:
                    event_dict = {
                        "type": event.type,
                        "reason": event.reason,
                        "message": event.message,
                        "count": event.count or 1,
                        "first_timestamp": event.first_timestamp.isoformat() if event.first_timestamp else None,
                        "last_timestamp": event.last_timestamp.isoformat() if event.last_timestamp else None,
                        "source": event.source.component if event.source else None,
                        "reporting_controller": getattr(event, 'reporting_controller', None),
                    }
                    event_list.append(event_dict)
        
        # Sort by last_timestamp descending (newest first)
        event_list.sort(
            key=lambda x: x.get("last_timestamp") or x.get("first_timestamp") or "",
            reverse=True
        )
        
        return event_list, None
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get events for {kind} {name}")
        return [], None  # Return empty list instead of error for 404
    except Exception as error:
        ErrorHandler(logger, error, f"get events for {kind} {name}")
        return [], None  # Return empty list on error
