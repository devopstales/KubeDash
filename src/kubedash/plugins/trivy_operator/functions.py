"""
Trivy Operator Plugin Functions

This module provides functions to fetch and process Trivy Operator security reports
from a Kubernetes cluster. It supports both:
- aquasecurity.github.io/v1alpha1 (Aqua Security's Trivy Operator)
- trivy-operator.devopstales.io/v1 (DevOps Tales fork)

Report Types:
- VulnerabilityReport: Container image vulnerabilities
- ConfigAuditReport: Configuration misconfigurations
- ExposedSecretReport: Exposed secrets detection
- RbacAssessmentReport: RBAC security assessments
- SbomReport: Software Bill of Materials (SBOM) for container images
"""

from logging import getLogger
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import ErrorHandler, trimAnnotations
from lib.k8s.server import k8sClientConfigGet

logger = getLogger(__name__)

# API Groups and versions - try both known variants
API_GROUPS = [
    ("trivy-operator.devopstales.io", "v1"),
    ("aquasecurity.github.io", "v1alpha1"),
]

# Report types - Namespace scoped
REPORT_TYPES = {
    "vulnerabilityreports": "VulnerabilityReport",
    "configauditreports": "ConfigAuditReport",
    "exposedsecretreports": "ExposedSecretReport",
    "rbacassessmentreports": "RbacAssessmentReport",
    "sbomreports": "SbomReport",
    "infraassessmentreports": "InfraAssessmentReport",
}

# Cluster scoped report types
CLUSTER_REPORT_TYPES = {
    "clustercompliancereports": "ClusterComplianceReport",
    "clustervulnerabilityreports": "ClusterVulnerabilityReport",
    "clusterconfigauditreports": "ClusterConfigAuditReport",
    "clusterinfraassessmentreports": "ClusterInfraAssessmentReport",
    "clusterrbacassessmentreports": "ClusterRbacAssessmentReport",
}


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


def _get_api_group_version(username_role, user_token):
    """
    Try to detect which API group/version is available.
    Returns (api_group, api_version) or None if not found.
    """
    k8sClientConfigGet(username_role, user_token)
    for api_group, api_version in API_GROUPS:
        try:
            # Try to list vulnerabilityreports as a test
            k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "vulnerabilityreports",
                _request_timeout=1, limit=1
            )
            return (api_group, api_version)
        except ApiException:
            continue
        except Exception:
            continue
    return None


##############################################################
# Check if Trivy Operator CRDs are installed
##############################################################

def check_trivy_operator_installed(username_role, user_token) -> dict:
    """
    Check if Trivy Operator CRDs are installed in the cluster.
    
    Returns a dict with:
    - installed: bool indicating if any Trivy Operator CRDs exist
    - api_group: detected API group
    - api_version: detected API version
    - report_types: list of available report types
    """
    k8sClientConfigGet(username_role, user_token)
    
    result = {
        "installed": False,
        "api_group": None,
        "api_version": None,
        "report_types": []
    }
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return result
    
    api_group, api_version = api_info
    result["api_group"] = api_group
    result["api_version"] = api_version
    
    # Check namespace-scoped report types
    for plural, singular in REPORT_TYPES.items():
        try:
            k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, plural,
                _request_timeout=1, limit=1
            )
            result["report_types"].append(plural)
        except ApiException:
            pass
        except Exception:
            pass
    
    # Check cluster-scoped report types
    for plural, singular in CLUSTER_REPORT_TYPES.items():
        try:
            k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, plural,
                _request_timeout=1, limit=1
            )
            result["report_types"].append(plural)
        except ApiException:
            pass
        except Exception:
            pass
    
    result["installed"] = len(result["report_types"]) > 0
    
    return result


##############################################################
# VulnerabilityReport Functions
##############################################################

def TrivyGetVulnerabilityReports(username_role, user_token, namespace: str = None) -> list:
    """
    List VulnerabilityReport resources.
    
    If namespace is None or "all", lists from all namespaces.
    """
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "vulnerabilityreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "vulnerabilityreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            container_name = labels.get('trivy-operator.container.name', 'Unknown')
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "container_name": container_name,
                "critical": summary.get('criticalCount', 0),
                "high": summary.get('highCount', 0),
                "medium": summary.get('mediumCount', 0),
                "low": summary.get('lowCount', 0),
                "unknown": summary.get('unknownCount', 0),
                "total": summary.get('criticalCount', 0) + summary.get('highCount', 0) + 
                         summary.get('mediumCount', 0) + summary.get('lowCount', 0) + 
                         summary.get('unknownCount', 0),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get vulnerabilityreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetVulnerabilityReports", str(error))
        return report_list


def TrivyGetVulnerabilityReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific VulnerabilityReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "vulnerabilityreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        vulnerabilities = report.get('vulnerabilities', [])
        artifact = report.get('artifact', {})
        
        # Process vulnerabilities
        processed_vulns = []
        for vuln in vulnerabilities:
            processed_vulns.append({
                "vulnerabilityID": vuln.get('vulnerabilityID', ''),
                "severity": vuln.get('severity', ''),
                "title": vuln.get('title', ''),
                "description": vuln.get('description', ''),
                "resource": vuln.get('resource', ''),
                "installedVersion": vuln.get('installedVersion', ''),
                "fixedVersion": vuln.get('fixedVersion', ''),
                "publishedDate": vuln.get('publishedDate', ''),
                "lastModifiedDate": vuln.get('lastModifiedDate', ''),
                "score": vuln.get('score', None),
                "primaryLink": vuln.get('primaryLink', ''),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        # Extract image information from artifact
        image_info = {
            "registry": artifact.get('registry', ''),
            "repository": artifact.get('repository', ''),
            "tag": artifact.get('tag', ''),
            "digest": artifact.get('digest', ''),
        }
        
        # Build full image reference if available
        image_ref = ""
        if image_info["registry"] and image_info["repository"]:
            image_ref = f"{image_info['registry']}/{image_info['repository']}"
            if image_info["tag"]:
                image_ref += f":{image_info['tag']}"
            if image_info["digest"]:
                image_ref += f"@{image_info['digest']}"
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "container_name": labels.get('trivy-operator.container.name', 'Unknown'),
            "image": image_info,
            "image_ref": image_ref,
            "summary": summary,
            "vulnerabilities": processed_vulns,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get vulnerabilityreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetVulnerabilityReport", str(error))
        return None


##############################################################
# ConfigAuditReport Functions
##############################################################

def TrivyGetConfigAuditReports(username_role, user_token, namespace: str = None) -> list:
    """List ConfigAuditReport resources."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "configauditreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "configauditreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            # ConfigAuditReport uses criticalCount, highCount, mediumCount, lowCount
            critical = summary.get('criticalCount', 0)
            high = summary.get('highCount', 0)
            medium = summary.get('mediumCount', 0)
            low = summary.get('lowCount', 0)
            total = critical + high + medium + low
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get configauditreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetConfigAuditReports", str(error))
        return report_list


def TrivyGetConfigAuditReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific ConfigAuditReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "configauditreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        checks = report.get('checks', [])
        
        # Process checks
        processed_checks = []
        for check in checks:
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": check.get('severity', ''),
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": check.get('success', False),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get configauditreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetConfigAuditReport", str(error))
        return None


##############################################################
# ExposedSecretReport Functions
##############################################################

def TrivyGetExposedSecretReports(username_role, user_token, namespace: str = None) -> list:
    """List ExposedSecretReport resources."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "exposedsecretreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "exposedsecretreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "critical": summary.get('criticalCount', 0),
                "high": summary.get('highCount', 0),
                "medium": summary.get('mediumCount', 0),
                "low": summary.get('lowCount', 0),
                "total": summary.get('criticalCount', 0) + summary.get('highCount', 0) + 
                         summary.get('mediumCount', 0) + summary.get('lowCount', 0),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get exposedsecretreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetExposedSecretReports", str(error))
        return report_list


def TrivyGetExposedSecretReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific ExposedSecretReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "exposedsecretreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        secrets = report.get('secrets', [])
        
        # Process secrets
        processed_secrets = []
        for secret in secrets:
            processed_secrets.append({
                "ruleID": secret.get('ruleID', ''),
                "category": secret.get('category', ''),
                "severity": secret.get('severity', ''),
                "title": secret.get('title', ''),
                "match": secret.get('match', ''),
                "target": secret.get('target', ''),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "secrets": processed_secrets,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get exposedsecretreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetExposedSecretReport", str(error))
        return None


##############################################################
# RbacAssessmentReport Functions
##############################################################

def TrivyGetRbacAssessmentReports(username_role, user_token, namespace: str = None) -> list:
    """List RbacAssessmentReport resources."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "rbacassessmentreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "rbacassessmentreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "danger": summary.get('dangerCount', 0),
                "warning": summary.get('warningCount', 0),
                "pass": summary.get('passCount', 0),
                "total": summary.get('dangerCount', 0) + summary.get('warningCount', 0) + summary.get('passCount', 0),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get rbacassessmentreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetRbacAssessmentReports", str(error))
        return report_list


def TrivyGetRbacAssessmentReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific RbacAssessmentReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "rbacassessmentreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        checks = report.get('checks', [])
        
        # Process checks
        processed_checks = []
        for check in checks:
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": check.get('severity', ''),
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": check.get('success', False),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get rbacassessmentreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetRbacAssessmentReport", str(error))
        return None


##############################################################
# SbomReport Functions
##############################################################

def TrivyGetSbomReports(username_role, user_token, namespace: str = None) -> list:
    """List SbomReport resources."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "sbomreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "sbomreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            artifact = report.get('artifact', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            container_name = labels.get('trivy-operator.container.name', 'Unknown')
            
            # Build image reference
            image_ref = ""
            if artifact.get('repository'):
                registry = report.get('registry', {}).get('server', '')
                if registry:
                    image_ref = f"{registry}/{artifact.get('repository', '')}"
                else:
                    image_ref = artifact.get('repository', '')
                if artifact.get('tag'):
                    image_ref += f":{artifact.get('tag', '')}"
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "container_name": container_name,
                "image_ref": image_ref,
                "components_count": summary.get('componentsCount', 0),
                "dependencies_count": summary.get('dependenciesCount', 0),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get sbomreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetSbomReports", str(error))
        return report_list


def TrivyGetSbomReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific SbomReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "sbomreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        components = report.get('components', {})
        artifact = report.get('artifact', {})
        registry = report.get('registry', {})
        scanner = report.get('scanner', {})
        
        # Extract image information
        image_info = {
            "repository": artifact.get('repository', ''),
            "tag": artifact.get('tag', ''),
        }
        
        # Build full image reference
        image_ref = ""
        if image_info["repository"]:
            registry_server = registry.get('server', '') if registry else ''
            if registry_server:
                image_ref = f"{registry_server}/{image_info['repository']}"
            else:
                image_ref = image_info['repository']
            if image_info["tag"]:
                image_ref += f":{image_info['tag']}"
        
        # Process components (CycloneDX format)
        components_list = []
        if components:
            components_data = components.get('components', [])
            for comp in components_data:
                components_list.append({
                    "bom_ref": comp.get('bom-ref', ''),
                    "name": comp.get('name', ''),
                    "version": comp.get('version', ''),
                    "type": comp.get('type', ''),
                    "purl": comp.get('purl', ''),
                    "licenses": comp.get('licenses', []),
                    "supplier": comp.get('supplier', {}),
                    "properties": comp.get('properties', []),
                })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "container_name": labels.get('trivy-operator.container.name', 'Unknown'),
            "image": image_info,
            "image_ref": image_ref,
            "registry": registry,
            "scanner": scanner,
            "summary": summary,
            "components": components_list,
            "components_data": components,  # Full components structure for YAML view
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "update_timestamp": report.get('updateTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get sbomreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetSbomReport", str(error))
        return None


##############################################################
# InfraAssessmentReport Functions (Namespace-scoped)
##############################################################

def TrivyGetInfraAssessmentReports(username_role, user_token, namespace: str = None) -> list:
    """List InfraAssessmentReport resources."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        if namespace and namespace != "all":
            k8s_objects = k8s_client.CustomObjectsApi().list_namespaced_custom_object(
                api_group, api_version, namespace, "infraassessmentreports",
                _request_timeout=5
            )
        else:
            k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                api_group, api_version, "infraassessmentreports",
                _request_timeout=5
            )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            # InfraAssessmentReport uses criticalCount, highCount, mediumCount, lowCount
            critical = summary.get('criticalCount', 0)
            high = summary.get('highCount', 0)
            medium = summary.get('mediumCount', 0)
            low = summary.get('lowCount', 0)
            total = critical + high + medium + low
            
            report_data = {
                "name": metadata.get('name', ''),
                "namespace": metadata.get('namespace', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get infraassessmentreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetInfraAssessmentReports", str(error))
        return report_list


def TrivyGetInfraAssessmentReport(username_role, user_token, namespace: str, name: str) -> Optional[dict]:
    """Get a specific InfraAssessmentReport by namespace and name."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            api_group, api_version, namespace, "infraassessmentreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        checks = report.get('checks', [])
        
        # Process checks
        processed_checks = []
        for check in checks:
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": check.get('severity', ''),
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": check.get('success', False),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": metadata.get('namespace', ''),
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get infraassessmentreport {namespace}/{name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetInfraAssessmentReport", str(error))
        return None


##############################################################
# Cluster-scoped Report Functions
##############################################################

def TrivyGetClusterComplianceReports(username_role, user_token) -> list:
    """List ClusterComplianceReport resources (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            api_group, api_version, "clustercompliancereports",
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            status = obj.get('status', {})
            summary = status.get('summary', {}) or {}
            summaryReport = status.get('summaryReport', {}) or {}
            
            # Try both possible locations for controlChecks
            controlChecks = summaryReport.get('controlCheck', [])  # Note: controlCheck (singular) in summaryReport
            if not controlChecks:
                # Fallback to status.controlChecks if summaryReport.controlCheck doesn't exist
                controlChecks = status.get('controlChecks', [])
            
            # Calculate counts from controlChecks by severity
            critical = 0
            high = 0
            medium = 0
            low = 0
            
            for check in controlChecks:
                severity = check.get('severity', '').upper()
                
                # Handle both structures: summaryReport.controlCheck (with totalFail) and status.controlChecks (with success)
                if 'totalFail' in check:
                    totalFail = check.get('totalFail', 0)
                    if totalFail > 0:  # Only count controls with failures
                        if severity == 'CRITICAL':
                            critical += totalFail
                        elif severity == 'HIGH':
                            high += totalFail
                        elif severity == 'MEDIUM':
                            medium += totalFail
                        elif severity == 'LOW':
                            low += totalFail
                else:
                    # Fallback: count failures from success field
                    success = check.get('success', False)
                    if not success:
                        if severity == 'CRITICAL':
                            critical += 1
                        elif severity == 'HIGH':
                            high += 1
                        elif severity == 'MEDIUM':
                            medium += 1
                        elif severity == 'LOW':
                            low += 1
            
            # Also try to get from summary if available (fallback)
            if summary.get('criticalCount') is not None:
                critical = summary.get('criticalCount', 0)
            if summary.get('highCount') is not None:
                high = summary.get('highCount', 0)
            if summary.get('mediumCount') is not None:
                medium = summary.get('mediumCount', 0)
            if summary.get('lowCount') is not None:
                low = summary.get('lowCount', 0)
            
            total = critical + high + medium + low
            
            report_data = {
                "name": metadata.get('name', ''),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get clustercompliancereports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterComplianceReports", str(error))
        return report_list


def TrivyGetClusterComplianceReport(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific ClusterComplianceReport by name (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            api_group, api_version, "clustercompliancereports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        spec = obj.get('spec', {})
        status = obj.get('status', {})
        summary = status.get('summary', {}) or {}
        summaryReport = status.get('summaryReport', {}) or {}
        
        # Try both possible locations for controlChecks
        controlChecks = summaryReport.get('controlCheck', [])  # Note: controlCheck (singular) in summaryReport
        if not controlChecks:
            # Fallback to status.controlChecks if summaryReport.controlCheck doesn't exist
            controlChecks = status.get('controlChecks', [])
        
        # Process control checks and calculate counts
        processed_checks = []
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for check in controlChecks:
            severity = check.get('severity', '').upper()
            totalFail = check.get('totalFail', 0)
            control_id = check.get('id', '')
            control_name = check.get('name', '')
            
            # Count failures by severity (totalFail represents number of resources that failed)
            if totalFail > 0:
                if severity == 'CRITICAL':
                    critical += totalFail
                elif severity == 'HIGH':
                    high += totalFail
                elif severity == 'MEDIUM':
                    medium += totalFail
                elif severity == 'LOW':
                    low += totalFail
            
            # Process check for display
            # Handle both structures: summaryReport.controlCheck (with totalFail) and status.controlChecks (with success)
            if 'totalFail' in check:
                # summaryReport.controlCheck structure
                processed_checks.append({
                    "id": control_id,
                    "name": control_name,
                    "description": check.get('description', ''),
                    "severity": severity,
                    "totalFail": totalFail,
                    "success": totalFail == 0,  # Success if no failures
                })
            else:
                # status.controlChecks structure (fallback)
                success = check.get('success', False)
                processed_checks.append({
                    "id": control_id,
                    "name": control_name,
                    "description": check.get('description', ''),
                    "severity": severity,
                    "totalFail": 0 if success else 1,  # Count as 1 failure if not successful
                    "success": success,
                })
        
        # Create/update summary with calculated counts
        summary_counts = {
            'criticalCount': critical,
            'highCount': high,
            'mediumCount': medium,
            'lowCount': low,
            'failCount': summary.get('failCount', critical + high + medium + low),
            'passCount': summary.get('passCount', 0),
        }
        # Merge with existing summary
        summary.update(summary_counts)
        
        return {
            "name": metadata.get('name', ''),
            "namespace": None,  # Cluster-scoped
            "spec": spec,
            "summary": summary,
            "controlChecks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": metadata.get('labels', {}),
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get clustercompliancereport {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterComplianceReport", str(error))
        return None


def TrivyGetClusterVulnerabilityReports(username_role, user_token) -> list:
    """List ClusterVulnerabilityReport resources (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            api_group, api_version, "clustervulnerabilityreports",
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            report_data = {
                "name": metadata.get('name', ''),
                "critical": summary.get('criticalCount', 0),
                "high": summary.get('highCount', 0),
                "medium": summary.get('mediumCount', 0),
                "low": summary.get('lowCount', 0),
                "unknown": summary.get('unknownCount', 0),
                "total": summary.get('criticalCount', 0) + summary.get('highCount', 0) + 
                         summary.get('mediumCount', 0) + summary.get('lowCount', 0) + 
                         summary.get('unknownCount', 0),
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get clustervulnerabilityreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterVulnerabilityReports", str(error))
        return report_list


def TrivyGetClusterVulnerabilityReport(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific ClusterVulnerabilityReport by name (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            api_group, api_version, "clustervulnerabilityreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        vulnerabilities = report.get('vulnerabilities', [])
        
        # Process vulnerabilities
        processed_vulns = []
        for vuln in vulnerabilities:
            processed_vulns.append({
                "vulnerabilityID": vuln.get('vulnerabilityID', ''),
                "severity": vuln.get('severity', ''),
                "title": vuln.get('title', ''),
                "description": vuln.get('description', ''),
                "resource": vuln.get('resource', ''),
                "installedVersion": vuln.get('installedVersion', ''),
                "fixedVersion": vuln.get('fixedVersion', ''),
                "publishedDate": vuln.get('publishedDate', ''),
                "lastModifiedDate": vuln.get('lastModifiedDate', ''),
                "score": vuln.get('score', None),
                "primaryLink": vuln.get('primaryLink', ''),
            })
        
        return {
            "name": metadata.get('name', ''),
            "namespace": None,  # Cluster-scoped
            "summary": summary,
            "vulnerabilities": processed_vulns,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": metadata.get('labels', {}),
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get clustervulnerabilityreport {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterVulnerabilityReport", str(error))
        return None


def TrivyGetClusterConfigAuditReports(username_role, user_token) -> list:
    """List ClusterConfigAuditReport resources (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            api_group, api_version, "clusterconfigauditreports",
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            # ClusterConfigAuditReport uses criticalCount, highCount, mediumCount, lowCount
            critical = summary.get('criticalCount', 0)
            high = summary.get('highCount', 0)
            medium = summary.get('mediumCount', 0)
            low = summary.get('lowCount', 0)
            total = critical + high + medium + low
            
            report_data = {
                "name": metadata.get('name', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get clusterconfigauditreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterConfigAuditReports", str(error))
        return report_list


def TrivyGetClusterConfigAuditReport(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific ClusterConfigAuditReport by name (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            api_group, api_version, "clusterconfigauditreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        checks = report.get('checks', [])
        
        # Process checks
        processed_checks = []
        for check in checks:
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": check.get('severity', ''),
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": check.get('success', False),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": None,  # Cluster-scoped
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get clusterconfigauditreport {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterConfigAuditReport", str(error))
        return None


def TrivyGetClusterInfraAssessmentReports(username_role, user_token) -> list:
    """List ClusterInfraAssessmentReport resources (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            api_group, api_version, "clusterinfraassessmentreports",
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            # ClusterInfraAssessmentReport uses criticalCount, highCount, mediumCount, lowCount
            critical = summary.get('criticalCount', 0)
            high = summary.get('highCount', 0)
            medium = summary.get('mediumCount', 0)
            low = summary.get('lowCount', 0)
            total = critical + high + medium + low
            
            report_data = {
                "name": metadata.get('name', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get clusterinfraassessmentreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterInfraAssessmentReports", str(error))
        return report_list


def TrivyGetClusterInfraAssessmentReport(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific ClusterInfraAssessmentReport by name (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            api_group, api_version, "clusterinfraassessmentreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {})
        checks = report.get('checks', [])
        
        # Process checks
        processed_checks = []
        for check in checks:
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": check.get('severity', ''),
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": check.get('success', False),
            })
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": None,  # Cluster-scoped
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get clusterinfraassessmentreport {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterInfraAssessmentReport", str(error))
        return None


def TrivyGetClusterRbacAssessmentReports(username_role, user_token) -> list:
    """List ClusterRbacAssessmentReport resources (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    report_list = []
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return report_list
    
    api_group, api_version = api_info
    
    try:
        k8s_objects = k8s_client.CustomObjectsApi().list_cluster_custom_object(
            api_group, api_version, "clusterrbacassessmentreports",
            _request_timeout=5
        )
        
        for obj in k8s_objects.get('items', []):
            metadata = obj.get('metadata', {})
            report = obj.get('report', {})
            summary = report.get('summary', {})
            checks = report.get('checks', [])
            
            # Get resource info from labels
            labels = metadata.get('labels', {})
            resource_kind = labels.get('trivy-operator.resource.kind', 'Unknown')
            resource_name = labels.get('trivy-operator.resource.name', 'Unknown')
            
            # Initialize counts
            danger = 0
            warning = 0
            pass_count = 0
            
            # Calculate from checks (always calculate, summary might not be populated)
            if checks:
                for check in checks:
                    success = check.get('success', False)
                    severity = check.get('severity', '').upper()
                    
                    if success:
                        pass_count += 1
                    elif severity == 'DANGER':
                        danger += 1
                    elif severity == 'WARNING':
                        warning += 1
                    # Also handle CRITICAL/HIGH/MEDIUM/LOW if present
                    elif severity == 'CRITICAL':
                        danger += 1
                    elif severity == 'HIGH':
                        danger += 1
                    elif severity == 'MEDIUM':
                        warning += 1
                    elif severity == 'LOW':
                        warning += 1
            
            # Use summary counts if they exist and are non-zero (override calculated values)
            if summary.get('dangerCount') is not None and summary.get('dangerCount', 0) > 0:
                danger = summary.get('dangerCount', 0)
            if summary.get('warningCount') is not None and summary.get('warningCount', 0) > 0:
                warning = summary.get('warningCount', 0)
            if summary.get('passCount') is not None and summary.get('passCount', 0) > 0:
                pass_count = summary.get('passCount', 0)
            
            total = danger + warning + pass_count
            
            report_data = {
                "name": metadata.get('name', ''),
                "resource_kind": resource_kind,
                "resource_name": resource_name,
                "danger": danger,
                "warning": warning,
                "pass": pass_count,
                "total": total,
                "age": calculate_age(metadata.get('creationTimestamp', '')),
                "raw": obj
            }
            report_list.append(report_data)
            
        return report_list
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, "get clusterrbacassessmentreports")
        return report_list
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterRbacAssessmentReports", str(error))
        return report_list


def TrivyGetClusterRbacAssessmentReport(username_role, user_token, name: str) -> Optional[dict]:
    """Get a specific ClusterRbacAssessmentReport by name (cluster-scoped)."""
    k8sClientConfigGet(username_role, user_token)
    
    api_info = _get_api_group_version(username_role, user_token)
    if not api_info:
        return None
    
    api_group, api_version = api_info
    
    try:
        obj = k8s_client.CustomObjectsApi().get_cluster_custom_object(
            api_group, api_version, "clusterrbacassessmentreports", name,
            _request_timeout=5
        )
        
        metadata = obj.get('metadata', {})
        report = obj.get('report', {})
        summary = report.get('summary', {}) or {}
        checks = report.get('checks', [])
        
        # Process checks and calculate counts
        processed_checks = []
        danger = 0
        warning = 0
        pass_count = 0
        
        for check in checks:
            success = check.get('success', False)
            severity = check.get('severity', '').upper()
            
            if success:
                pass_count += 1
            elif severity == 'DANGER':
                danger += 1
            elif severity == 'WARNING':
                warning += 1
            # Also handle CRITICAL/HIGH/MEDIUM/LOW if present
            elif severity == 'CRITICAL':
                danger += 1
            elif severity == 'HIGH':
                danger += 1
            elif severity == 'MEDIUM':
                warning += 1
            elif severity == 'LOW':
                warning += 1
            
            processed_checks.append({
                "checkID": check.get('checkID', ''),
                "title": check.get('title', ''),
                "severity": severity,
                "category": check.get('category', ''),
                "description": check.get('description', ''),
                "messages": check.get('messages', []),
                "remediation": check.get('remediation', ''),
                "success": success,
            })
        
        # Update summary with calculated counts
        summary_counts = {
            'dangerCount': danger,
            'warningCount': warning,
            'passCount': pass_count,
        }
        # Merge with existing summary
        summary.update(summary_counts)
        
        # Get resource info from labels
        labels = metadata.get('labels', {})
        
        return {
            "name": metadata.get('name', ''),
            "namespace": None,  # Cluster-scoped
            "resource_kind": labels.get('trivy-operator.resource.kind', 'Unknown'),
            "resource_name": labels.get('trivy-operator.resource.name', 'Unknown'),
            "summary": summary,
            "checks": processed_checks,
            "age": calculate_age(metadata.get('creationTimestamp', '')),
            "creation_timestamp": metadata.get('creationTimestamp', ''),
            "labels": labels,
            "annotations": trimAnnotations(metadata.get('annotations')),
            "raw": obj
        }
        
    except ApiException as error:
        if error.status != 404:
            ErrorHandler(logger, error, f"get clusterrbacassessmentreport {name}")
        return None
    except Exception as error:
        ErrorHandler(logger, "TrivyGetClusterRbacAssessmentReport", str(error))
        return None


##############################################################
# Events Functions
##############################################################

def TrivyGetEvents(
    kind: str,
    name: str,
    namespace: str,
    username_role: str,
    user_token: str,
    uid: str = None,
    limit: int = 50
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Fetch Kubernetes events related to a Trivy Operator report.
    
    Args:
        kind: The report kind (e.g., VulnerabilityReport, ConfigAuditReport)
        name: The name of the report
        namespace: The namespace of the report
        username_role: User role for authorization
        user_token: User token for authentication
        uid: Optional UID of the report for more precise matching
        limit: Maximum number of events to return
        
    Returns:
        Tuple of (events_list, error_message)
    """
    k8sClientConfigGet(username_role, user_token)
    core_api = k8s_client.CoreV1Api()
    
    try:
        # Field selector to filter events by involved object
        if uid:
            field_selector = f"involvedObject.uid={uid}"
        else:
            field_selector = f"involvedObject.name={name},involvedObject.kind={kind}"
        
        # For cluster-scoped resources, list events from all namespaces
        if not namespace:
            # List events from all namespaces for cluster-scoped resources
            events = core_api.list_event_for_all_namespaces(
                field_selector=field_selector,
                limit=limit,
                _request_timeout=5
            )
        else:
            events = core_api.list_namespaced_event(
                namespace=namespace,
                field_selector=field_selector,
                limit=limit,
                _request_timeout=5
            )
        
        # Convert to list of dicts and sort by last timestamp (newest first)
        event_list = []
        for event in events.items:
            if event.involved_object.name == name and event.involved_object.kind == kind:
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
        return [], None
    except Exception as error:
        ErrorHandler(logger, error, f"get events for {kind} {name}")
        return [], None
