#!/usr/bin/env python3
"""
MCP Integration plugin for KubeDash.

Provides an in-app AI chatbot backed by MCP (Model Context Protocol) servers
(e.g. Kubernetes MCP server) for natural-language cluster queries and actions.
See docs/prd/mcp-integration.md for requirements.
"""

import json
from flask import Blueprint, render_template
from flask_login import login_required
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

from lib.helper_functions import get_logger

##############################################################
## Variables
##############################################################

mcp_integration_bp = Blueprint(
    "mcp_integration",
    __name__,
    url_prefix="/plugins",
    template_folder="templates",
)
logger = get_logger()

# Built from cluster discovery at first use (see get_resource_list_map).
RESOURCE_LIST_MAP = None

# Static fallback when cluster discovery is unavailable (e.g. no kubeconfig at import).
_RESOURCE_LIST_MAP_FALLBACK = {
    "pods": ("v1", "Pod"),
    "pod": ("v1", "Pod"),
    "services": ("v1", "Service"),
    "service": ("v1", "Service"),
    "deployments": ("apps/v1", "Deployment"),
    "deployment": ("apps/v1", "Deployment"),
    "statefulsets": ("apps/v1", "StatefulSet"),
    "statefulset": ("apps/v1", "StatefulSet"),
    "daemonsets": ("apps/v1", "DaemonSet"),
    "daemonset": ("apps/v1", "DaemonSet"),
    "replicasets": ("apps/v1", "ReplicaSet"),
    "replicaset": ("apps/v1", "ReplicaSet"),
    "ingresses": ("networking.k8s.io/v1", "Ingress"),
    "ingress": ("networking.k8s.io/v1", "Ingress"),
    "configmaps": ("v1", "ConfigMap"),
    "configmap": ("v1", "ConfigMap"),
    "secrets": ("v1", "Secret"),
    "secret": ("v1", "Secret"),
    "persistentvolumeclaims": ("v1", "PersistentVolumeClaim"),
    "pvc": ("v1", "PersistentVolumeClaim"),
    "pvcs": ("v1", "PersistentVolumeClaim"),
    "jobs": ("batch/v1", "Job"),
    "job": ("batch/v1", "Job"),
    "cronjobs": ("batch/v1", "CronJob"),
    "cronjob": ("batch/v1", "CronJob"),
    "events": ("v1", "Event"),
    "event": ("v1", "Event"),
}


def _build_resource_list_map():
    """Populate RESOURCE_LIST_MAP from Kubernetes API discovery. Uses Admin kubeconfig."""
    global RESOURCE_LIST_MAP
    if RESOURCE_LIST_MAP is not None:
        return RESOURCE_LIST_MAP
    logger = get_logger()
    out = {}
    try:
        from lib.k8s.server import k8sClientConfigGet
        k8sClientConfigGet("Admin", None)
        api_client = k8s_client.ApiClient()
        # Core API: /api/v1
        try:
            body = api_client.call_api("/api/v1", "GET", response_type="object", _request_timeout=10)[0]
            for r in body.get("resources") or []:
                name = r.get("name")
                kind = r.get("kind")
                if not name or not kind or "/" in name:
                    continue
                api_version = "v1"
                out[name] = (api_version, kind)
                singular = (r.get("singularName") or "").strip()
                if singular and singular != name:
                    out[singular] = (api_version, kind)
        except ApiException as e:
            if e.status != 404:
                logger.debug("MCP plugin: core API discovery failed: %s", e.reason)
        # Named groups: /apis/<group>/<version>
        apis = k8s_client.ApisApi(api_client)
        for group in apis.get_api_versions().groups or []:
            group_name = group.name
            for ver in group.versions or []:
                version = getattr(ver, "version", None)
                if not version:
                    continue
                gv = f"{group_name}/{version}"
                try:
                    body = api_client.call_api(f"/apis/{gv}", "GET", response_type="object", _request_timeout=10)[0]
                    for r in body.get("resources") or []:
                        name = r.get("name")
                        kind = r.get("kind")
                        if not name or not kind or "/" in name:
                            continue
                        # Prefer core: do not overwrite existing keys (e.g. core "pods" -> Pod over metrics "pods" -> PodMetrics)
                        if name not in out:
                            out[name] = (gv, kind)
                        singular = (r.get("singularName") or "").strip()
                        if singular and singular != name and singular not in out:
                            out[singular] = (gv, kind)
                        # Add kind as lowercase key so "list podmetrics" works (metrics.k8s.io PodMetrics)
                        kind_key = kind.lower()
                        if kind_key not in out:
                            out[kind_key] = (gv, kind)
                except ApiException as e:
                    if e.status != 404:
                        logger.debug("MCP plugin: discovery failed for %s: %s", gv, e.reason)
        if out:
            RESOURCE_LIST_MAP = out
            logger.info("MCP plugin: built RESOURCE_LIST_MAP from cluster (%s entries)", len(out))
        else:
            RESOURCE_LIST_MAP = _RESOURCE_LIST_MAP_FALLBACK
            logger.debug("MCP plugin: using fallback RESOURCE_LIST_MAP (no resources from discovery)")
    except Exception as e:
        logger.debug("MCP plugin: could not build RESOURCE_LIST_MAP from cluster: %s", e)
        RESOURCE_LIST_MAP = _RESOURCE_LIST_MAP_FALLBACK
    return RESOURCE_LIST_MAP


def get_resource_list_map():
    """Return RESOURCE_LIST_MAP, building from cluster discovery on first call."""
    if RESOURCE_LIST_MAP is None:
        _build_resource_list_map()   
    return RESOURCE_LIST_MAP or _RESOURCE_LIST_MAP_FALLBACK



##############################################################
## Routes
##############################################################


@mcp_integration_bp.route("/mcp-chat", methods=["GET"])
@login_required
def chat():
    """
    MCP Chat main page: in-app chatbot UI with message thread and input.
    """
    logger.debug("MCP plugin: serving mcp-chat page")
    return render_template("mcp-chat.html.j2")


# Build RESOURCE_LIST_MAP from cluster at plugin load (best-effort; fallback used if discovery fails)
try:
    _build_resource_list_map()
except Exception:
    pass
