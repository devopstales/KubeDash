"""
MCP Integration plugin API: chat message endpoint.

Registered under /api/v1/plugins/mcp-integration/ (see initialize_plugin_apis).
"""

import re
from contextlib import nullcontext

from flask import current_app, jsonify, request
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint

from lib.components import db
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

from plugins.mcp_integration import get_resource_list_map
from plugins.mcp_integration.helm_operations import install as helm_install_release
from plugins.mcp_integration.helm_operations import list_releases as helm_list_releases
from plugins.mcp_integration.helm_operations import uninstall as helm_uninstall_release
from plugins.mcp_integration.k8s_operations import (
    create_namespace as k8s_create_namespace,
    create_resource as k8s_create_resource,
    delete_resource as k8s_delete_resource,
    get_pod_logs as k8s_get_pod_logs,
    get_resource as k8s_get_resource,
    list_namespaces as k8s_list_namespaces,
    list_pods as k8s_list_pods,
    list_resource as k8s_list_resource,
    update_resource as k8s_update_resource,
)
from plugins.mcp_integration.mcp_client import parse_intent
from plugins.mcp_integration.models import McpConversation, McpMessage
from plugins.mcp_integration.resource_yaml import extract_configmap_mount

##############################################################
## Blueprint
##############################################################

mcp_integration_api_bp = Blueprint(
    "mcp_integration_api",
    "mcp_integration_api",
    url_prefix="/mcp-integration",
    description="MCP Integration - Chat API for AI-backed cluster queries",
)
logger = get_logger()
tracer = get_tracer()


def _validate_namespace_access(user, namespace: str) -> bool:
    """
    Check if user has RBAC permission for namespace before MCP tool calls.

    Option A: Use Kubernetes SubjectAccessReview (via lib/extension_api/authorization).
    Option B: Check against allowed_namespaces from user config/claims.
    Option C: Delegate to your existing authz layer.

    Returns True if access is allowed or if authz cannot be determined (fail-open placeholder).
    """
    if not namespace or not namespace.strip():
        return True
    try:
        from lib.extension_api.authentication import AuthenticatedUser
        from lib.extension_api.authorization import check_namespace_access
        username = getattr(user, "username", None) or getattr(user, "name", None)
        if not username and hasattr(user, "id"):
            username = str(user.id)
        if not username:
            username = "unknown"
        groups = getattr(user, "groups", None) or []
        auth_user = AuthenticatedUser(username=username, groups=list(groups))
        return check_namespace_access(
            auth_user, namespace.strip(), verb="list", resource="pods", api_group=""
        )
    except ImportError:
        logger.debug("MCP namespace validation: extension_api not available, allowing access")
        return True
    except Exception as e:
        logger.warning("MCP namespace validation failed for %s: %s", namespace, e)
        return False


# Intent types that only read data (list, describe, logs). Write intents (create, delete, apply, etc.) must not be in this set.
READ_ONLY_INTENT_TYPES = frozenset({
    "list_namespaces", "pods", "describe_pod", "pod_logs", "helm_releases", "list_resource",
})


def _get_mcp_config():
    """Read [mcp_integration] from kubedash.ini. Returns dict with mcp_server_url, read_only, helm_list_tool."""
    try:
        ini = current_app.config.get("kubedash.ini")
        if not ini or "mcp_integration" not in ini:
            return {"mcp_server_url": "", "read_only": False, "helm_list_tool": "helm_list"}
        section = ini["mcp_integration"]
        url = (section.get("mcp_server_url") or "").strip()
        read_only = section.getboolean("read_only", fallback=False)
        helm_list_tool = (section.get("helm_list_tool") or "helm_list").strip() or "helm_list"
        return {"mcp_server_url": url, "read_only": read_only, "helm_list_tool": helm_list_tool}
    except Exception:
        return {"mcp_server_url": "", "read_only": False, "helm_list_tool": "helm_list"}


def _get_or_create_conversation(user_id: int, conversation_id_str: str | None):
    """Return existing conversation if valid and owned by user, else create and return a new one."""
    if conversation_id_str:
        try:
            cid = int(conversation_id_str)
            conv = McpConversation.query.filter_by(id=cid, user_id=user_id).first()
            if conv:
                return conv
        except (TypeError, ValueError):
            pass
    conv = McpConversation(user_id=user_id)
    db.session.add(conv)
    db.session.commit()
    return conv


def _save_message(conversation_id: int, role: str, content: str):
    """Append a message to a conversation and bump updated_at."""
    from datetime import datetime, timezone
    msg = McpMessage(conversation_id=conversation_id, role=role, content=content)
    db.session.add(msg)
    conv = McpConversation.query.get(conversation_id)
    if conv:
        conv.updated_at = datetime.now(timezone.utc)
    db.session.commit()


def _chat_response(conversation, reply: str):
    """Persist assistant message and return JSON response with conversation_id and message."""
    reply_str = reply if isinstance(reply, str) else str(reply)
    _save_message(conversation.id, "assistant", reply_str)
    return jsonify({
        "conversation_id": str(conversation.id),
        "message": {"role": "assistant", "content": reply_str},
    })


def _parse_kubectl_table(raw: str):
    """
    Parse kubectl-style table (tab- or multi-space-separated). Returns (headers, rows) or (None, None).
    """
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines or "NAME" not in lines[0]:
        return None, None
    if "\t" in lines[0]:
        split = lambda s: [c.strip() for c in s.split("\t")]
    else:
        split = lambda s: re.split(r"\s{2,}", s)
    headers = split(lines[0])
    if not headers:
        return None, None
    rows = []
    for ln in lines[1:]:
        cells = split(ln)
        if len(cells) >= len(headers):
            rows.append(cells[: len(headers)])
        elif len(cells) >= 4:
            rows.append(cells + [""] * (len(headers) - len(cells)))
    return headers, rows


def _parse_helm_list_yaml(raw: str) -> list[dict] | None:
    """
    Parse Helm list output from containers/kubernetes-mcp-server (YAML list of release objects).
    Returns list of dicts with keys like name, namespace, chart, chartVersion, status, revision; or None.
    """
    if not raw or not raw.strip():
        return None
    import yaml
    try:
        data = yaml.safe_load(raw)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data
        if isinstance(data, dict) and "name" in data:
            return [data]
        return None
    except Exception:
        # Line-oriented parse: blocks starting with "- " then indented key: value (Helm YAML list)
        blocks = []
        current = {}
        for line in raw.splitlines():
            line = line.rstrip()
            if line.startswith("- "):
                if current:
                    blocks.append(current)
                current = {}
                rest = line[2:].strip()
                if ":" in rest:
                    k, _, v = rest.partition(":")
                    current[k.strip().lower().replace(" ", "_")] = v.strip()
            elif ":" in line and current is not None:
                stripped = line.strip()
                if stripped:
                    k, _, v = stripped.partition(":")
                    key = k.strip().lower().replace(" ", "_")
                    current[key] = v.strip() if v else ""
        if current:
            blocks.append(current)
        return blocks if blocks else None
    return None


def _format_helm_releases_reply(title: str, raw: str) -> str:
    """Format Helm list YAML output as a markdown table. Falls back to raw if not parseable."""
    rows = _parse_helm_list_yaml(raw)
    if not rows:
        if not raw or not raw.strip():
            return "**{}**: no releases.".format(title)
        return "**{}**:\n\n{}".format(title, raw.strip())
    headers = ["NAME", "NAMESPACE", "CHART", "CHART VERSION", "STATUS", "REVISION"]
    # Map display header -> possible YAML keys (containers/kubernetes-mcp-server uses camelCase)
    key_aliases = {
        "NAME": ["name"],
        "NAMESPACE": ["namespace"],
        "CHART": ["chart"],
        "CHART VERSION": ["chartVersion", "chartversion", "chart_version"],
        "STATUS": ["status"],
        "REVISION": ["revision"],
    }

    def get_cell(row: dict, h: str) -> str:
        for key in key_aliases.get(h, [h.lower().replace(" ", "_")]):
            if key in row and row[key] is not None:
                return str(row[key])
        for k, v in row.items():
            if k.lower().replace("-", "").replace(" ", "") == h.lower().replace("-", "").replace(" ", ""):
                return str(v) if v is not None else ""
        return ""
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "|" + "|".join("---" for _ in headers) + "|"
    body_lines = ["| " + " | ".join(get_cell(r, h) for h in headers) + " |" for r in rows]
    table = "\n".join([header_line, sep_line] + body_lines)
    return "**{}** ({}):\n\n{}".format(title, len(rows), table)


def _fetch_podmetrics_with_usage(namespace: str) -> list[dict] | None:
    """
    Fetch PodMetrics for a namespace from the metrics.k8s.io API with CPU, MEMORY, WINDOW.
    Returns list of {"name": str, "cpu": str, "memory": str, "window": str} or None on error.
    """
    try:
        from lib.k8s.server import k8sClientConfigGet
        from kubernetes import client as k8s_client
        from lib.helper_functions import parse_quantity

        k8sClientConfigGet("Admin", None)
        api = k8s_client.CustomObjectsApi()
        resp = api.list_cluster_custom_object(
            "metrics.k8s.io", "v1beta1", "pods",
            _request_timeout=10,
        )
        items = resp.get("items") or []
        # Aggregate per pod (sum CPU and memory across containers), filter by namespace
        pod_agg = {}
        for item in items:
            meta = item.get("metadata") or {}
            ns = meta.get("namespace") or ""
            if ns != namespace:
                continue
            name = meta.get("name") or ""
            window = (item.get("window") or "—").strip()
            if name not in pod_agg:
                pod_agg[name] = {"name": name, "cpu_n": 0, "memory_bytes": 0, "window": window}
            for cont in item.get("containers") or []:
                usage = cont.get("usage") or {}
                try:
                    cpu_q = usage.get("cpu") or "0"
                    pod_agg[name]["cpu_n"] += float(parse_quantity(cpu_q))
                except (ValueError, TypeError):
                    pass
                try:
                    mem_q = usage.get("memory") or "0"
                    pod_agg[name]["memory_bytes"] += float(parse_quantity(mem_q))
                except (ValueError, TypeError):
                    pass
        # parse_quantity returns CPU in cores (e.g. 386216n -> 0.000386216), memory in bytes (e.g. 14848Ki -> bytes)
        # Display: CPU as nanocores (int)n, memory as Ki
        out = []
        for name, agg in sorted(pod_agg.items()):
            cpu_cores = agg["cpu_n"]
            cpu_nanocores = int(round(cpu_cores * 1e9)) if cpu_cores else 0
            mem_bytes = agg["memory_bytes"]
            mem_ki = int(round(mem_bytes / 1024)) if mem_bytes else 0
            out.append({
                "name": name,
                "cpu": "{}n".format(cpu_nanocores),
                "memory": "{}Ki".format(mem_ki),
                "window": agg["window"],
            })
        return out
    except Exception as e:
        logger.debug("PodMetrics fetch for namespace %s failed: %s", namespace, e)
        return None


def _format_podmetrics_reply(title: str, rows: list[dict]) -> str:
    """Format PodMetrics rows (name, cpu, memory, window) as a markdown table."""
    if not rows:
        return "**{}**: no data.".format(title)
    header = "| NAME | CPU | MEMORY | WINDOW |"
    sep = "| --- | --- | --- | --- |"
    body = ["| {} | {} | {} | {} |".format(
        r.get("name", ""),
        r.get("cpu", "—"),
        r.get("memory", "—"),
        r.get("window", "—"),
    ) for r in rows]
    return "**{}** ({}):\n\n{}\n{}\n{}".format(title, len(rows), header, sep, "\n".join(body))


def _format_pod_log_output(raw: str, tail_lines: int = 15) -> str:
    """
    Format pod log text: collapse consecutive duplicate lines and show a repeat count,
    then return only the last tail_lines lines (default 15).
    """
    if not raw or not raw.strip():
        return raw or ""
    lines = raw.strip().splitlines()
    if not lines:
        return raw.strip()
    out = []
    prev = None
    count = 0
    for line in lines:
        if line == prev:
            count += 1
            continue
        if prev is not None:
            out.append(prev)
            if count > 1:
                out.append("... (repeated {} more times)".format(count - 1))
        prev = line
        count = 1
    if prev is not None:
        out.append(prev)
        if count > 1:
            out.append("... (repeated {} more times)".format(count - 1))
    if len(out) > tail_lines:
        out = ["(last {} lines)".format(tail_lines), ""] + out[-tail_lines:]
    return "\n".join(out)


def _format_table_reply(title: str, raw: str) -> str:
    """Format kubectl-style table output with a title. Uses markdown table if parseable."""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return "**{}**: no data.".format(title)

    headers, rows = _parse_kubectl_table(raw)
    if headers and rows:
        col_names = [c for c in ("NAMESPACE", "NAME", "STATUS", "AGE") if c in headers][:6]
        if not col_names:
            col_names = headers[:6]
        indices = []
        for c in col_names:
            for i, h in enumerate(headers):
                if h == c:
                    indices.append((i, c))
                    break
        if indices:
            header_line = "| " + " | ".join(c for _, c in indices) + " |"
            sep_line = "|" + "|".join("---" for _ in indices) + "|"
            body_lines = ["| " + " | ".join(row[i].strip() if i < len(row) else "" for i, _ in indices) + " |" for row in rows]
            table = "\n".join([header_line, sep_line] + body_lines)
            return "**{}** ({}):\n\n{}".format(title, len(rows), table)
    normalized = "\n".join(ln.replace("\t", "  ") for ln in lines)
    return "**{}**:\n\n{}".format(title, normalized)


def _format_pods_reply(namespace: str, raw: str, user_asked_count: bool) -> str:
    """Turn MCP pods_list_in_namespace output into a short answer with readable formatting."""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return "There are **0 pods** in namespace `{}`.".format(namespace)

    headers, rows = _parse_kubectl_table(raw)
    if headers and rows:
        # Build a compact table: only NAME, READY, STATUS, AGE (and NAMESPACE if present)
        col_names = ["NAME", "READY", "STATUS", "AGE"]
        if "NAMESPACE" in headers:
            col_names.insert(0, "NAMESPACE")
        indices = []
        for c in col_names:
            for i, h in enumerate(headers):
                if h == c:
                    indices.append((i, c))
                    break
        if indices:
            header_line = "| " + " | ".join(c for _, c in indices) + " |"
            sep_line = "|" + "|".join("---" for _ in indices) + "|"
            body_lines = []
            for row in rows:
                cells = [row[i].strip() if i < len(row) else "" for i, _ in indices]
                body_lines.append("| " + " | ".join(cells) + " |")
            table = "\n".join([header_line, sep_line] + body_lines)
            if user_asked_count:
                return "There are **{}** pod(s) in namespace `{}`.\n\n{}".format(
                    len(rows), namespace, table
                )
            return "Pods in namespace `{}`:\n\n{}".format(namespace, table)

    # Fallback: preserve raw with normalized whitespace (tabs -> spaces) for alignment
    normalized = "\n".join(ln.replace("\t", "  ") for ln in lines)
    if user_asked_count:
        data_count = len(lines) - 1 if (lines and "NAME" in lines[0] and "READY" in lines[0]) else len(lines)
        return "There are **{}** pod(s) in namespace `{}`.\n\n{}".format(
            max(0, data_count), namespace, normalized
        )
    return "Pods in namespace `{}`:\n\n{}".format(namespace, normalized)


##############################################################
## Chat message: MCP tool calls for supported intents
##############################################################


def _chat_message_impl():
    """Implementation of chat message handling. Returns (response_body, status_code) or (Response, None)."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        content = (data.get("content") or "").strip()
        if not content:
            return jsonify({"error": "BadRequest", "message": "content is required"}), 400

        conversation = _get_or_create_conversation(current_user.id, (data.get("conversation_id") or "").strip())
        _save_message(conversation.id, "user", content)

        config = _get_mcp_config()
        mcp_url = config.get("mcp_server_url") or ""
        read_only = config.get("read_only", False)
        logger.debug("MCP chat config: mcp_server_url=%r, read_only=%s", mcp_url or "(empty)", read_only)

        # Single intent parse: returns {"type": "...", ...} or None
        intent = parse_intent(content)
        if intent and read_only and intent.get("type") not in READ_ONLY_INTENT_TYPES:
            reply = (
                "Write operations are disabled. This MCP integration is configured in **read-only** mode "
                "(`read_only = true` in `[mcp_integration]` in kubedash.ini). Only list, describe, and logs queries are allowed."
            )
            return _chat_response(conversation, reply)
        # Derive legacy-style vars for branching
        namespace = intent.get("namespace") if intent and intent.get("type") == "pods" else None
        list_namespaces = intent is not None and intent.get("type") == "list_namespaces"
        res_api = intent.get("api_version") if intent and intent.get("type") == "list_resource" else None
        res_kind = intent.get("kind") if intent and intent.get("type") == "list_resource" else None
        res_namespace = intent.get("namespace") if intent and intent.get("type") == "list_resource" else None
        helm_releases = intent is not None and intent.get("type") == "helm_releases"
        helm_all_ns = intent.get("all_namespaces", True) if intent and intent.get("type") == "helm_releases" else True
        helm_namespace = intent.get("namespace") if intent and intent.get("type") == "helm_releases" else None
        pod_logs = intent is not None and intent.get("type") == "pod_logs"
        log_pod_name = intent.get("pod_name") if intent and pod_logs else None
        log_namespace = intent.get("namespace") if intent and pod_logs else None
        describe_pod = intent is not None and intent.get("type") == "describe_pod"
        describe_pod_name = intent.get("pod_name") if intent and describe_pod else None
        describe_namespace = intent.get("namespace") if intent and describe_pod else None
        delete_resource = intent is not None and intent.get("type") == "delete_resource"
        delete_res_name = intent.get("name") if intent and delete_resource else None
        delete_res_kind = intent.get("resource") if intent and delete_resource else None
        delete_res_namespace = intent.get("namespace") if intent and delete_resource else None
        create_resource = intent is not None and intent.get("type") == "create_resource"
        create_ns_name = intent.get("create_namespace") if intent and create_resource else None
        create_res_kind = intent.get("resource") if intent and create_resource else None
        create_res_name = intent.get("name") if intent and create_resource else None
        create_res_namespace = intent.get("namespace") if intent and create_resource else None
        helm_install = intent is not None and intent.get("type") == "helm_install"
        helm_install_chart = intent.get("chart") if intent and helm_install else None
        helm_install_release = intent.get("release") if intent and helm_install else None
        helm_install_namespace = intent.get("namespace") if intent and helm_install else None
        helm_uninstall = intent is not None and intent.get("type") == "helm_uninstall"
        helm_uninstall_release = intent.get("release") if intent and helm_uninstall else None
        helm_uninstall_namespace = intent.get("namespace") if intent and helm_uninstall else None
        update_resource = intent is not None and intent.get("type") == "update_resource"
        update_res_name = intent.get("name") if intent and update_resource else None
        update_res_kind = intent.get("resource") if intent and update_resource else None
        update_res_namespace = intent.get("namespace") if intent and update_resource else None

        logger.info(
            "MCP chat: content=%r, mcp_url=%r, intent=%s",
            content[:80], mcp_url or "(empty)", intent.get("type") if intent else None,
        )

        span_attrs = {
            "http.route": "/api/v1/plugins/mcp-integration/chat/message",
            "http.method": "POST",
            "mcp.intent_matched": intent is not None,
        }
        if intent:
            span_attrs["mcp.intent_type"] = intent.get("type", "")
        if namespace:
            span_attrs["mcp.namespace"] = namespace
        if list_namespaces:
            span_attrs["mcp.intent_list_namespaces"] = True
        if res_kind:
            span_attrs["mcp.intent_list_resource"] = res_kind
        if helm_releases:
            span_attrs["mcp.intent_helm_releases"] = True
        if mcp_url:
            span_attrs["mcp.server_configured"] = True

        with tracer.start_as_current_span(
            "mcp-chat-message",
            attributes=span_attrs,
        ) if tracer else nullcontext():
            # Namespace validation before any namespace-scoped MCP call
            if helm_namespace and not _validate_namespace_access(current_user, helm_namespace):
                logger.warning("User %s denied access to namespace %s (helm releases)", current_user, helm_namespace)
                return jsonify({
                    "error": "Forbidden",
                    "message": "No access to namespace {}".format(helm_namespace),
                }), 403
            if res_namespace and not _validate_namespace_access(current_user, res_namespace):
                logger.warning("User %s denied access to namespace %s (list resource)", current_user, res_namespace)
                return jsonify({
                    "error": "Forbidden",
                    "message": "No access to namespace {}".format(res_namespace),
                }), 403
            if namespace and not _validate_namespace_access(current_user, namespace):
                logger.warning("User %s denied access to namespace %s (pods)", current_user, namespace)
                return jsonify({
                    "error": "Forbidden",
                    "message": "No access to namespace {}".format(namespace),
                }), 403
            if log_namespace and not _validate_namespace_access(current_user, log_namespace):
                logger.warning("User %s denied access to namespace %s (pod logs)", current_user, log_namespace)
                return jsonify({
                    "error": "Forbidden",
                    "message": "No access to namespace {}".format(log_namespace),
                }), 403
            if describe_namespace and not _validate_namespace_access(current_user, describe_namespace):
                logger.warning("User %s denied access to namespace %s (describe pod)", current_user, describe_namespace)
                return jsonify({
                    "error": "Forbidden",
                    "message": "No access to namespace {}".format(describe_namespace),
                }), 403
            if delete_resource and delete_res_namespace and not _validate_namespace_access(current_user, delete_res_namespace):
                logger.warning("User %s denied access to namespace %s (delete resource)", current_user, delete_res_namespace)
                return jsonify({"error": "Forbidden", "message": "No access to namespace {}".format(delete_res_namespace)}), 403
            if create_resource and create_res_namespace and not _validate_namespace_access(current_user, create_res_namespace):
                logger.warning("User %s denied access to namespace %s (create resource)", current_user, create_res_namespace)
                return jsonify({"error": "Forbidden", "message": "No access to namespace {}".format(create_res_namespace)}), 403
            if helm_install and helm_install_namespace and not _validate_namespace_access(current_user, helm_install_namespace):
                logger.warning("User %s denied access to namespace %s (helm install)", current_user, helm_install_namespace)
                return jsonify({"error": "Forbidden", "message": "No access to namespace {}".format(helm_install_namespace)}), 403
            if helm_uninstall and helm_uninstall_namespace and not _validate_namespace_access(current_user, helm_uninstall_namespace):
                logger.warning("User %s denied access to namespace %s (helm uninstall)", current_user, helm_uninstall_namespace)
                return jsonify({"error": "Forbidden", "message": "No access to namespace {}".format(helm_uninstall_namespace)}), 403
            if update_resource and update_res_namespace and not _validate_namespace_access(current_user, update_res_namespace):
                logger.warning("User %s denied access to namespace %s (update resource)", current_user, update_res_namespace)
                return jsonify({"error": "Forbidden", "message": "No access to namespace {}".format(update_res_namespace)}), 403

            if mcp_url and describe_pod and describe_pod_name:
                ns = describe_namespace or "default"
                try:
                    raw = k8s_get_resource(mcp_url, ns, "Pod", describe_pod_name)
                    title = "Describe pod `{}` in namespace `{}`".format(describe_pod_name, ns)
                    reply = "**{}**\n\n```\n{}\n```".format(title, (raw or "(no output)").strip())
                    if not describe_namespace:
                        reply += "\n\n(Assuming namespace `default`. Specify e.g. *describe &lt;pod&gt; in &lt;namespace&gt; namespace* for another.)"
                    logger.info("MCP chat: get_resource (pod) pod=%s ns=%s", describe_pod_name, ns)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            # Delete resource
            if mcp_url and delete_resource and delete_res_name and delete_res_kind:
                ns = delete_res_namespace or "default"
                resource_map = get_resource_list_map()
                res_key = delete_res_kind.lower()
                if res_key not in resource_map and delete_res_name.lower() in resource_map:
                    delete_res_name, delete_res_kind = delete_res_kind, delete_res_name
                    res_key = delete_res_kind.lower()
                if res_key not in resource_map:
                    reply = "Unknown resource type **{}**. Use a valid kind (e.g. pod, deployment, namespace).".format(delete_res_kind)
                    return _chat_response(conversation, reply)
                api_version, kind = resource_map[res_key]
                try:
                    raw = k8s_delete_resource(mcp_url, api_version, kind, delete_res_name, ns)
                    reply = "**Deleted** {} `{}` in namespace `{}`.\n\n{}".format(kind, delete_res_name, ns, (raw or "Done.").strip())
                    logger.info("MCP chat: delete kind=%s name=%s", kind, delete_res_name)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            # Create resource: namespace only or <kind> <name> in namespace
            if mcp_url and create_resource:
                if create_ns_name:
                    try:
                        raw = k8s_create_namespace(mcp_url, create_ns_name)
                        reply = "**Created namespace** `{}`.\n\n{}".format(create_ns_name, (raw or "Done.").strip())
                        logger.info("MCP chat: create namespace name=%s", create_ns_name)
                        return _chat_response(conversation, reply)
                    except RuntimeError as e:
                        reply = "The MCP server returned an error: **{}**".format(str(e))
                        return _chat_response(conversation, reply)
                if create_res_kind and create_res_name and create_res_namespace:
                    resource_map = get_resource_list_map()
                    res_key = create_res_kind.lower()
                    if res_key not in resource_map and create_res_name.lower() in resource_map:
                        create_res_name, create_res_kind = create_res_kind, create_res_name
                        res_key = create_res_kind.lower()
                    if res_key not in resource_map:
                        reply = "Unknown resource type **{}**. Use a valid kind (e.g. deployment, configmap, pod, service, secret).".format(create_res_kind)
                        return _chat_response(conversation, reply)
                    api_version, kind = resource_map[res_key]
                    try:
                        raw = k8s_create_resource(
                            mcp_url, api_version, kind, create_res_name, create_res_namespace, content=content
                        )
                        raw_str = (raw or "Done.").strip() if isinstance(raw, str) else str(raw)
                        reply = "**Created** {} `{}` in namespace `{}`.\n\n```yaml\n{}\n```".format(
                            kind, create_res_name, create_res_namespace, raw_str
                        )
                        logger.info("MCP chat: create kind=%s name=%s", kind, create_res_name)
                        return _chat_response(conversation, reply)
                    except RuntimeError as e:
                        reply = "The MCP server returned an error: **{}**".format(str(e))
                        return _chat_response(conversation, reply)
            # Helm install
            if mcp_url and helm_install and helm_install_chart:
                ns = helm_install_namespace or "default"
                try:
                    raw = helm_install_release(mcp_url, helm_install_chart, namespace=ns, release_name=helm_install_release)
                    reply = "**Helm install** chart `{}` in namespace `{}`.\n\n{}".format(helm_install_chart, ns, (raw or "Done.").strip())
                    if helm_install_release:
                        reply = "**Helm install** release `{}` (chart `{}`) in namespace `{}`.\n\n{}".format(helm_install_release, helm_install_chart, ns, (raw or "Done.").strip())
                    logger.info("MCP chat: helm install chart=%s", helm_install_chart)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            # Helm uninstall
            if mcp_url and helm_uninstall and helm_uninstall_release:
                ns = helm_uninstall_namespace or "default"
                try:
                    raw = helm_uninstall_release(mcp_url, helm_uninstall_release, namespace=ns)
                    reply = "**Helm uninstall** release `{}` from namespace `{}`.\n\n{}".format(helm_uninstall_release, ns, (raw or "Done.").strip())
                    logger.info("MCP chat: helm uninstall release=%s", helm_uninstall_release)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            # Update resource
            if mcp_url and update_resource and update_res_name and update_res_kind:
                ns = update_res_namespace or "default"
                resource_map = get_resource_list_map()
                res_key = update_res_kind.lower()
                if res_key not in resource_map and update_res_name.lower() in resource_map:
                    update_res_name, update_res_kind = update_res_kind, update_res_name
                    res_key = update_res_kind.lower()
                if res_key not in resource_map:
                    reply = "Unknown resource type **{}**. Use a valid kind (e.g. deployment, pod, configmap).".format(update_res_kind)
                    return _chat_response(conversation, reply)
                api_version, kind = resource_map[res_key]
                try:
                    raw = k8s_update_resource(mcp_url, api_version, kind, update_res_name, ns, content=content)
                    raw_str = (raw or "Done.").strip() if isinstance(raw, str) else str(raw)
                    mount_info = extract_configmap_mount(content) if kind == "Deployment" else None
                    if kind == "Deployment" and mount_info:
                        reply = "**Updated Deployment** `{}` in namespace `{}` with ConfigMap `{}` mounted at `{}`.\n\n```yaml\n{}\n```".format(
                            update_res_name, ns, mount_info[0], mount_info[1], raw_str
                        )
                    else:
                        reply = "**Updated** {} `{}` in namespace `{}`.\n\n```yaml\n{}\n```".format(
                            kind, update_res_name, ns, raw_str
                        )
                    logger.info("MCP chat: update kind=%s name=%s", kind, update_res_name)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            if mcp_url and pod_logs and log_pod_name:
                ns = log_namespace or "default"
                try:
                    raw = k8s_get_pod_logs(mcp_url, ns, log_pod_name)
                    raw_str = (raw if raw is not None else "(no output)")
                    if not isinstance(raw_str, str):
                        raw_str = str(raw_str)
                    title = "Logs for pod `{}` in namespace `{}`".format(log_pod_name, ns)
                    log_text = _format_pod_log_output(raw_str.strip())
                    reply = "**{}**\n\n```\n{}\n```".format(title, log_text)
                    if not log_namespace:
                        reply += "\n\n(Assuming namespace `default`. Specify e.g. *get logs of &lt;pod&gt; pod in &lt;namespace&gt; namespace* for another.)"
                    logger.info("MCP chat: get_pod_logs pod=%s ns=%s", log_pod_name, ns)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            if mcp_url and helm_releases:
                try:
                    raw = helm_list_releases(
                        mcp_url,
                        namespace=helm_namespace,
                        all_namespaces=helm_all_ns,
                        helm_list_tool=config.get("helm_list_tool") or "helm_list",
                    )
                    title = "Helm releases in namespace `{}`".format(helm_namespace) if helm_namespace else "Helm releases (all namespaces)"
                    reply = _format_helm_releases_reply(title, raw or "(no output)")
                    logger.info("MCP chat: helm list, content_length=%s", len(reply))
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            if mcp_url and res_api and res_kind is not None:
                if res_kind == "PodMetrics" and res_namespace:
                    rows = _fetch_podmetrics_with_usage(res_namespace)
                    if rows is not None:
                        title = "PodMetrics in namespace `{}`".format(res_namespace)
                        reply = _format_podmetrics_reply(title, rows)
                        logger.info("MCP chat: PodMetrics (metrics API) ns=%s, rows=%s", res_namespace, len(rows))
                        return _chat_response(conversation, reply)
                try:
                    raw = k8s_list_resource(mcp_url, res_api, res_kind, res_namespace)
                    plural = res_kind + "s" if not res_kind.endswith("s") else res_kind
                    title = "{} in namespace `{}`".format(plural, res_namespace) if res_namespace else "{} (all namespaces)".format(plural)
                    reply = _format_table_reply(title, raw or "(no output)")
                    if res_kind == "NodeMetrics":
                        reply += "\n\nFor **CPU / MEMORY** columns run: `kubectl top nodes` or install metrics-server and use `kubectl get nodemetrics`."
                    logger.info("MCP chat: list_resource %s", res_kind)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            if mcp_url and list_namespaces:
                try:
                    raw = k8s_list_namespaces(mcp_url)
                    reply = _format_table_reply("Kubernetes namespaces", raw or "(no output)")
                    logger.info("MCP chat: list_namespaces")
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**\n\nCheck that the Kubernetes MCP server is running.".format(str(e))
                    return _chat_response(conversation, reply)
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return _chat_response(conversation, reply)
            if mcp_url and namespace:
                try:
                    raw = k8s_list_pods(mcp_url, namespace)
                    user_asked_count = "how many" in content.lower()
                    reply = _format_pods_reply(namespace, raw or "(no output)", user_asked_count)
                    logger.info("MCP chat: list_pods namespace=%s", namespace)
                    return _chat_response(conversation, reply)
                except RuntimeError as e:
                    reply = "The MCP server returned an error: **{}**\n\nCheck that the Kubernetes MCP server is running and that namespace `{}` exists and you have access.".format(
                        str(e), namespace
                    )
                    return _chat_response(conversation, reply)
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return _chat_response(conversation, reply)

            # No MCP URL or intent not supported
            if mcp_url:
                logger.warning(
                    "MCP chat: no intent matched or not supported, returning fallback reply. content=%r",
                    content[:500],
                )
                reply = (
                    "MCP server is configured at `{}`. I can: **List** (*\"List all namespaces\"*, *\"List pods in &lt;ns&gt;\"*, *\"List Helm releases\"*), "
                    "**Read** (*\"Get logs of &lt;pod&gt;\"*, *\"Describe &lt;pod&gt;\"*), "
                    "**Create** (*\"Create namespace &lt;name&gt;\"*, *\"Create deployment &lt;name&gt; in namespace &lt;ns&gt;\"*), "
                    "**Update** (*\"Update deployment &lt;name&gt; [in namespace &lt;ns&gt;]\"*), "
                    "**Delete** (*\"Delete pod &lt;name&gt; [in namespace &lt;ns&gt;]\"*), "
                    "**Helm** (*\"Install helm chart &lt;chart&gt; [as &lt;release&gt;] [in namespace &lt;ns&gt;]\"*, *\"Uninstall helm release &lt;name&gt;\"*). "
                    "Set `read_only = false` in kubedash.ini to allow create/update/delete/install/uninstall. You said: {}"
                ).format(mcp_url, content[:200])
            else:
                reply = (
                    "MCP server is not configured. Set `[mcp_integration]` `mcp_server_url` in kubedash.ini "
                    "(e.g. `http://127.0.0.1:8082`). You said: " + content[:200]
                )

            return _chat_response(conversation, reply)
    except Exception as e:
        logger.exception("chat_message error: %s", e)
        return jsonify({"error": "InternalError", "message": str(e)}), 500


def _conversation_titles(conversation_ids: list[int]) -> dict[int, str]:
    """Return map conversation_id -> title (first user message truncated, or 'New chat')."""
    if not conversation_ids:
        return {}
    first_user = (
        McpMessage.query.filter(
            McpMessage.conversation_id.in_(conversation_ids),
            McpMessage.role == "user",
        )
        .order_by(McpMessage.conversation_id, McpMessage.created_at.asc())
        .all()
    )
    # First user message per conversation (order is by conv_id, created_at)
    by_conv = {}
    for m in first_user:
        if m.conversation_id not in by_conv:
            title = (m.content or "").strip().replace("\n", " ")[:56]
            by_conv[m.conversation_id] = title + "…" if len((m.content or "").strip()) > 56 else (title or "New chat")
    return {cid: by_conv.get(cid, "New chat") for cid in conversation_ids}


@mcp_integration_api_bp.route("/chat/conversations")
class ChatConversationsResource(MethodView):
    """List conversations for the current user, most recent first (like mcp-chat saved chats)."""

    @login_required
    def get(self):
        limit = min(int(request.args.get("limit", 50)), 100)
        convs = (
            McpConversation.query.filter_by(user_id=current_user.id)
            .order_by(McpConversation.updated_at.desc())
            .limit(limit)
            .all()
        )
        ids = [c.id for c in convs]
        titles = _conversation_titles(ids)
        return jsonify({
            "conversations": [
                {
                    "id": str(c.id),
                    "title": titles.get(c.id, "New chat"),
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                }
                for c in convs
            ]
        })


@mcp_integration_api_bp.route("/chat/conversations/<int:conversation_id>")
class ChatConversationResource(MethodView):
    """Get or delete a single conversation. Conversation must belong to current user."""

    @login_required
    def delete(self, conversation_id):
        conv = McpConversation.query.filter_by(id=conversation_id, user_id=current_user.id).first()
        if not conv:
            return jsonify({"error": "NotFound", "message": "Conversation not found"}), 404
        try:
            db.session.delete(conv)
            db.session.commit()
            return jsonify({"deleted": str(conversation_id)}), 200
        except Exception as e:
            db.session.rollback()
            logger.exception("Delete conversation %s failed: %s", conversation_id, e)
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@mcp_integration_api_bp.route("/chat/conversations/<int:conversation_id>/messages")
class ChatConversationMessagesResource(MethodView):
    """Get messages for a conversation. Conversation must belong to current user."""

    @login_required
    def get(self, conversation_id):
        conv = McpConversation.query.filter_by(id=conversation_id, user_id=current_user.id).first()
        if not conv:
            return jsonify({"error": "NotFound", "message": "Conversation not found"}), 404
        messages = [{"role": m.role, "content": m.content, "created_at": m.created_at.isoformat() if m.created_at else None} for m in conv.messages.all()]
        return jsonify({"conversation_id": str(conv.id), "messages": messages})


@mcp_integration_api_bp.route("/chat/message")
class ChatMessageResource(MethodView):
    """
    Send a user message and return an assistant reply.

    Request JSON: { "content": "user message", "conversation_id": "optional" }
    Response: { "conversation_id": "...", "message": { "role": "assistant", "content": "..." } }

    For supported intents (e.g. "how many pods in namespace X") calls the MCP server.
    Otherwise returns a short status or suggests configuring LLM for open-ended questions.
    """

    @login_required
    def post(self):
        result = _chat_message_impl()
        if isinstance(result, tuple):
            if len(result) == 2:
                return result[0], result[1]
            return result[0]
        return result
