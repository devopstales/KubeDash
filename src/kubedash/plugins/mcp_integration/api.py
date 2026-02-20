"""
MCP Integration plugin API: chat message endpoint.

Registered under /api/v1/plugins/mcp-integration/ (see initialize_plugin_apis).
"""

import re
from contextlib import nullcontext

from flask import current_app, jsonify, request
from flask_login import current_user, login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

from plugins.mcp_integration.mcp_client import parse_intent
from plugins.mcp_integration.mcp_session import query_mcp_tool

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


@mcp_integration_api_bp.route("/chat/message", methods=["POST"])
@login_required
def chat_message():
    """
    Send a user message and return an assistant reply.

    Request JSON: { "content": "user message", "conversation_id": "optional" }
    Response: { "conversation_id": "...", "message": { "role": "assistant", "content": "..." } }

    For supported intents (e.g. "how many pods in namespace X") calls the MCP server.
    Otherwise returns a short status or suggests configuring LLM for open-ended questions.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        content = (data.get("content") or "").strip()
        if not content:
            return jsonify({"error": "BadRequest", "message": "content is required"}), 400

        config = _get_mcp_config()
        mcp_url = config.get("mcp_server_url") or ""
        logger.debug("MCP chat config: mcp_server_url=%r, read_only=%s", mcp_url or "(empty)", config.get("read_only"))

        # Single intent parse: returns {"type": "...", ...} or None
        intent = parse_intent(content)
        # Derive legacy-style vars for branching
        namespace = intent.get("namespace") if intent and intent.get("type") == "pods" else None
        list_namespaces = intent is not None and intent.get("type") == "list_namespaces"
        res_api = intent.get("api_version") if intent and intent.get("type") == "list_resource" else None
        res_kind = intent.get("kind") if intent and intent.get("type") == "list_resource" else None
        res_namespace = intent.get("namespace") if intent and intent.get("type") == "list_resource" else None
        helm_releases = intent is not None and intent.get("type") == "helm_releases"
        helm_all_ns = intent.get("all_namespaces", True) if intent and intent.get("type") == "helm_releases" else True
        helm_namespace = intent.get("namespace") if intent and intent.get("type") == "helm_releases" else None

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

            if mcp_url and helm_releases:
                tool_name = config.get("helm_list_tool") or "helm_list"
                # containers/kubernetes-mcp-server uses helm_list with all_namespaces (snake_case)
                params_snake = {"all_namespaces": helm_all_ns}
                if not helm_all_ns and helm_namespace:
                    params_snake["namespace"] = helm_namespace
                params_camel = {"allNamespaces": helm_all_ns}
                if not helm_all_ns and helm_namespace:
                    params_camel["namespace"] = helm_namespace
                candidates = [tool_name]
                for alt in ("helm_list", "list_helm_releases"):
                    if alt not in candidates:
                        candidates.append(alt)
                tried_tools = []
                for candidate in candidates:
                    tried_tools.append(candidate)
                    # Prefer snake_case params for helm_list (containers/kubernetes-mcp-server)
                    params = params_snake if candidate == "helm_list" else params_camel
                    try:
                        raw = query_mcp_tool(mcp_url, candidate, params)
                        title = "Helm releases in namespace `{}`".format(helm_namespace) if helm_namespace else "Helm releases (all namespaces)"
                        reply = _format_helm_releases_reply(title, raw or "(no output)")
                        logger.info("MCP chat: replied with %s, content_length=%s", candidate, len(reply))
                        return jsonify({
                            "conversation_id": data.get("conversation_id") or "",
                            "message": {"role": "assistant", "content": reply},
                        })
                    except RuntimeError as e:
                        err_msg = str(e).lower()
                        if "unknown tool" in err_msg or "not found" in err_msg:
                            logger.debug("MCP tool %s not available, trying next candidate: %s", candidate, e)
                            continue
                        logger.error("MCP tool call failed: %s", e)
                        reply = "The MCP server returned an error: **{}**".format(str(e))
                        return jsonify({
                            "conversation_id": data.get("conversation_id") or "",
                            "message": {"role": "assistant", "content": reply},
                        })
                reply = (
                    "The MCP server does not expose a Helm list tool. Tried: {}. "
                    "If your server uses a different tool name, set `[mcp_integration]` `helm_list_tool` in kubedash.ini. "
                    "For containers/kubernetes-mcp-server, ensure the helm toolset is enabled (e.g. `--toolsets=...,helm`)."
                ).format(", ".join(tried_tools))
                return jsonify({
                    "conversation_id": data.get("conversation_id") or "",
                    "message": {"role": "assistant", "content": reply},
                })
            if mcp_url and res_api and res_kind is not None:
                try:
                    params = {"apiVersion": res_api, "kind": res_kind}
                    if res_namespace:
                        params["namespace"] = res_namespace
                    raw = query_mcp_tool(mcp_url, "resources_list", params)
                    plural = res_kind + "s" if not res_kind.endswith("s") else res_kind
                    title = "{} in namespace `{}`".format(plural, res_namespace) if res_namespace else "{} (all namespaces)".format(plural)
                    reply = _format_table_reply(title, raw or "(no output)")
                    logger.info("MCP chat: replied with resources_list %s, content_length=%s", res_kind, len(reply))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except RuntimeError as e:
                    logger.error("MCP tool call failed: %s", e)
                    reply = "The MCP server returned an error: **{}**".format(str(e))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
            if mcp_url and list_namespaces:
                try:
                    raw = query_mcp_tool(mcp_url, "namespaces_list", {})
                    reply = _format_table_reply("Kubernetes namespaces", raw or "(no output)")
                    logger.info("MCP chat: replied with namespaces list, content_length=%s", len(reply))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except RuntimeError as e:
                    logger.error("MCP tool call failed: %s", e)
                    reply = "The MCP server returned an error: **{}**\n\nCheck that the Kubernetes MCP server is running.".format(str(e))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
            if mcp_url and namespace:
                try:
                    raw = query_mcp_tool(
                        mcp_url,
                        "pods_list_in_namespace",
                        {"namespace": namespace},
                    )
                    user_asked_count = "how many" in content.lower()
                    reply = _format_pods_reply(namespace, raw or "(no output)", user_asked_count)
                    logger.info("MCP chat: replied for namespace=%s, content_length=%s", namespace, len(reply))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except RuntimeError as e:
                    logger.error("MCP tool call failed: %s", e)
                    reply = "The MCP server returned an error: **{}**\n\nCheck that the Kubernetes MCP server is running and that namespace `{}` exists and you have access.".format(
                        str(e), namespace
                    )
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })
                except Exception as e:
                    logger.exception("MCP chat unexpected error: %s", e)
                    reply = "An error occurred while calling the MCP server: **{}**".format(str(e))
                    return jsonify({
                        "conversation_id": data.get("conversation_id") or "",
                        "message": {"role": "assistant", "content": reply},
                    })

            # No MCP URL or intent not supported
            if mcp_url:
                reply = (
                    "MCP server is configured at `{}`. I can answer: *\"List all namespaces\"*, "
                    "*\"How many pods in namespace &lt;name&gt;?\"*, *\"List pods in namespace &lt;name&gt;\"*, "
                    "*\"List Helm releases in &lt;namespace&gt;\"*. "
                    "I can also list other resources: *\"List deployments\"*, *\"List services in default\"*, etc. "
                    "For other questions, LLM integration is not yet implemented. You said: {}"
                ).format(mcp_url, content[:200])
            else:
                reply = (
                    "MCP server is not configured. Set `[mcp_integration]` `mcp_server_url` in kubedash.ini "
                    "(e.g. `http://127.0.0.1:8082`). You said: " + content[:200]
                )

            return jsonify({
                "conversation_id": data.get("conversation_id") or "",
                "message": {"role": "assistant", "content": reply},
            })
    except Exception as e:
        logger.exception("chat_message error: %s", e)
        return jsonify({"error": "InternalError", "message": str(e)}), 500
