"""
Minimal MCP (Model Context Protocol) HTTP client for the Kubernetes MCP server.

Uses JSON-RPC 2.0 over HTTP POST to the server's /mcp endpoint.
See: https://modelcontextprotocol.io/specification
"""

import json
import re
import urllib.request
import urllib.error

from lib.helper_functions import get_logger

logger = get_logger()

# Default timeout for MCP HTTP calls
MCP_REQUEST_TIMEOUT = 30


def _parse_sse_json(raw: str):
    """
    If the response is SSE format (event: ... / data: {...}), extract the first data payload as JSON.
    Returns parsed dict or None if not SSE or parse failed.
    """
    if not raw or "data:" not in raw:
        return None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if not payload:
                continue
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                continue
    return None


def _mcp_request(base_url: str, method: str, params: dict, request_id: int = 1) -> dict:
    """
    Send a JSON-RPC 2.0 request to the MCP server.

    Args:
        base_url: Base URL of the MCP server (e.g. http://127.0.0.1:8082)
        method: JSON-RPC method (e.g. tools/call, tools/list)
        params: Method parameters
        request_id: JSON-RPC request id

    Returns:
        The "result" field of the JSON-RPC response, or raises on error.
    """
    url = base_url.rstrip("/") + "/mcp"
    logger.debug("MCP HTTP: %s %s", method, url)
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=MCP_REQUEST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", None)
        try:
            out = json.loads(raw)
        except json.JSONDecodeError:
            out = _parse_sse_json(raw)
            if out is None:
                snippet = (raw[:200] + "..." if len(raw) > 200 else raw).strip() or "(empty body)"
                logger.warning(
                    "MCP HTTP: non-JSON response from %s status=%s, body snippet: %s",
                    url, status, repr(snippet),
                )
                raise RuntimeError(
                    "Invalid MCP response (server did not return JSON). "
                    "Check that the MCP server supports HTTP POST to /mcp. Response snippet: {}".format(snippet[:100])
                )
            logger.debug("MCP HTTP: parsed JSON from SSE-style response")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            err = json.loads(body)
            raise RuntimeError(err.get("error", {}).get("message", body) or str(e))
        except (ValueError, TypeError):
            logger.warning("MCP HTTP: %s %s, body: %s", e.code, e.reason, body[:200] if body else "(empty)")
            raise RuntimeError(body or "{} {}".format(e.code, e.reason))
    except urllib.error.URLError as e:
        raise RuntimeError("MCP server unreachable: " + str(e.reason))

    if "error" in out:
        err = out["error"]
        logger.warning("MCP HTTP error response: method=%s, message=%s", method, err.get("message"))
        raise RuntimeError(err.get("message", "Unknown MCP error"))

    logger.debug("MCP HTTP: %s succeeded", method)
    return out.get("result", {})


def _mcp_post_with_headers(
    base_url: str, method: str, params: dict, request_id: int = 1, extra_headers: dict | None = None
) -> tuple[dict, dict]:
    """
    POST a JSON-RPC request to /mcp and return (response_headers_dict, parsed_response_dict).
    Handles JSON or SSE response body.
    """
    url = base_url.rstrip("/") + "/mcp"
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=MCP_REQUEST_TIMEOUT)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        out = json.loads(raw) if raw.strip().startswith("{") else _parse_sse_json(raw)
        if out and "error" in out:
            raise RuntimeError(out["error"].get("message", raw or str(e)))
        raise RuntimeError(raw or "{} {}".format(e.code, e.reason))
    with resp:
        raw = resp.read().decode("utf-8", errors="replace")
        out = json.loads(raw) if raw.strip().startswith("{") else _parse_sse_json(raw)
        if out is None:
            raise RuntimeError("Invalid MCP response (not JSON): " + (raw[:100] or "(empty)"))
        resp_headers = {k.lower(): resp.headers[k] for k in resp.headers.keys()}
        return resp_headers, out


def _mcp_post_notification(
    base_url: str, method: str, params: dict | None = None, extra_headers: dict | None = None
) -> None:
    """Send a JSON-RPC notification (no id). Server may return 202 or 200 with no body."""
    url = base_url.rstrip("/") + "/mcp"
    body = {"jsonrpc": "2.0", "method": method, "params": params if params is not None else {}}
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=MCP_REQUEST_TIMEOUT) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        if e.code != 202:
            body_str = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise RuntimeError(body_str or "{} {}".format(e.code, e.reason))


def _extract_content_text(result: dict) -> str:
    """Extract concatenated text from MCP result.content[].text."""
    content = result.get("content") or []
    parts = [item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
    return "\n".join(parts).strip() if parts else ""


def streamable_http_call_tool(base_url: str, tool_name: str, arguments: dict) -> str:
    """
    Call an MCP tool using sync Streamable HTTP with full handshake:
    initialize -> notifications/initialized -> tools/call.
    Required by MCP spec; avoids "tools/call is invalid during session initialization".
    """
    url = base_url.rstrip("/") + "/mcp"
    logger.info("MCP Streamable HTTP (sync): initialize -> initialized -> tool %s at %s", tool_name, url)
    init_params = {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "kubedash", "version": "1.0"},
    }
    try:
        resp_headers, init_out = _mcp_post_with_headers(base_url, "initialize", init_params, request_id=1)
    except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError) as e:
        logger.warning("MCP Streamable HTTP: initialize failed: %s", e)
        raise
    if "error" in init_out:
        raise RuntimeError(init_out["error"].get("message", "Initialize failed"))
    session_id = resp_headers.get("mcp-session-id")
    if not session_id and isinstance(init_out.get("result"), dict):
        session_id = init_out["result"].get("sessionId")
    if not session_id:
        logger.warning("MCP Streamable HTTP: no session id in response")
        raise RuntimeError("Server did not return a session id")
    if isinstance(session_id, list):
        session_id = session_id[0] if session_id else ""
    session_id = str(session_id).strip()
    extra = {"Mcp-Session-Id": session_id}
    try:
        _mcp_post_notification(base_url, "notifications/initialized", extra_headers=extra)
    except Exception as e:
        logger.warning("MCP Streamable HTTP: notifications/initialized failed: %s", e)
        raise
    try:
        _, call_out = _mcp_post_with_headers(
            base_url,
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
            request_id=2,
            extra_headers=extra,
        )
    except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError) as e:
        logger.warning("MCP Streamable HTTP: tools/call failed: %s", e)
        raise
    if "error" in call_out:
        raise RuntimeError(call_out["error"].get("message", "Tool call failed"))
    out = _extract_content_text(call_out.get("result", {}))
    logger.debug("MCP Streamable HTTP (sync): tool %s returned %s chars", tool_name, len(out))
    return out


def mcp_call_tool(base_url: str, tool_name: str, arguments: dict) -> str:
    """
    Call an MCP tool and return the result as text.

    Args:
        base_url: MCP server base URL
        tool_name: Tool name (e.g. pods_list_in_namespace)
        arguments: Tool arguments (e.g. {"namespace": "default"})

    Returns:
        Concatenated text from result.content[].text, or empty string.
    """
    logger.info("MCP HTTP: calling tool %s at %s, arguments=%s", tool_name, base_url, arguments)
    result = _mcp_request(base_url, "tools/call", {"name": tool_name, "arguments": arguments or {}})
    content = result.get("content") or []
    parts = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
    out = "\n".join(parts).strip() if parts else ""
    logger.debug("MCP HTTP: tool %s returned %s chars", tool_name, len(out))
    return out


# Namespace extraction: shared group name for regexes that capture namespace
_NS_GROUP = r"([a-z0-9][a-z0-9\-_.]*)"
# Patterns that capture namespace (in "in X namespace" / "in namespace X" / "in X" at end)
_NS_IN_SUFFIX = r"\bin\s+(?:the\s+)?(?:namespace\s+)?" + _NS_GROUP + r"\s*[.?\s]*$"
_NS_IN_MID = r"\bin\s+namespace\s+" + _NS_GROUP + r"\b"
_NS_IN_SUFFIX_WORD = r"\bin\s+(?:the\s+)?" + _NS_GROUP + r"\s+namespace\s*[.?\s]*$"

# Intent patterns: order matters (more specific first).
# Each entry: (intent_type, required_keywords, trigger_regex, namespace_regexes_or_None)
# trigger_regex: must match for the intent; if it has a group, it's the namespace.
# For multi-step namespace extraction we use a list of (regex, group_index) and run after trigger.
INTENT_PATTERNS = (
    # list_namespaces: "list/show/get/what (all) namespaces" only (no "in X namespace")
    (
        "list_namespaces",
        (),
        re.compile(r"\b(?:list|show|get|what)\s+(?:all\s+)?namespaces?\b", re.I),
        None,
    ),
    # helm_releases: "list/show/get ... helm releases" [optional in namespace X]
    (
        "helm_releases",
        ("helm", "release"),
        re.compile(r"\b(?:list|show|get)\s+[\w\s\-]*helm\s+releases?\b", re.I),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
        ],
    ),
)

# RESOURCE_LIST_MAP is built from cluster discovery in plugins.mcp_integration.__init__
# (get_resource_list_map). Used for list_resource intent: plural/singular -> (apiVersion, kind).

# Shared namespace extractors (list of (regex, group_index)) for reuse
_NS_EXTRACTORS = [
    (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
    (re.compile(_NS_IN_SUFFIX, re.I), 1),
    (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
]


def _extract_namespace(t: str, extractors: list | None) -> str | None:
    """Run namespace extractors on normalized text; return first captured group or None."""
    if not extractors:
        return None
    for regex, group_idx in extractors:
        m = regex.search(t)
        if m:
            return m.group(group_idx).strip()
    return None


def parse_intent(text: str) -> dict | None:
    """
    Single entry point for MCP chat intent parsing.

    Matches in order: list_namespaces, helm_releases, list_resource, pods.
    Returns a structured intent dict or None if no intent matched.

    Return shapes:
      {"type": "list_namespaces"}
      {"type": "helm_releases", "all_namespaces": bool, "namespace": str | None}
      {"type": "list_resource", "api_version": str, "kind": str, "namespace": str | None}
      {"type": "pods", "namespace": str}
    """
    if not text or not text.strip():
        return None
    t = text.strip().lower().rstrip("?.!;,")

    # 1. Pattern-driven intents (INTENT_PATTERNS)
    for intent_type, required_keywords, trigger_re, ns_extractors in INTENT_PATTERNS:
        if required_keywords and not all(kw in t for kw in required_keywords):
            continue
        if not trigger_re.search(t):
            continue
        if intent_type == "list_namespaces":
            logger.debug("MCP intent: list_namespaces")
            return {"type": "list_namespaces"}
        if intent_type == "helm_releases":
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: helm_releases namespace=%r", ns)
            return {"type": "helm_releases", "all_namespaces": ns is None, "namespace": ns}
        # extend with more pattern-driven types as needed

    # 2. list_resource: "list/show/get <resource>" [in namespace X]
    from plugins.mcp_integration import get_resource_list_map
    for key, (api_version, kind) in get_resource_list_map().items():
        if key not in t:
            continue
        if not re.search(r"\b(?:list|show|get)\s+[\w\s\-]*" + re.escape(key), t, re.I):
            continue
        ns = _extract_namespace(t, _NS_EXTRACTORS)
        logger.debug("MCP intent: list_resource kind=%s namespace=%r", kind, ns)
        return {"type": "list_resource", "api_version": api_version, "kind": kind, "namespace": ns}

    # 3. pods: "pods/pod ... in [namespace] X"
    if "pod" in t:
        ns = _extract_namespace(t, _NS_EXTRACTORS)
        if ns is not None:
            logger.debug("MCP intent: pods namespace=%r", ns)
            return {"type": "pods", "namespace": ns}

    return None
