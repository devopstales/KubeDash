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
    """Extract concatenated text from MCP result.content[].text. Always returns a string."""
    content = result.get("content") or []
    parts = []
    for item in content:
        if not isinstance(item, dict) or item.get("type") != "text":
            continue
        t = item.get("text", "")
        parts.append(str(t) if t is not None else "")
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
    # pod_logs: "get/show logs (of) <podname> (pod)" [in namespace X]
    (
        "pod_logs",
        ("log",),
        re.compile(
            r"\b(?:get|show)\s+logs?\s+(?:of\s+)?(?P<pod>[a-z0-9][a-z0-9\-.]*)\s*(?:pod\b)?",
            re.I,
        ),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
        ],
    ),
    # describe_pod: "describe <podname>" or "describe pod <podname>" [in namespace X]
    (
        "describe_pod",
        (),
        re.compile(
            r"\bdescribe\s+(?:pod\s+)?(?P<pod>[a-z0-9][a-z0-9\-.]*)\s*(?:pod\b)?",
            re.I,
        ),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
        ],
    ),
    # helm_uninstall: "uninstall helm release X" or "helm uninstall X" [in namespace Y]
    (
        "helm_uninstall",
        ("helm",),
        re.compile(
            r"\b(?:helm\s+)?uninstall\s+(?:helm\s+release\s+)?(?P<release>[a-z0-9][a-z0-9\-.]*)\b",
            re.I,
        ),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
        ],
    ),
    # helm_install: "install helm chart X [as Y]" or "helm install Y X" [in namespace Z]
    (
        "helm_install",
        ("helm", "install"),
        re.compile(
            r"\binstall\s+helm\s+(?:chart\s+)?(?P<chart>[a-z0-9][a-z0-9\-./]*)\b"
            r"(?:\s+as\s+|\s+release\s+|\s+name\s+)(?P<release>[a-z0-9][a-z0-9\-.]*)?|"
            r"\bhelm\s+install\s+(?P<release2>[a-z0-9][a-z0-9\-.]*)\s+(?P<chart2>[a-z0-9][a-z0-9\-./]*)\b",
            re.I,
        ),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
        ],
    ),
    # create_resource: "create namespace X" or "create [a] deployment [named] Y [with ...] in [namespace] Z"
    # Also: "create a <name> <kind> in ... namespace" (name before kind, e.g. "create a hello-world configmap in X namespace")
    (
        "create_resource",
        ("create",),
        re.compile(
            r"\bcreate\s+namespace\s+(?P<ns_name>[a-z0-9][a-z0-9\-]*)\b|"
            r"\bcreate\s+(?:a\s+)?(?P<resource>\w+)\s+(?:named\s+)?(?P<name>[a-z0-9][a-z0-9\-.]*)\s+.+?\s+in\s+(?:the\s+)?(?:namespace\s+(?P<ns>[a-z0-9][a-z0-9\-_.]*)|(?P<ns_alt>[a-z0-9][a-z0-9\-_.]*)\s+namespace)\b|"
            r"\bcreate\s+(?:a\s+)?(?P<resource2>\w+)\s+(?:named\s+)?(?P<name2>[a-z0-9][a-z0-9\-.]*)\s+in\s+(?:the\s+)?(?:namespace\s+(?P<ns2>[a-z0-9][a-z0-9\-_.]*)|(?P<ns2_alt>[a-z0-9][a-z0-9\-_.]*)\s+namespace)\b|"
            r"\bcreate\s+(?:a\s+)?(?P<name_first>[a-z0-9][a-z0-9\-.]*)\s+(?P<kind_after>\w+)\s+.+?\s+in\s+(?:the\s+)?(?:namespace\s+(?P<ns_name_first>[a-z0-9][a-z0-9\-_.]*)|(?P<ns_alt_name_first>[a-z0-9][a-z0-9\-_.]*)\s+namespace)\b",
            re.I,
        ),
        None,  # namespace for create <kind> <name> in namespace X is in the regex
    ),
    # delete_resource: "delete pod X" or "delete deployment Y in namespace Z"
    (
        "delete_resource",
        ("delete",),
        re.compile(r"\bdelete\s+(?P<resource>[a-z0-9][a-z0-9\-.]*)\s+(?P<name>[a-z0-9][a-z0-9\-.]*)\b", re.I),
        [
            (re.compile(_NS_IN_SUFFIX_WORD, re.I), 1),
            (re.compile(r"\bin\s+namespace\s+" + _NS_GROUP + r"\b", re.I), 1),
            (re.compile(_NS_IN_SUFFIX, re.I), 1),
        ],
    ),
    # update_resource: "update deployment X" or "patch pod Y in namespace Z" ("udate" = typo for update)
    (
        "update_resource",
        (),
        re.compile(r"\b(?:update|udate|patch|edit)\s+(?P<resource>[a-z0-9][a-z0-9\-.]*)\s+(?P<name>[a-z0-9][a-z0-9\-.]*)\b", re.I),
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

    Matches in order: list_namespaces, helm_releases, pod_logs, describe_pod, list_resource, pods.
    Returns a structured intent dict or None if no intent matched.

    Return shapes:
      {"type": "list_namespaces"}
      {"type": "helm_releases", "all_namespaces": bool, "namespace": str | None}
      {"type": "pod_logs", "pod_name": str, "namespace": str | None}
      {"type": "describe_pod", "pod_name": str, "namespace": str | None}
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
        if intent_type == "pod_logs":
            m = trigger_re.search(t)
            pod_name = m.group("pod").strip() if m else None
            if not pod_name:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: pod_logs pod_name=%r namespace=%r", pod_name, ns)
            return {"type": "pod_logs", "pod_name": pod_name, "namespace": ns}
        if intent_type == "describe_pod":
            m = trigger_re.search(t)
            pod_name = m.group("pod").strip() if m else None
            if not pod_name:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: describe_pod pod_name=%r namespace=%r", pod_name, ns)
            return {"type": "describe_pod", "pod_name": pod_name, "namespace": ns}
        if intent_type == "helm_uninstall":
            m = trigger_re.search(t)
            release = (m.group("release") or "").strip() if m else None
            if not release:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: helm_uninstall release=%r namespace=%r", release, ns)
            return {"type": "helm_uninstall", "release": release, "namespace": ns}
        if intent_type == "helm_install":
            m = trigger_re.search(t)
            if not m:
                continue
            chart = (m.group("chart") or m.group("chart2") or "").strip()
            release = (m.group("release") or m.group("release2") or "").strip() or None
            if not chart:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: helm_install chart=%r release=%r namespace=%r", chart, release, ns)
            return {"type": "helm_install", "chart": chart, "release": release, "namespace": ns}
        if intent_type == "create_resource":
            m = trigger_re.search(t)
            if not m:
                continue
            ns_name = (m.group("ns_name") or "").strip()
            if ns_name:
                logger.debug("MCP intent: create_resource (namespace only) name=%r", ns_name)
                return {"type": "create_resource", "create_namespace": ns_name}
            # "create a <name> <kind> in ... namespace" (name_first, kind_after)
            name_first = (m.group("name_first") or "").strip()
            kind_after = (m.group("kind_after") or "").strip()
            ns_name_first = (m.group("ns_name_first") or m.group("ns_alt_name_first") or "").strip()
            if name_first and kind_after and ns_name_first:
                from plugins.mcp_integration import get_resource_list_map
                resource_map = get_resource_list_map()
                if kind_after.lower() in resource_map:
                    logger.debug("MCP intent: create_resource (name-then-kind) kind=%r name=%r namespace=%r", kind_after, name_first, ns_name_first)
                    return {"type": "create_resource", "resource": kind_after, "name": name_first, "namespace": ns_name_first}
            res = (m.group("resource") or m.group("resource2") or "").strip()
            name = (m.group("name") or m.group("name2") or "").strip()
            ns = (m.group("ns") or m.group("ns_alt") or m.group("ns2") or m.group("ns2_alt") or "").strip()
            if res and name and ns:
                # If "resource" is an article, resolve actual kind from text (e.g. "create a hello-word configmap" -> kind=configmap)
                if res.lower() in ("a", "an", "the"):
                    from plugins.mcp_integration import get_resource_list_map
                    resource_map = get_resource_list_map()
                    for key in sorted(resource_map.keys(), key=lambda k: -len(k)):
                        if re.search(r"\b" + re.escape(key) + r"\b", t):
                            res = key
                            break
                    else:
                        continue  # no known kind found, skip this match
                logger.debug("MCP intent: create_resource kind=%r name=%r namespace=%r", res, name, ns)
                return {"type": "create_resource", "resource": res, "name": name, "namespace": ns}
        if intent_type == "delete_resource":
            m = trigger_re.search(t)
            if not m:
                continue
            res = (m.group("resource") or "").strip()
            name = (m.group("name") or "").strip()
            if not res or not name:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: delete_resource resource=%r name=%r namespace=%r", res, name, ns)
            return {"type": "delete_resource", "resource": res, "name": name, "namespace": ns}
        if intent_type == "update_resource":
            m = trigger_re.search(t)
            if not m:
                continue
            res = (m.group("resource") or "").strip()
            name = (m.group("name") or "").strip()
            if not res or not name:
                continue
            ns = _extract_namespace(t, ns_extractors)
            logger.debug("MCP intent: update_resource resource=%r name=%r namespace=%r", res, name, ns)
            return {"type": "update_resource", "resource": res, "name": name, "namespace": ns}
        # extend with more pattern-driven types as needed

    # 2. list_resource: "list/show/get <resource>" [in namespace X]
    # Require the resource key to be the direct object (right after the verb), so
    # "list pods in balazs-paldi namespace" matches pods, not "namespace" from the phrase "in X namespace".
    # Try longer keys first so "list pods" matches "pods" not "pod", and "get podmetrics" matches "podmetrics" not "pod".
    from plugins.mcp_integration import get_resource_list_map
    resource_map = get_resource_list_map()
    for key in sorted(resource_map.keys(), key=lambda k: -len(k)):
        api_version, kind = resource_map[key]
        if not re.search(r"\b(?:list|show|get)\s+(?:all\s+)?" + re.escape(key) + r"\b", t, re.I):
            continue
        ns = _extract_namespace(t, _NS_EXTRACTORS)
        logger.debug("MCP intent: list_resource kind=%s namespace=%r", kind, ns)
        return {"type": "list_resource", "api_version": api_version, "kind": kind, "namespace": ns}

    # 3. pods: "pods/pod ... in [namespace] X" — require whole-word pod/pods so "podmetrics" doesn't match
    if re.search(r"\b(?:pod|pods)\b", t):
        ns = _extract_namespace(t, _NS_EXTRACTORS)
        if ns is not None:
            logger.debug("MCP intent: pods namespace=%r", ns)
            return {"type": "pods", "namespace": ns}

    return None
