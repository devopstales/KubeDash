"""Server-side HTTP push of kubeconfig payload to the kdlogin kubectl plugin.

Server push (this module): GET /info to verify the listener, then POST / with JSON.
If that fails (timeout, unreachable from KubeDash), the OIDC callback may still render
a browser handoff page that POSTs directly to http://<host>:<port>/ from the user's
browser — that path does not call /info. So logs showing /info failure are not
inconsistent with kubeconfig arriving via handoff.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Optional

import requests
from flask import Flask, Request
from opentelemetry.trace import Status, StatusCode

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

logger = get_logger()
tracer = get_tracer()

SESSION_OIDC_CLIENT_FLOW = "oidc_client_flow"
KDLOGIN_FLOW_KDLOGIN = "kdlogin"
SESSION_KDLOGIN_CLIENT_PORT = "kdlogin_client_port"
# Set by GET /kdlogin?kdlogin_client=... (kubectl plugin reports local IPv4)
SESSION_KDLOGIN_CLIENT_HOST = "kdlogin_client_host"

# OAuth callback may show these as "client" when the browser runs on the Docker host.
_DOCKER_HOST_GATEWAY_IPS = frozenset({"192.168.65.1", "172.17.0.1"})

KDLOGIN_PUSH_HOST_ENV = "KUBEDASH_KDLOGIN_CLIENT_PUSH_HOST"

# Skip when walking X-Forwarded-For for a "better" client IP (still not reachable from K8s for push)
_UNUSABLE_CLIENT_IPS = _DOCKER_HOST_GATEWAY_IPS | frozenset(
    {"127.0.0.1", "::1", "0.0.0.0"}
)

# Avoid pooled connections to short-lived local listeners (reduces spurious disconnects).
_KDLOGIN_HTTP_HEADERS = {"Connection": "close"}


def client_ip_for_kdlogin_push(request: Request) -> str:
    """
    Best-effort IP for kdlogin server→plugin push. Does not use REMOTE_ADDR when it is only
    the nginx→gunicorn hop (127.0.0.1) while X-Forwarded-For is present. Skips known Docker
    gateway entries in X-Forwarded-For when a different hop exists.
    """
    xff = request.environ.get("HTTP_X_FORWARDED_FOR")
    parts: list[str] = []
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for ip in parts:
            if ip not in _UNUSABLE_CLIENT_IPS:
                return ip
        if parts:
            return parts[-1]
    ra = (request.remote_addr or "").strip()
    if ra and ra not in _UNUSABLE_CLIENT_IPS:
        return ra
    try:
        for ip in getattr(request, "access_route", None) or []:
            s = str(ip).strip()
            if s and s not in _UNUSABLE_CLIENT_IPS:
                return s
    except (TypeError, ValueError):
        pass
    if parts:
        return parts[0]
    return ra or "127.0.0.1"


@dataclass
class KdloginPushResult:
    skipped: bool = False
    success: bool = False
    info_reachable: bool = False
    posted: bool = False
    error_phase: Optional[str] = None
    http_status: Optional[int] = None
    detail: Optional[str] = None


def _kdlogin_timeouts(app: Flask) -> tuple[float, float]:
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("kdlogin"):
        info_t = float(ini.get("kdlogin", "http_info_timeout_sec", fallback="3"))
        post_t = float(ini.get("kdlogin", "http_post_timeout_sec", fallback="5"))
    else:
        info_t, post_t = 3.0, 5.0
    return info_t, post_t


def _default_listen_port(app: Flask) -> int:
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("kdlogin"):
        return int(ini.get("kdlogin", "client_listen_port", fallback="8080"))
    return 8080


def resolve_kdlogin_listen_port(session_dict: dict, app: Flask) -> int:
    """Port the kubectl plugin listens on (session ?port= or [kdlogin] default)."""
    return _resolve_port(session_dict, app)


def _resolve_port(session_dict: dict, app: Flask) -> int:
    raw = session_dict.get(SESSION_KDLOGIN_CLIENT_PORT)
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    return _default_listen_port(app)


def _host_for_http_url(host: str) -> str:
    """IPv6 literals must be bracketed in http:// URLs (RFC 3986)."""
    host = (host or "").strip()
    if not host:
        return host
    try:
        ip = ip_address(host)
        if ip.version == 6:
            return f"[{ip.compressed}]"
    except ValueError:
        pass
    return host


def http_url_host_for_browser_handoff(plugin_reported_host: Optional[str]) -> str:
    """Host for browser fetch() to kdlogin: plugin-reported address only; else localhost name."""
    h = (plugin_reported_host or "").strip()
    if not h:
        return "localhost"
    return _host_for_http_url(h)


def _client_push_host_override(app: Flask) -> Optional[str]:
    raw = os.environ.get(KDLOGIN_PUSH_HOST_ENV, "").strip()
    if raw:
        return raw
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("kdlogin"):
        raw = ini.get("kdlogin", "client_push_host", fallback="").strip()
        if raw:
            return raw
    return None


def _dedupe_hosts(hosts: list[str]) -> list[str]:
    out: list[str] = []
    for h in hosts:
        x = (h or "").strip()
        if x and x not in out:
            out.append(x)
    return out


def _push_host_candidates(
    app: Flask,
    remote_addr: str,
    plugin_client_host: Optional[str] = None,
) -> list[str]:
    override = _client_push_host_override(app)
    if override:
        return [override]
    ra = (remote_addr or "").strip()
    hosts: list[str] = []
    if plugin_client_host:
        p = plugin_client_host.strip()
        if p:
            logger.info(
                "kdlogin push: target host %s from GET /kdlogin?kdlogin_client= (kubectl plugin)",
                p,
            )
            return [p]
    if ra in _DOCKER_HOST_GATEWAY_IPS:
        logger.info(
            "kdlogin push: remote_addr=%s matches Docker host gateway; using that address only",
            ra,
        )
        hosts.append(ra)
    elif ra:
        hosts.append(ra)
    hosts = _dedupe_hosts(hosts)
    return hosts if hosts else ([ra] if ra else ["localhost"])


def _peer_closed_before_response_body(exc: BaseException) -> bool:
    """
    True when the TCP peer closed before urllib3 could read an HTTP response.
    kdlogin writes kubeconfig then may shut down; the POST body was often accepted.
    Only use this after GET /info has already succeeded (so this is POST-phase).
    """
    s = str(exc)
    if "Remote end closed connection without response" in s:
        return True
    if "RemoteDisconnected" in s and "without response" in s:
        return True
    return False


def _kdlogin_push_attempt(
    push_host: str,
    detected_remote: str,
    port: int,
    response_json: dict[str, Any],
    info_timeout: float,
    post_timeout: float,
    root_span_name: str,
) -> KdloginPushResult:
    base_url = f"http://{_host_for_http_url(push_host)}:{port}"
    info_url = f"{base_url}/info"
    post_url = f"{base_url}/"

    with tracer.start_as_current_span(root_span_name) as span:
        span.set_attribute("kdlogin.detected_remote_addr", detected_remote)
        span.set_attribute("kdlogin.push_host", push_host)
        span.set_attribute("kdlogin.port", port)

        try:
            r_info = requests.get(
                info_url,
                timeout=info_timeout,
                headers=_KDLOGIN_HTTP_HEADERS,
            )
        except requests.exceptions.Timeout as e:
            logger.info(
                "kdlogin push GET /info timeout push_host=%s detected_remote=%s: %s "
                "(kubeconfig may still arrive via browser handoff)",
                push_host,
                detected_remote,
                e,
            )
            if span.is_recording():
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, "timeout"))
            return KdloginPushResult(
                success=False, error_phase="network", detail=str(e)
            )
        except requests.exceptions.RequestException as e:
            logger.info(
                "kdlogin push GET /info failed push_host=%s detected_remote=%s: %s "
                "(kubeconfig may still arrive via browser handoff)",
                push_host,
                detected_remote,
                e,
            )
            if span.is_recording():
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return KdloginPushResult(
                success=False, error_phase="network", detail=str(e)
            )

        if r_info.status_code != 200:
            msg = f"kdlogin info HTTP {r_info.status_code}"
            logger.warning(
                "kdlogin push phase=info push_host=%s detected_remote=%s status=%s",
                push_host,
                detected_remote,
                r_info.status_code,
            )
            if span.is_recording():
                span.set_attribute("http.status_code", r_info.status_code)
                span.set_status(Status(StatusCode.ERROR, msg))
            return KdloginPushResult(
                success=False,
                info_reachable=True,
                error_phase="info",
                http_status=r_info.status_code,
                detail=msg,
            )
        try:
            info = r_info.json()
        except json.JSONDecodeError as e:
            logger.warning(
                "kdlogin push phase=info push_host=%s invalid JSON: %s",
                push_host,
                e,
            )
            if span.is_recording():
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
            return KdloginPushResult(
                success=False,
                info_reachable=True,
                error_phase="info",
                detail="invalid JSON from /info",
            )

        if info.get("message") != "kdlogin":
            logger.warning(
                "kdlogin push phase=info push_host=%s unexpected payload=%s",
                push_host,
                info,
            )
            if span.is_recording():
                span.set_attribute("kdlogin.info.message", str(info.get("message")))
                span.set_status(Status(StatusCode.ERROR, "not kdlogin listener"))
            return KdloginPushResult(
                success=False,
                info_reachable=True,
                error_phase="info",
                detail="listener is not kdlogin",
            )

        with tracer.start_as_current_span("kubedash.kdlogin.post") as post_span:
            post_span.set_attribute("http.url", post_url)
            try:
                r_post = requests.post(
                    post_url,
                    json=response_json,
                    timeout=post_timeout,
                    headers=_KDLOGIN_HTTP_HEADERS,
                )
            except requests.exceptions.Timeout as e:
                logger.info(
                    "kdlogin push POST / timeout push_host=%s detected_remote=%s: %s "
                    "(kubeconfig may still arrive via browser handoff)",
                    push_host,
                    detected_remote,
                    e,
                )
                if span.is_recording():
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, "timeout"))
                return KdloginPushResult(
                    success=False, error_phase="network", detail=str(e)
                )
            except requests.exceptions.RequestException as e:
                if _peer_closed_before_response_body(e):
                    logger.info(
                        "kdlogin push: POST reached plugin but connection closed before "
                        "HTTP response was read (kdlogin often exits after writing "
                        "kubeconfig); treating as success push_host=%s detected_remote=%s",
                        push_host,
                        detected_remote,
                    )
                    if post_span.is_recording():
                        post_span.set_attribute("http.status_code", 200)
                    if span.is_recording():
                        span.set_attribute("http.status_code", 200)
                        span.set_status(Status(StatusCode.OK))
                    return KdloginPushResult(
                        success=True,
                        info_reachable=True,
                        posted=True,
                        http_status=200,
                    )
                logger.info(
                    "kdlogin push POST / failed push_host=%s detected_remote=%s: %s "
                    "(kubeconfig may still arrive via browser handoff)",
                    push_host,
                    detected_remote,
                    e,
                )
                if span.is_recording():
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                return KdloginPushResult(
                    success=False, error_phase="network", detail=str(e)
                )

            if post_span.is_recording():
                post_span.set_attribute("http.status_code", r_post.status_code)
            if r_post.status_code != 200:
                msg = f"kdlogin post HTTP {r_post.status_code}"
                logger.warning(
                    "kdlogin push phase=post push_host=%s status=%s body=%s",
                    push_host,
                    r_post.status_code,
                    (r_post.text[:500] if r_post.text else ""),
                )
                if span.is_recording():
                    span.set_attribute("http.status_code", r_post.status_code)
                    span.set_status(Status(StatusCode.ERROR, msg))
                return KdloginPushResult(
                    success=False,
                    info_reachable=True,
                    posted=True,
                    error_phase="post",
                    http_status=r_post.status_code,
                    detail=msg,
                )

        logger.info(
            "kdlogin push ok push_host=%s detected_remote=%s", push_host, detected_remote
        )
        if span.is_recording():
            span.set_attribute("http.status_code", 200)
            span.set_status(Status(StatusCode.OK))
        return KdloginPushResult(
            success=True, info_reachable=True, posted=True, http_status=200
        )


def _execute_push(
    app: Flask,
    remote_addr: str,
    port: int,
    response_json: dict[str, Any],
    info_timeout: float,
    post_timeout: float,
    root_span_name: str,
    plugin_client_host: Optional[str] = None,
) -> KdloginPushResult:
    candidates = _push_host_candidates(app, remote_addr, plugin_client_host)
    last: Optional[KdloginPushResult] = None
    for i, push_host in enumerate(candidates):
        if len(candidates) > 1 and i > 0:
            logger.info(
                "kdlogin push retry detected_remote=%s fallback_push_host=%s",
                remote_addr,
                push_host,
            )
        for attempt in range(2):
            last = _kdlogin_push_attempt(
                push_host,
                remote_addr,
                port,
                response_json,
                info_timeout,
                post_timeout,
                root_span_name,
            )
            if last.success:
                return last
            if last.error_phase != "network":
                return last
            if attempt == 0:
                logger.info(
                    "kdlogin push: network error on push_host=%s, retrying once",
                    push_host,
                )
                time.sleep(0.35)
                continue
            break
    assert last is not None
    return last


def try_push_kubeconfig_to_kdlogin(
    app: Flask,
    session_dict: dict,
    remote_addr: str,
    response_json: dict[str, Any],
) -> KdloginPushResult:
    """
    If OIDC was started from kdlogin, probe the plugin and POST the payload.
    Consumes and clears oidc_client_flow and kdlogin_client_port from session_dict.
    """
    if session_dict.get(SESSION_OIDC_CLIENT_FLOW) != KDLOGIN_FLOW_KDLOGIN:
        return KdloginPushResult(skipped=True)

    plugin_host = session_dict.get(SESSION_KDLOGIN_CLIENT_HOST)
    if isinstance(plugin_host, str):
        plugin_host = plugin_host.strip() or None
    else:
        plugin_host = None

    port = _resolve_port(session_dict, app)
    session_dict.pop(SESSION_OIDC_CLIENT_FLOW, None)
    session_dict.pop(SESSION_KDLOGIN_CLIENT_PORT, None)
    session_dict.pop(SESSION_KDLOGIN_CLIENT_HOST, None)

    info_timeout, post_timeout = _kdlogin_timeouts(app)
    return _execute_push(
        app,
        remote_addr,
        port,
        response_json,
        info_timeout,
        post_timeout,
        "kubedash.kdlogin.push",
        plugin_client_host=plugin_host,
    )


def _cert_push_attempt(
    push_host: str,
    detected_remote: str,
    port: int,
    post_body: dict[str, Any],
    info_timeout: float,
    post_timeout: float,
) -> tuple[bool, KdloginPushResult]:
    """
    Returns (retry_next_host, result).
    retry_next_host is True on timeout/connection error so callers can try another push_host.
    """
    base_url = f"http://{_host_for_http_url(push_host)}:{port}"
    try:
        r_info = requests.get(
            f"{base_url}/info",
            timeout=info_timeout,
            headers=_KDLOGIN_HTTP_HEADERS,
        )
        if r_info.status_code != 200:
            logger.debug(
                "kdlogin cert push skip: push_host=%s info HTTP %s",
                push_host,
                r_info.status_code,
            )
            return (
                False,
                KdloginPushResult(
                    skipped=True, detail=f"info status {r_info.status_code}"
                ),
            )
        info = r_info.json()
        if info.get("message") != "kdlogin":
            return (
                False,
                KdloginPushResult(skipped=True, detail="not kdlogin"),
            )

        r_post = requests.post(
            f"{base_url}/",
            json=post_body,
            timeout=post_timeout,
            headers=_KDLOGIN_HTTP_HEADERS,
        )
        if r_post.status_code == 200:
            logger.info(
                "kdlogin cert push ok push_host=%s detected_remote=%s",
                push_host,
                detected_remote,
            )
            return (
                False,
                KdloginPushResult(
                    success=True, info_reachable=True, posted=True, http_status=200
                ),
            )
        logger.warning(
            "kdlogin cert push post push_host=%s status=%s",
            push_host,
            r_post.status_code,
        )
        return (
            False,
            KdloginPushResult(
                success=False,
                posted=True,
                error_phase="post",
                http_status=r_post.status_code,
            ),
        )
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.debug(
            "kdlogin cert push unreachable push_host=%s detected_remote=%s: %s",
            push_host,
            detected_remote,
            e,
        )
        return (True, KdloginPushResult(skipped=True, detail=str(e)))
    except requests.exceptions.RequestException as e:
        logger.warning("kdlogin cert push error: %s", e)
        return (False, KdloginPushResult(success=False, detail=str(e)))


def try_push_cert_kubeconfig_to_kdlogin(
    app: Flask,
    remote_addr: str,
    post_body: dict[str, Any],
) -> KdloginPushResult:
    """Push cert-based kubeconfig when local listener is kdlogin."""
    port = _default_listen_port(app)
    info_timeout, post_timeout = _kdlogin_timeouts(app)
    candidates = _push_host_candidates(app, remote_addr, None)

    with tracer.start_as_current_span("kubedash.kdlogin.push_cert") as span:
        span.set_attribute("kdlogin.detected_remote_addr", remote_addr)
        span.set_attribute("kdlogin.port", port)
        last: Optional[KdloginPushResult] = None
        for i, push_host in enumerate(candidates):
            span.set_attribute("kdlogin.push_host", push_host)
            if len(candidates) > 1 and i > 0:
                logger.info(
                    "kdlogin cert push retry detected_remote=%s fallback_push_host=%s",
                    remote_addr,
                    push_host,
                )
            retry_next, res = _cert_push_attempt(
                push_host,
                remote_addr,
                port,
                post_body,
                info_timeout,
                post_timeout,
            )
            last = res
            if res.success:
                return res
            if retry_next:
                continue
            return res
        return last or KdloginPushResult(skipped=True)
