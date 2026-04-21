"""One-time code storage for kdlogin kubeconfig retrieval when push fails."""

from __future__ import annotations

import json
import secrets
from typing import Any, Optional

from flask import Flask, request

from lib.components import cache
from lib.helper_functions import get_logger

logger = get_logger()

KDLOGIN_CACHE_PREFIX = "kdlogin_otc:v1:"
KDLOGIN_RL_PREFIX = "kdlogin_otc_rl:v1:"
KDLOGIN_HANDOFF_PREFIX = "kdlogin_handoff:v1:"

# Session key: browser handoff fallback (one-time code) after POST to localhost fails
SESSION_KDLOGIN_HANDOFF_ID = "kdlogin_handoff_id"
# Session keys: show one-time code page (push failed or manual fallback; not OAuth success)
SESSION_KDLOGIN_CODE_SHOW = "kdlogin_code_show"
SESSION_KDLOGIN_CODE_FROM_HANDOFF = "kdlogin_code_from_handoff_fallback"


def _code_ttl_seconds(app: Flask) -> int:
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("kdlogin"):
        return int(ini.get("kdlogin", "exchange_code_ttl_sec", fallback="300"))
    return 300


def _rate_limit_per_minute(app: Flask) -> int:
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("kdlogin"):
        return int(ini.get("kdlogin", "exchange_rate_limit_per_minute", fallback="60"))
    return 60


def store_kdlogin_handoff_payload(app: Flask, payload: dict[str, Any]) -> str:
    """Store kubeconfig JSON for handoff-fallback (exchange code) if browser POST fails."""
    handoff_id = secrets.token_urlsafe(18)
    key = KDLOGIN_HANDOFF_PREFIX + handoff_id
    ttl = _code_ttl_seconds(app)
    cache.set(key, json.dumps(payload), timeout=ttl)
    return handoff_id


def pop_kdlogin_handoff_payload(app: Flask, handoff_id: str) -> Optional[dict[str, Any]]:
    if not handoff_id or len(handoff_id) > 256:
        return None
    key = KDLOGIN_HANDOFF_PREFIX + handoff_id
    raw = cache.get(key)
    if raw is None:
        return None
    cache.delete(key)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("kdlogin handoff corrupt cache entry")
        return None


def store_kdlogin_config_payload(app: Flask, payload: dict[str, Any]) -> str:
    """Store payload under a new random code; return the code."""
    code = secrets.token_urlsafe(18)
    key = KDLOGIN_CACHE_PREFIX + code
    ttl = _code_ttl_seconds(app)
    cache.set(key, json.dumps(payload), timeout=ttl)
    logger.info("kdlogin exchange code issued ttl_sec=%s", ttl)
    return code


def pop_kdlogin_config_payload(app: Flask, code: str) -> Optional[dict[str, Any]]:
    """Return payload and delete key if present and non-expired."""
    if not code or len(code) > 256:
        return None
    key = KDLOGIN_CACHE_PREFIX + code
    raw = cache.get(key)
    if raw is None:
        return None
    cache.delete(key)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("kdlogin exchange corrupt cache entry")
        return None


def rate_limit_exchange(app: Flask, client_ip: str) -> bool:
    """Return True if request is allowed, False if rate limited."""
    limit = _rate_limit_per_minute(app)
    rl_key = KDLOGIN_RL_PREFIX + client_ip
    current = cache.get(rl_key)
    if current is None:
        cache.set(rl_key, 1, timeout=60)
        return True
    try:
        n = int(current)
    except (TypeError, ValueError):
        n = 0
    if n >= limit:
        return False
    cache.set(rl_key, n + 1, timeout=60)
    return True


def client_ip_for_rate_limit() -> str:
    forwarded = request.environ.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"
