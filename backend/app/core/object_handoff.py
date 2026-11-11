"""One-shot object handoff for the SPA deep link (ADR-0040 R4/R5).

The share button POSTs ``o=<token>`` (a hidden form field) to the object's
list route in a fresh tab. The SPA fallback (``app.register_static``) bounces
the POST as a 303 to the same path and stashes the token in the ``kv`` table
(ADR-0030, the Redis removal) under ``obj_incoming:<sub>`` —
the authenticated user's JWT ``sub`` — with a 60 s TTL (the client relay
window). The first subsequent GET (the fresh tab's document load, same
session cookie) pops the stash and injects it into ``index.html`` as
``<meta name="kd-object-incoming" content="<token>">``.

The token never appears in a URL (R1) and no new cookie is issued (ADR-0025
transport is untouched): the transfer channel is the server-side session
state keyed by the existing ``kd_access`` JWT. The ref payload itself still
crosses tabs through the localStorage relay the client wrote before the POST
— the stash carries the key, the relay carries the object.

Miss paths all render the list, never a wrong object: anonymous/bogus
session (no stash), malformed token (not stashed), expired relay (client
side), or a second GET (stash already popped).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from flask import Response, abort, request

from app.core.errors import UnauthorizedError
from app.core.security import ACCESS_COOKIE, verify_jwt

#: <meta> name the SPA's consumeIncoming() reads once at mount.
INCOMING_META = "kd-object-incoming"
#: <meta> name the SPA's share form echoes the verified session CSRF token from.
CSRF_META = "kd-csrf"
#: Client tokens are hex (32-bit legacy, 64-bit current). Anything else is
#: not a share token — never stashed, never injected.
TOKEN_RE = re.compile(r"^[0-9a-f]{8,16}$")
#: Matches the client relay TTL (objectRef.ts RELAY_TTL_MS = 60 s): the stash
#: and the localStorage relay it keys expire together.
STASH_TTL_SECONDS = 60
_HEAD_CLOSE = "</head>"


def _verified_identity() -> tuple[str, str] | None:
    """Best-effort verified session identity: ``(JWT sub, jti)``.

    The ``jti`` doubles as the unguessable per-session CSRF token for the
    share POST. Returns None for an absent/invalid/expired/revoked token — the
    miss paths are unaffected (the bounce/GET render plain documents).
    """
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        return None
    try:
        claims = verify_jwt(token)
    except UnauthorizedError:
        return None
    sub = claims.get("sub")
    jti = claims.get("jti")
    if not isinstance(sub, str) or not sub or not isinstance(jti, str) or not jti:
        return None
    return sub, jti


def _stash_key(sub: str) -> str:
    return f"obj_incoming:{sub}"


def post_bounce(path: str) -> Response:
    """Handle the share form's POST to an SPA route: stash the token for the
    session and 303 back to the exact same path (clean URL — the token
    arrived in the form body and leaves nowhere but the kv table).

    The form must echo the verified session CSRF token (`jti`) alongside the
    object token; anything else is rejected without stashing.
    """
    token = request.form.get("o", "")
    identity = _verified_identity()
    if identity is None:
        # Anonymous/bogus session: bounce, but never stash.
        return Response(status=303, headers={"Location": path})
    sub, csrf_token = identity
    if not TOKEN_RE.fullmatch(token):
        return Response(status=303, headers={"Location": path})
    if request.form.get("csrf", "") != csrf_token:
        return Response(status=403, headers={"Location": path})
    from app.core import kvstore
    from app.extensions import db

    current = kvstore.kv_get(db.engine, _stash_key(sub))
    tokens = json.loads(current) if current is not None else []
    tokens.append(token)
    kvstore.kv_set(db.engine, _stash_key(sub), json.dumps(tokens), STASH_TTL_SECONDS)
    # A bare flask Response (not werkzeug's redirect()) so the typed view
    # signatures stay flask-Response end to end; a 303's body is ignored.
    return Response(status=303, headers={"Location": path})


def render_index(static_dir: Path) -> Response:
    """Serve the SPA document, injecting the one-shot handoff meta and the
    verified session CSRF meta when the session is authenticated.

    The stash is consumed by exactly one GET (kv read + one-shot delete, the
    ADR-0030 kvstore pattern): a second load — or a load by a different
    session — gets the plain document. Caching follows the content: the
    injected document is no-store (it carries a one-shot payload), the plain
    document keeps no-cache (as before).
    """
    index_file = static_dir / "index.html"
    if not index_file.is_file():
        abort(404)
    html = index_file.read_text(encoding="utf-8")
    identity = _verified_identity()
    sub = identity[0] if identity is not None else None
    csrf_token = identity[1] if identity is not None else None
    token: str | None = None
    if sub is not None:
        from app.core import kvstore
        from app.extensions import db

        # Per-sub token queue: POSTs append, GETs pop the oldest. Rapid
        # double shares therefore cannot overwrite an in-flight handoff.
        current = kvstore.kv_get(db.engine, _stash_key(sub))
        if current is None:
            kvstore.kv_delete(db.engine, _stash_key(sub))  # prune expired tombstone
        else:
            tokens = json.loads(current)
            token = tokens.pop(0)
            if tokens:
                kvstore.kv_set(
                    db.engine, _stash_key(sub), json.dumps(tokens), STASH_TTL_SECONDS
                )
            else:
                kvstore.kv_delete(db.engine, _stash_key(sub))
    injection = ""
    if token is not None:
        injection += f'<meta name="{INCOMING_META}" content="{token}" />\n'
    if csrf_token is not None:
        injection += f'<meta name="{CSRF_META}" content="{csrf_token}" />\n'
    if injection:
        html = html.replace(_HEAD_CLOSE, injection + _HEAD_CLOSE, 1)
    cache = "no-store" if token is not None else "no-cache"
    return Response(html, mimetype="text/html", headers={"Cache-Control": cache})
