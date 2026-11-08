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

import re
from pathlib import Path

from flask import Response, abort, request

from app.core.errors import UnauthorizedError
from app.core.security import ACCESS_COOKIE, verify_jwt

#: <meta> name the SPA's consumeIncoming() reads once at mount.
INCOMING_META = "kd-object-incoming"
#: Client tokens are hex (32-bit legacy, 64-bit current). Anything else is
#: not a share token — never stashed, never injected.
TOKEN_RE = re.compile(r"^[0-9a-f]{8,16}$")
#: Matches the client relay TTL (objectRef.ts RELAY_TTL_MS = 60 s): the stash
#: and the localStorage relay it keys expire together.
STASH_TTL_SECONDS = 60
_HEAD_CLOSE = "</head>"


def _subject_from_cookie() -> str | None:
    """Best-effort session subject from the ``kd_access`` cookie.

    Returns None for an absent/invalid/expired/revoked token — the bounce
    and the plain GET are unaffected (a miss renders the list)."""
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        return None
    try:
        claims = verify_jwt(token)
    except UnauthorizedError:
        return None
    sub = claims.get("sub")
    return sub if isinstance(sub, str) and sub else None


def _stash_key(sub: str) -> str:
    return f"obj_incoming:{sub}"


def post_bounce(path: str) -> Response:
    """Handle the share form's POST to an SPA route: stash the token for the
    session and 303 back to the exact same path (clean URL — the token
    arrived in the form body and leaves nowhere but the kv table)."""
    token = request.form.get("o", "")
    sub = _subject_from_cookie()
    if sub is not None and TOKEN_RE.fullmatch(token):
        from app.core import kvstore
        from app.extensions import db

        kvstore.kv_set(db.engine, _stash_key(sub), token, STASH_TTL_SECONDS)
    # A bare flask Response (not werkzeug's redirect()) so the typed view
    # signatures stay flask-Response end to end; a 303's body is ignored.
    return Response(status=303, headers={"Location": path})


def render_index(static_dir: Path) -> Response:
    """Serve the SPA document, injecting the one-shot handoff meta when the
    session carries a fresh stash.

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
    sub = _subject_from_cookie()
    token: str | None = None
    if sub is not None:
        from app.core import kvstore
        from app.extensions import db

        # kv_delete is the one-shot (False = already consumed or absent). It
        # also deletes an EXPIRED row — a stale relay must not be injected,
        # so an expired read prunes and falls through to the plain document.
        value = kvstore.kv_get(db.engine, _stash_key(sub))
        if value is None:
            kvstore.kv_delete(db.engine, _stash_key(sub))  # prune expired tombstone
        elif kvstore.kv_delete(db.engine, _stash_key(sub)):
            token = value
    if token is not None:
        # Token-only (validated hex) attribute value — no quoting hazards.
        html = html.replace(
            _HEAD_CLOSE,
            f'<meta name="{INCOMING_META}" content="{token}" />\n{_HEAD_CLOSE}',
            1,
        )
        cache = "no-store"
    else:
        cache = "no-cache"
    return Response(html, mimetype="text/html", headers={"Cache-Control": cache})
