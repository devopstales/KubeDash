"""JWT/OIDC security core (R2).

OIDC is the auth spine: login → IdP redirect → callback exchanges the code,
upserts the User, issues a short-lived HS256 access JWT + an opaque rotating
refresh token (sha256-hashed row), and hands both to the browser as HttpOnly
cookies (`302 /`, ADR-0025). No credential ever travels in the URL.

Two credential sources are accepted, in this order: ``Authorization: Bearer``
(the kubectl plugin and API clients) and the ``kd_access`` cookie (the SPA).
The cookie is what makes XSS unable to read the session; the Bearer path is
what lets a non-browser client authenticate at all.

``oidc_authorize_url`` / ``oidc_exchange`` are the two mock seams: tests
monkeypatch exactly these names against ``app.core.security``; the Authlib
client below is the production adapter.
"""
import base64
import hashlib
import hmac
import os
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any
from uuid import UUID

import jwt
from authlib.integrations.flask_client import OAuth
from flask import Response, current_app, g, request

from app.core import kvstore
from app.core.config import get_settings
from app.core.errors import RbacDeniedError, StateMismatchError, UnauthorizedError
from app.extensions import db
from app.models.token import RefreshToken
from app.models.user import User
from app.services import revocation

REFRESH_TTL_DAYS = 30
STATE_TTL_SECONDS = 300
#: ADR-0025: one lifetime for the JWT and its cookie, so they cannot drift.
ACCESS_TTL_SECONDS = 900
ACCESS_COOKIE = "kd_access"
REFRESH_COOKIE = "kd_refresh"
#: Non-HttpOnly navigation hint for the SPA guard. It is spoofable by design
#: and grants nothing — every API call is verified by `_auth_check`.
SESSION_HINT_COOKIE = "kd_session"
_REFRESH_COOKIE_PATH = "/api/v1/auth"

_oauth = OAuth()
# NOTE: do NOT hold a module-level client here — authlib's register() without
# a bound app returns a LocalProxy whose create_client raises, and it is only
# resolved AFTER init_app. The client is created inside init_oidc.
_oidc_client: Any = None


def init_oidc(app: object) -> None:
    """Bind the Authlib client to ``app`` (called from create_app; the Docker-
    free test app also creates it via create_app, but never calls the IdP).

    The OAuth() registry keeps one app for its lifetime, and its client cache
    is per-registry — resetting both here keeps consecutive create_app calls
    (conftest builds one app per test) from reusing a client bound to a
    dead app."""
    global _oidc_client
    s = get_settings()
    _oauth.app = None
    _oauth._clients.clear()
    _oauth.init_app(app)
    _oidc_client = _oauth.register(
        "oidc",
        overwrite=True,
        client_id=s.oidc_client_id,
        client_secret=s.oidc_client_secret,
        server_metadata_url=f"{s.oidc_issuer}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile groups"},
    )


def oidc_authorize_url(state: str) -> str:
    """Real adapter: the IdP authorize URL carrying our opaque ``state``."""
    app = _oidc_client.authorize_redirect(state=state)
    return str(app.get("url") or f"{get_settings().oidc_issuer}/authorize?state={state}")


def oidc_exchange(code: str) -> dict[str, Any]:
    """Real adapter: code → token → userinfo. Returns {sub, email, name, groups}."""
    token = _oidc_client.authorize_access_token(code=code)
    userinfo = token.get("userinfo") or _oidc_client.parse_id_token(token["id_token"])
    return {
        "sub": userinfo["sub"],
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "groups": userinfo.get("groups", []),
    }


def issue_token_pair(user: User, expires_in: int = ACCESS_TTL_SECONDS) -> tuple[str, str]:
    """Short-lived HS256 access JWT (jti carries the ADR-0014 deny-list key)
    + a random opaque refresh token (only its sha256 hash is ever persisted)."""
    s = get_settings()
    now = datetime.now(UTC)
    claims = {
        "sub": user.sub,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    access = jwt.encode(claims, s.kubedash_jwt_secret, algorithm="HS256")
    refresh = uuid.uuid4().hex
    return access, refresh


def set_session_cookies(response: Response, access: str, refresh: str) -> Response:
    """ADR-0025: park the pair in HttpOnly cookies — the ONLY delivery path.

    `Secure` is read from app.config so the HTTP test client can opt out; the
    Settings default is True, so a forgotten config cannot leak the token over
    plain HTTP. The refresh cookie is path-scoped to the auth blueprint: it is
    never sent on ordinary API calls, and `SameSite=Strict` keeps a cross-site
    POST from rotating it.
    """
    secure = bool(current_app.config.get("KUBEDASH_COOKIE_SECURE", True))
    response.set_cookie(
        ACCESS_COOKIE,
        access,
        max_age=ACCESS_TTL_SECONDS,
        httponly=True,
        secure=secure,
        samesite="Lax",
        path="/",
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TTL_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=secure,
        samesite="Strict",
        path=_REFRESH_COOKIE_PATH,
    )
    # Readable by the SPA router on purpose. It carries no credential: a forged
    # `kd_session=1` only renders the shell, and every API call still 401s.
    response.set_cookie(
        SESSION_HINT_COOKIE,
        "1",
        max_age=REFRESH_TTL_DAYS * 24 * 60 * 60,
        httponly=False,
        secure=secure,
        samesite="Lax",
        path="/",
    )
    return response


def clear_session_cookies(response: Response) -> Response:
    """Logout: expire all three cookies at the paths they were set on."""
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path=_REFRESH_COOKIE_PATH)
    response.delete_cookie(SESSION_HINT_COOKIE, path="/")
    return response


def hash_password(pw: str) -> str:
    """ADR-0021: pbkdf2-sha256, 600_000 iterations, 16-byte salt — stdlib
    only (air-gap, ADR-0020). Format: ``pbkdf2:sha256:600000$<b64salt>$<b64hash>``."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
    return f"pbkdf2:sha256:600000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(stored: str, pw: str) -> bool:
    """Constant-time (``hmac.compare_digest``) check against a stored hash.
    A malformed ``stored`` value returns False — it never raises.

    Format: ``pbkdf2:sha256:600000$<b64salt>$<b64hash>`` — the first token
    carries the algorithm + iteration count colon-separated; salt and hash
    are the two ``$``-separated fields."""
    try:
        algo_tok, salt_b64, hash_b64 = stored.split("$")
        _, scheme, iters = algo_tok.split(":")
        assert scheme == "sha256"
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt_b64), int(iters))
    except (ValueError, AssertionError, TypeError):
        # ValueError: b64decode / int() on a malformed field.
        # AssertionError: wrong scheme token.
        # TypeError: pbkdf2_hmac rejects a bad iteration count.
        return False
    return hmac.compare_digest(base64.b64encode(dk).decode(), hash_b64)


def verify_jwt(token: str) -> dict[str, Any]:
    """Decode + validate the access JWT. Raises UnauthorizedError on any
    failure (bad signature, expired, revoked jti) — never a 500."""
    s = get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(token, s.kubedash_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        raise UnauthorizedError("missing or invalid token") from e
    # ADR-0014 deny-list (ADR-0030): the jti row in ``revoked_jtis``, TTL =
    # JWT lifetime. ``db.engine`` is the call-site seam — core may touch the
    # engine, ``app/services/`` may not.
    if revocation.is_revoked(db.engine, UUID(claims["jti"])):
        raise UnauthorizedError("token revoked")
    return claims


def new_state() -> str:
    """Per-session opaque state: 32-byte hex in ``kv`` under
    ``oidc_state:<state>``, TTL 300s (ADR-0030). The value is a one-shot
    marker — the ROW is what ``consume_state`` reads."""
    st = secrets.token_hex(16)
    kvstore.kv_set(db.engine, f"oidc_state:{st}", "1", STATE_TTL_SECONDS)
    return st


def consume_state(state: str) -> None:
    """One-shot check-and-delete: a missing/mismatched state raises
    StateMismatchError, which the factory maps to 400 STATE_MISMATCH.

    The delete is the one-shot: a second consume finds no row (kv_delete
    returned False) and raises — a read-then-delete would let a replay win
    the race."""
    # kv_delete is the one-shot (False = absent), but it also deletes an
    # EXPIRED row: a callback after the TTL must 400, not pass (the TTL
    # half). A fresh row is never deleted here, so the one-shot semantics
    # hold either way.
    key = f"oidc_state:{state}"
    if kvstore.kv_get(db.engine, key) is None:
        kvstore.kv_delete(db.engine, key)  # prune the expired tombstone
        raise StateMismatchError("state mismatch")
    if not kvstore.kv_delete(db.engine, key):
        raise StateMismatchError("state mismatch")


def rotate_refresh(raw_token: str) -> tuple[str, str]:
    """Consume-once refresh rotation: the consumed row is DELETED (T5) and a
    fresh pair is issued. Reuse of a consumed/revoked/unknown token → 401."""
    h = RefreshToken.hash_token(raw_token)
    rt = db.session.execute(db.select(RefreshToken).filter_by(token_hash=h)).scalar_one_or_none()
    if rt is None:
        raise UnauthorizedError("invalid refresh token")
    user = db.session.get(User, rt.user_id)
    if user is None:  # pragma: no cover - FK CASCADE makes this unreachable
        raise UnauthorizedError("invalid refresh token")
    pair = issue_token_pair(user)
    db.session.delete(rt)  # consumed row gone — reuse below finds nothing
    db.session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=RefreshToken.hash_token(pair[1]),
            expires_at=datetime.now(UTC) + timedelta(days=REFRESH_TTL_DAYS),
        )
    )
    db.session.commit()
    return pair


def revoke_user_refresh_tokens(user_id: int) -> None:
    """Logout: every live row for the user is deleted (consumed-token reuse
    then 401s against the missing row)."""
    db.session.execute(
        db.delete(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    db.session.commit()


def _load_user_for_claims(claims: dict[str, Any]) -> None:
    """Single choke point BOTH auth entry paths hit (``_auth_check`` and the
    ``require_auth`` decorator route through it), so the disabled-user gate
    (ADR-0013) lives here: a ``status == "disabled"`` row is a 401, same as a
    missing one (no status enumeration)."""
    user = db.session.execute(db.select(User).filter_by(sub=claims["sub"])).scalar_one_or_none()
    if user is None:
        raise UnauthorizedError("missing or invalid token")
    if user.status == "disabled":
        raise UnauthorizedError("missing or invalid token")
    g.current_user = user


def _auth_check() -> None:
    """Verify the request credential and bind g.current_user.

    Bearer is checked first: an explicit header wins over the ambient cookie,
    which keeps the kubectl plugin unambiguous when a browser happens to send
    both. The cookie is the SPA's path (ADR-0025). Raises UnauthorizedError.
    """
    header = request.headers.get("Authorization", "")
    token = (
        header[len("Bearer "):]
        if header.startswith("Bearer ")
        else request.cookies.get(ACCESS_COOKIE)
    )
    if not token:
        raise UnauthorizedError("missing or invalid token")
    claims = verify_jwt(token)
    _load_user_for_claims(claims)


def _current_jti() -> UUID:
    """Decode the ambient access token's ``jti`` (ADR-0030) — the credential
    the request authenticated with, under the SAME precedence as
    ``_auth_check`` (Bearer header first, then the ``kd_access`` cookie).

    ``verify_jwt`` is not re-run: ``logout`` is ``@require_auth`` (already
    verified + deny-list-checked), and a second PK probe per logout is
    wasted work. A request without a credential raises UnauthorizedError —
    the same 401, not a 500."""
    header = request.headers.get("Authorization", "")
    token = (
        header[len("Bearer "):]
        if header.startswith("Bearer ")
        else request.cookies.get(ACCESS_COOKIE)
    )
    if not token:
        raise UnauthorizedError("missing or invalid token")
    try:
        claims = jwt.decode(token, get_settings().kubedash_jwt_secret, algorithms=["HS256"])
        return UUID(claims["jti"])
    except (jwt.PyJWTError, ValueError, KeyError) as e:
        raise UnauthorizedError("missing or invalid token") from e


def require_auth(f: Callable[..., Any]) -> Callable[..., Any]:
    """Per-route decorator (used by /auth/me): verifies the JWT and loads the
    User into g.current_user. Domain APIs instead register the shared hook in
    on_init — see ``ClustersApi`` in app/api/auth.py for the exact pattern
    Tasks 4-6 copy."""
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _auth_check()
        return f(*args, **kwargs)

    return wrapper


def require_admin() -> None:
    """ADR-0013 admin gate for the Task 4 admin APIs: reads
    ``g.current_user`` (set by the ``require_auth``-family hooks) and raises
    403 ``RBAC_DENIED`` when the caller's role is not ``"admin"``."""
    user = g.current_user
    if getattr(user, "role", None) != "admin":
        raise RbacDeniedError("admin role required")
