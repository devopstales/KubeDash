"""JWT/OIDC security core (R2).

OIDC is the auth spine: login → IdP redirect → callback exchanges the code,
upserts the User, issues a short-lived HS256 access JWT + an opaque rotating
refresh token (sha256-hashed row), and hands both to the SPA via
``302 /?token=<access_jwt>&refresh=<refresh>`` (no HttpOnly cookie).

``oidc_authorize_url`` / ``oidc_exchange`` are the two mock seams: tests
monkeypatch exactly these names against ``app.core.security``; the Authlib
client below is the production adapter.
"""
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import jwt
from authlib.integrations.flask_client import OAuth
from flask import g, request

from app.core.config import get_settings
from app.core.errors import StateMismatchError, UnauthorizedError
from app.extensions import db
from app.models.token import RefreshToken
from app.models.user import User

REFRESH_TTL_DAYS = 30
STATE_TTL_SECONDS = 300

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


def issue_token_pair(user: User, expires_in: int = 900) -> tuple[str, str]:
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


def verify_jwt(token: str) -> dict[str, Any]:
    """Decode + validate the access JWT. Raises UnauthorizedError on any
    failure (bad signature, expired, revoked jti) — never a 500."""
    s = get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(token, s.kubedash_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        raise UnauthorizedError("missing or invalid token") from e
    # ADR-0014 deny-list: jti revocation set in Redis, TTL = JWT lifetime.
    from app.extensions import redis_client

    if redis_client.get(f"revoked:{claims['jti']}"):
        raise UnauthorizedError("token revoked")
    return claims


def new_state() -> str:
    """Per-session opaque state: 32-byte hex in ``oidc_state:<state>``, TTL 300s."""
    from app.extensions import redis_client

    st = secrets.token_hex(16)
    redis_client.set(f"oidc_state:{st}", "1", ex=STATE_TTL_SECONDS)
    return st


def consume_state(state: str) -> None:
    """One-shot check-and-delete: a missing/mismatched state raises
    StateMismatchError, which the factory maps to 400 STATE_MISMATCH."""
    from app.extensions import redis_client

    if not redis_client.delete(f"oidc_state:{state}"):
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
    user = db.session.execute(db.select(User).filter_by(sub=claims["sub"])).scalar_one_or_none()
    if user is None:
        raise UnauthorizedError("missing or invalid token")
    g.current_user = user


def _auth_check() -> None:
    """Verify the Bearer JWT and bind g.current_user. Raises UnauthorizedError."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise UnauthorizedError("missing or invalid token")
    claims = verify_jwt(header[len("Bearer "):])
    _load_user_for_claims(claims)


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
