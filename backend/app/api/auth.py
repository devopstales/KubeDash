"""AuthApi (R2) — the OIDC spine: login / callback / refresh / logout / me,
plus ADR-0021's local password sibling: ``/auth/local`` + ``/auth/settings``.

JWT delivery contract: the callback AND local login redirect ``302
/?token=<access_jwt>&refresh=<refresh_token>`` (one builder:
``redirect_with_tokens``); the SPA parks both in localStorage. Auth routes
are open pre-JWT; /auth/me uses the ``require_auth`` decorator.

The domain Api's shared auth-hook pattern (app-wide ``before_request`` scoped
to ``/api/v1/*``) now lives in ``app/api/clusters.py`` (Task 4 replaced the
exemplar stub); Tasks 5-6 copy that ``on_init`` into their own domain APIs.
"""
from datetime import UTC, datetime, timedelta

from flask import g, redirect, request
from flask_smorest import Api, Blueprint, abort

from app.core import security
from app.core.config import get_settings
from app.core.errors import InvalidCredentialsError, LocalAuthDisabledError
from app.core.security import (
    REFRESH_TTL_DAYS,
    consume_state,
    new_state,
    require_auth,
    revoke_user_refresh_tokens,
    rotate_refresh,
)
from app.extensions import db
from app.models.token import RefreshToken
from app.models.user import User
from app.schemas.auth import AuthSettingsOut, LocalLoginIn, MeOut, RefreshIn, RefreshOut


def redirect_with_tokens(access: str, refresh: str) -> str:
    """The JWT delivery contract — ONE builder shared by the OIDC callback
    and local login (T1 key link: both routes cannot diverge)."""
    return f"/?token={access}&refresh={refresh}"


def _issue_and_persist(user: User) -> tuple[str, str]:
    """issue_token_pair + the hashed RefreshToken row (TTL 30d) + commit —
    the OIDC callback's block, verbatim, so local login cannot diverge."""
    access, refresh = security.issue_token_pair(user)
    db.session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=RefreshToken.hash_token(refresh),
            expires_at=datetime.now(UTC) + timedelta(days=REFRESH_TTL_DAYS),
        )
    )
    db.session.commit()
    return access, refresh


def _upsert_user(userinfo: dict[str, object]) -> User:
    """OIDC callback: sub is the stable identity — upsert on it, refreshing
    email/name/groups + last_login_at each login."""
    user = db.session.execute(db.select(User).filter_by(sub=userinfo["sub"])).scalar_one_or_none()
    if user is None:
        user = User(sub=userinfo["sub"])
        db.session.add(user)
    user.last_login_at = datetime.now(UTC)
    user.email = userinfo.get("email")
    user.display_name = userinfo.get("name")
    user.groups = userinfo.get("groups", [])
    # Honest write (I-NEW-2): the OIDC path DECLARES auth_source='oidc'
    # explicitly rather than relying on the column default. The collision
    # case (the bootstrap email claimed by an IdP) flips the row to 'oidc'
    # as a written value — 'SSO wins' per ADR-0021 — and the bootstrap
    # hook's case-gated refresh must not flip it back on the next boot.
    user.auth_source = "oidc"
    db.session.commit()
    return user


class AuthApi(Api):
    resources_namespace = "auth"
    tags = ["Auth"]
    blp = Blueprint("auth", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        # Auth routes are open (pre-JWT); /auth/me uses require_auth per-route.
        # The domain hook (app/api/_authhook.py) path-scopes to /api/v1/* and
        # skips /api/v1/auth/*, so auth needs no opt-out flag here.
        pass

    @blp.route("/auth/login", methods=["POST"])
    @blp.doc(description="Start OIDC login: 302 to /v1/auth/callback?state=<s>&next=<idp>")
    def login(self) -> object:
        state = new_state()
        idp_url = security.oidc_authorize_url(state)
        return redirect(f"/api/v1/auth/callback?state={state}&next={idp_url}")

    @blp.route("/auth/callback", methods=["GET"])
    @blp.doc(responses={
        302: "Redirect to /?token=<jwt>&refresh=<token> (JWT delivery contract)",
        400: "STATE_MISMATCH / missing state or code",
        401: "UNAUTHORIZED",
    })
    def callback(self) -> object:
        args = request.args.to_dict(flat=True)
        state = args.get("state", "")
        code = args.get("code") or ""
        if not state or not code:
            abort(400, message="missing state or code")
        consume_state(state)  # StateMismatchError → 400 STATE_MISMATCH
        userinfo = security.oidc_exchange(code)
        user = _upsert_user(userinfo)
        access, refresh = _issue_and_persist(user)
        return redirect(redirect_with_tokens(access, refresh))  # JWT delivery contract

    @blp.route("/auth/local", methods=["POST"])
    @blp.arguments(LocalLoginIn)
    @blp.doc(responses={
        302: "Redirect to /?token=<jwt>&refresh=<token> (JWT delivery contract)",
        401: "INVALID_CREDENTIALS (wrong password OR unknown email — no enumeration)",
        403: "LOCAL_AUTH_DISABLED",
    })
    def local(self, args: dict[str, object]) -> object:
        """ADR-0021: bootstrap-admin password login, sibling of OIDC. The
        route gates on auth_source='local' so a row SSO has claimed (or a
        pure-SSO row) never answers with a password — same 401 code, no
        enumeration across auth sources (I-NEW-2)."""
        s = get_settings()
        if not (s.bootstrap_admin_email and s.bootstrap_admin_password):
            raise LocalAuthDisabledError("local auth is not configured")
        email = str(args["email"])
        # scalar_one_or_none: a non-existent email → None (the 401 path), never
        # a raised NoResultFound → 500. Multiple rows is impossible — email is
        # the unique key (uq_users_email, TICKET-14).
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if (
            user is None
            or user.auth_source != "local"
            or user.password_hash is None
            or not security.verify_password(user.password_hash, str(args["password"]))
        ):
            raise InvalidCredentialsError("invalid email or password")
        user.last_login_at = datetime.now(UTC)
        access, refresh = _issue_and_persist(user)
        return redirect(redirect_with_tokens(access, refresh))  # JWT delivery contract

    @blp.route("/auth/settings", methods=["GET"])
    @blp.response(200, AuthSettingsOut)
    def settings(self) -> dict[str, bool]:
        """Open (pre-JWT) capability flags for the login page (R3): the SSO
        button renders iff sso_enabled, the local form iff local_enabled."""
        s = get_settings()
        return {
            "sso_enabled": bool(s.oidc_issuer),
            "local_enabled": bool(s.bootstrap_admin_email and s.bootstrap_admin_password),
        }

    @blp.route("/auth/refresh", methods=["POST"])
    @blp.arguments(RefreshIn)
    @blp.response(200, RefreshOut)
    @blp.doc(responses={401: "UNAUTHORIZED"})
    def refresh(self, args: dict[str, object]) -> dict[str, str]:
        access, refresh = rotate_refresh(str(args["refresh_token"]))
        return {"access": access, "refresh": refresh}  # BOTH tokens (rotation)

    @blp.route("/auth/logout", methods=["POST"])
    @blp.doc(responses={401: "UNAUTHORIZED"})
    @require_auth
    def logout(self) -> dict[str, str]:
        user = g.current_user
        revoke_user_refresh_tokens(user.id)
        return {"status": "ok"}

    @blp.route("/auth/me", methods=["GET"])
    @blp.response(200, MeOut)
    @blp.doc(responses={401: "UNAUTHORIZED"})
    @require_auth
    def me(self) -> dict[str, object]:
        u = g.current_user
        return {
            "sub": u.sub,
            "email": u.email,
            "display_name": u.display_name,
            "groups": u.groups or [],
            "role": u.role,
        }
