"""AuthApi (R2) — the OIDC spine: login / callback / refresh / logout / me.

JWT delivery contract: the callback redirects ``302 /?token=<access_jwt>
&refresh=<refresh_token>``; the SPA (Task 8) parks both in localStorage.
Auth routes are open pre-JWT; /auth/me uses the ``require_auth`` decorator.

The domain Api's shared auth-hook pattern (app-wide ``before_request`` scoped
to ``/api/v1/*``) now lives in ``app/api/clusters.py`` (Task 4 replaced the
exemplar stub); Tasks 5-6 copy that ``on_init`` into their own domain APIs.
"""
from datetime import UTC, datetime, timedelta

from flask import g, redirect, request
from flask_smorest import Api, Blueprint, abort

from app.core import security
from app.core.security import (
    REFRESH_TTL_DAYS,
    consume_state,
    issue_token_pair,
    new_state,
    require_auth,
    revoke_user_refresh_tokens,
    rotate_refresh,
)
from app.extensions import db
from app.models.token import RefreshToken
from app.models.user import User
from app.schemas.auth import MeOut, RefreshIn, RefreshOut


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
        access, refresh = issue_token_pair(user)
        db.session.add(
            RefreshToken(
                user_id=user.id,
                token_hash=RefreshToken.hash_token(refresh),
                expires_at=datetime.now(UTC) + timedelta(days=REFRESH_TTL_DAYS),
            )
        )
        db.session.commit()
        return redirect(f"/?token={access}&refresh={refresh}")  # JWT delivery contract

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
