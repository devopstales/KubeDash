"""Admin — user management (TICKET-04, ADR-0013 / R1).

Replaces the base-structure 501 stubs: ``GET /admin/users`` (every user,
with binding count) + ``PATCH /admin/users/<id>`` (role/status, audit,
bootstrap-admin immutable). The bootstrap ``local:`` admin (ADR-0021) is
immutable for role/status → 409 (stable code ``CLUSTER_ALREADY_EXISTS`` —
the frozen v1 contract has no 409 for users; the message names the
restriction. ``BUILTIN_TEMPLATE_PROTECTED`` is reserved for templates).

The ``/admin/clusters`` 501 stub is dropped (replaced by the real registry
``/clusters`` route); its path is removed from the apidocs baseline (the
baseline test is supersets-only: spec ⊇ baseline).
"""
from flask import g, jsonify
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import (
    ClusterAlreadyExistsError,
    InvalidKubeconfigError,
    ResourceKindNotSupportedError,
)
from app.core import security
from app.core.security import require_admin
from app.extensions import db
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.group import Group, GroupMember
from app.models.user import User
from app.schemas.permissions import (
    UserCreateIn,
    UserOut,
    UserPatch,
)


def _stored_groups_by_user() -> dict[str, set[str]]:
    """user sub -> set of group names assigned via the admin UI (TASK-026).
    Dialect-portable (sqlite api tier + PG): one JOIN, no JSONB ops — the
    users table is small (one row per logged-in identity)."""
    rows = db.session.execute(
        db.select(User.sub, Group.name)
        .join(GroupMember, GroupMember.user_id == User.id)
        .join(Group, Group.id == GroupMember.group_id)
    )
    from app.services.groups import LOCAL_PREFIX
    out: dict[str, set[str]] = {}
    for sub, name in rows:
        # Strip the local: prefix so the API returns display names.
        display = name[len(LOCAL_PREFIX):] if name and name.startswith(LOCAL_PREFIX) else name
        out.setdefault(sub, set()).add(display)
    return out


def _effective_groups(claim: list[str] | None, stored: set[str]) -> list[str]:
    """A user's groups = the OIDC claim ∪ stored memberships, deduped and
    sorted (TASK-026)."""
    return sorted(set(claim or []) | stored)


def _user_type(u: User) -> str:
    """The main-branch "Type" column: 'Local' for auth_source=local rows,
    'OIDC' otherwise (TASK-027)."""
    return "Local" if u.auth_source == "local" else "OIDC"


def _out(u: User, cluster_count: int, stored: dict[str, set[str]]) -> dict[str, object]:
    return {
        "id": u.id,
        "sub": u.sub,
        "email": u.email,
        "display_name": u.display_name,
        "groups": _effective_groups(u.groups, stored.get(u.sub, set())),
        "role": u.role,
        "status": u.status,
        "cluster_count": cluster_count,
        "last_login_at": u.last_login_at,
        "auth_source": u.auth_source,
        "user_type": _user_type(u),
    }


class AdminApi(Api):
    """The real ``/api/v1/admin/users`` routes — replaces the base-structure
    stub. ``/admin/clusters`` is intentionally NOT re-added here: the real
    cluster registry lives on the ``clusters`` Api (TICKET-16 owns the list
    surface); its 501 path is dropped from the spec (and the apidocs
    baseline)."""

    resources_namespace = "admin"
    tags = ["Admin"]
    blp = Blueprint("admin", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        # The shared auth-hook pattern (app-wide before_request scoped to
        # /api/v1/*, deduplicated across every domain Api's on_init).
        apply_auth(app)

    @blp.route("/admin/users", methods=["GET"])
    @blp.doc(
        responses={
            200: ("Every user (bare list, UserOut items).", None),
            403: "RBAC_DENIED",
        }
    )
    def list_users(self) -> object:
        """R1: the admin sees EVERY user with a binding count.

        The count is the number of user-management (template-scoped)
        ``cluster_bindings`` rows — legacy rows auto-bound by cluster
        registration (``template=None``, pre user-management) are not
        permission bindings and do not count.
        """
        require_admin()
        counts: dict[int, int] = {
            user_id: n
            for user_id, n in db.session.execute(
                db.select(ClusterBinding.user_id, db.func.count())
                .filter(ClusterBinding.template.is_not(None))
                .group_by(ClusterBinding.user_id)
            )
        }
        stored = _stored_groups_by_user()
        users = db.session.execute(db.select(User).order_by(User.id)).scalars().all()
        items = [_out(u, counts.get(u.id, 0), stored) for u in users]
        return jsonify(items), 200

    @blp.route("/admin/users", methods=["POST"])
    @blp.arguments(UserCreateIn)
    @blp.doc(responses={
        201: ("The created user.", None),
        403: "RBAC_DENIED",
        409: "CLUSTER_ALREADY_EXISTS (email/sub already exists)",
        422: "INVALID_KUBECONFIG (blank username/password or bad role)",
    })
    def create_user(self, args: dict[str, object]) -> object:
        """Create a local-password user (TASK-027, the main-branch Create
        User modal). The password is hashed with the ADR-0021 pbkdf2 util
        (``security.hash_password``); ``auth_source='local'`` so it can log
        in via the local-auth route. A duplicate email or sub is 409 with the
        frozen 409 code."""
        require_admin()
        username = str(args.get("username") or "").strip()
        email = str(args.get("email") or "").strip()
        password = str(args.get("password") or "")
        role = str(args.get("role") or "")
        if not username or not email or not password:
            raise InvalidKubeconfigError("username, email and password are required")
        if role not in ("user", "admin"):
            raise InvalidKubeconfigError("role must be 'user' or 'admin'")
        sub = f"local:{email}"
        exists = db.session.execute(
            db.select(User).filter(db.or_(User.email == email, User.sub == sub))
        ).scalar_one_or_none()
        if exists is not None:
            raise ClusterAlreadyExistsError(f"user {email!r} already exists")
        u = User(
            sub=sub,
            email=email,
            display_name=username,
            role=role,
            auth_source="local",
            password_hash=security.hash_password(password),
        )
        db.session.add(u)
        db.session.add(AuditLog(
            action="user.create", actor_sub=g.current_user.sub, target=sub,
        ))
        db.session.commit()
        resp = jsonify(_out(u, 0, {}))
        resp.status_code = 201
        resp.headers["Location"] = f"/api/v1/admin/users/{u.id}"
        return resp

    @blp.route("/admin/users/<int:user_id>", methods=["DELETE"])
    @blp.doc(responses={
        200: ("Deleted.", None),
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED (user not found)",
        409: "CLUSTER_ALREADY_EXISTS (bootstrap admin or self are immutable)",
    })
    def delete_user(self, user_id: int) -> dict[str, object]:
        """Delete a user (TASK-027, the main-branch delete action). The
        bootstrap ``local:`` admin and the caller themselves are immutable
        (409). Membership (``user_groups``) and bindings cascade via their
        FK ``ondelete=CASCADE``."""
        require_admin()
        user = db.session.get(User, user_id)
        if user is None:
            raise ResourceKindNotSupportedError(f"user {user_id} not found")
        # ponytail: the immutability gate keys on ``sub.startswith("local:")``
        # — the bootstrap upsert's reserved sub convention (same as patch_user).
        if user.sub.startswith("local:"):
            raise ClusterAlreadyExistsError("bootstrap admin cannot be deleted")
        if user.sub == g.current_user.sub:
            raise ClusterAlreadyExistsError("you cannot delete your own account")
        sub = user.sub
        db.session.delete(user)
        db.session.add(AuditLog(
            action="user.delete", actor_sub=g.current_user.sub, target=sub,
        ))
        db.session.commit()
        return {"sub": sub, "deleted": True}

    # NOTE: /admin/groups* (list/detail/sync/create/members/privileges) lives
    # on the GroupsApi (app/api/groups.py) — the frontend-mirrored surface
    # (src/lib/groupTypes.ts mirrors app/schemas/groups.py). The TASK-026
    # group CRUD that used to live here was removed on 2026-10-26 when its
    # duplicate registration collided with GroupsApi (apispec GroupIn /
    # GroupMemberIn name collision; every colliding route was a coin flip
    # between two implementations). Group deletion has no GroupsApi route
    # yet — open task.

    @blp.route("/admin/users/<int:user_id>", methods=["PATCH"])
    @blp.arguments(UserPatch)
    @blp.response(200, UserOut)
    @blp.doc(responses={
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED",
        409: "CLUSTER_ALREADY_EXISTS (bootstrap admin immutable)",
        422: "INVALID_KUBECONFIG",
    })
    def patch_user(self, args: dict[str, object], user_id: int) -> tuple[dict[str, object], int]:
        """R1: change ``role`` and/or ``status``; audit each change. The
        bootstrap ``local:`` admin is immutable (409)."""
        require_admin()
        user = db.session.get(User, user_id)
        if user is None:
            from app.core.errors import ResourceKindNotSupportedError

            raise ResourceKindNotSupportedError(f"user {user_id} not found")
        role = args.get("role")
        status = args.get("status")
        # Validation BEFORE the immutability check: a malformed patch is a
        # 422 (the caller's mistake), even against the immutable bootstrap
        # admin — the 409 is reserved for a VALID change that is refused.
        if role is not None and role not in ("user", "admin"):
            raise InvalidKubeconfigError("role must be 'user' or 'admin'")
        if status is not None and status not in ("active", "disabled"):
            raise InvalidKubeconfigError("status must be 'active' or 'disabled'")
        # The bootstrap local: admin is immutable for role/status (R1) — 409
        # with the restriction named. No update, no audit.
        # ponytail: the gate keys on ``sub.startswith("local:")`` — the
        # bootstrap upsert's reserved sub convention (M-NEW-1: an IdP sub
        # starting with "local:" collides, which is exactly the marker this
        # check relies on). Upgrade path: a dedicated bootstrap flag if
        # ADR-0021 ever adds non-immutable local users.
        if (role is not None or status is not None) and user.sub.startswith("local:"):
            raise ClusterAlreadyExistsError("bootstrap admin cannot be demoted or disabled")
        if role is not None and role != user.role:
            user.role = role
            db.session.add(AuditLog(
                action="role_change", actor_sub=g.current_user.sub, target=user.sub,
            ))
        if status is not None and status != user.status:
            user.status = status
            db.session.add(AuditLog(
                action="status_change", actor_sub=g.current_user.sub, target=user.sub,
            ))
        db.session.commit()
        count = db.session.scalar(
            db.select(db.func.count())
            .select_from(ClusterBinding)
            .filter_by(user_id=user.id)
            .filter(ClusterBinding.template.is_not(None))
        )
        return _out(user, int(count or 0), _stored_groups_by_user()), 200
