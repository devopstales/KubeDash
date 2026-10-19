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
from app.core.errors import ClusterAlreadyExistsError, InvalidKubeconfigError
from app.core.security import require_admin
from app.extensions import db
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.user import User
from app.schemas.permissions import UserOut, UserPatch


def _out(u: User, cluster_count: int) -> dict[str, object]:
    return {
        "id": u.id,
        "sub": u.sub,
        "email": u.email,
        "display_name": u.display_name,
        "groups": list(u.groups or []),
        "role": u.role,
        "status": u.status,
        "cluster_count": cluster_count,
        "last_login_at": u.last_login_at,
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
        users = db.session.execute(db.select(User).order_by(User.id)).scalars().all()
        items = [_out(u, counts.get(u.id, 0)) for u in users]
        return jsonify(items), 200

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
        return _out(user, int(count or 0)), 200
