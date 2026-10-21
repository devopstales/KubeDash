"""Group management — 4.1 /user/group parity (TICKET: user/group FE).

``/api/v1/admin/groups/*`` (list, detail, sync, member add/remove,
privilege bind/unbind) — admin-gated, mirroring the permissions API's
shape: thin handlers, the k8s apply + audit rows live in
``services/permission`` (``subject_kind="Group"``), the group CRUD in
``services/groups``.
"""
from flask import g, jsonify
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.api.permissions import _cluster_by_name_or_404
from app.core.security import require_admin
from app.extensions import db
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.group import Group, GroupMember
from app.models.user import User
from app.schemas.groups import (
    GroupBindIn,
    GroupIn,
    GroupMemberIn,
    GroupOut,
    GroupPrivilegeOut,
    GroupSyncOut,
)
from app.services import groups as groups_svc
from app.services import k8s_client as kc
from app.services import permission


class GroupsApi(Api):
    """The real ``/api/v1/admin/groups/*`` routes — replaces the
    base-structure aggregate 501 (which stays; it serves the 8443 mTLS
    app per ADR-0012)."""

    resources_namespace = "groups"
    tags = ["Groups"]
    blp = Blueprint("groups", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        apply_auth(app)

    # ------------------------------------------------------------------
    # List / detail
    # ------------------------------------------------------------------

    @blp.route("/admin/groups", methods=["GET"])
    @blp.doc(responses={
        200: "Every group, oidc first, name order (bare list, GroupOut items).",
        403: "RBAC_DENIED",
    })
    def list_groups(self) -> object:
        require_admin()
        rows = (
            db.session.execute(
                db.select(Group).order_by(Group.source.desc(), Group.name)
            )
        ).scalars().all()
        return jsonify([self._out(group) for group in rows]), 200

    @blp.route("/admin/groups/<name>", methods=["GET"])
    @blp.doc(responses={
        200: "The group + its members (GroupOut with members populated).",
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED",
    })
    def group_detail(self, name: str) -> object:
        require_admin()
        group = self._group_or_404(name)
        payload = self._out(group)
        payload["members"] = self._members(group)
        return jsonify(payload), 200

    # ------------------------------------------------------------------
    # Sync (materialize memberships from every user's groups claim)
    # ------------------------------------------------------------------

    @blp.route("/admin/groups/sync", methods=["POST"])
    @blp.response(200, GroupSyncOut)
    @blp.doc(responses={200: "Sync result.", 403: "RBAC_DENIED"})
    def sync_groups(self) -> dict[str, object]:
        """Materialize Group + GroupMember rows from users' OIDC claims —
        the 4.1 'groups appear after first login' behavior on demand."""
        require_admin()
        created = groups_svc.sync_from_users(db.session)
        db.session.add(AuditLog(
            action="groups.sync", actor_sub=g.current_user.sub, target="groups",
        ))
        db.session.commit()
        return {"created_members": created}

    # ------------------------------------------------------------------
    # Manual group + members
    # ------------------------------------------------------------------

    @blp.route("/admin/groups", methods=["POST"])
    @blp.arguments(GroupIn)
    @blp.response(201, GroupOut)
    @blp.doc(responses={
        201: "Created (GroupOut).",
        403: "RBAC_DENIED",
        409: "CLUSTER_ALREADY_EXISTS (name collision)",
    })
    def create_group(self, args: dict[str, object]) -> tuple[dict[str, object], int]:
        require_admin()
        group = groups_svc.add_manual_group(db.session, name=str(args["name"]))
        db.session.add(AuditLog(
            action="group.create", actor_sub=g.current_user.sub, target=group.name,
        ))
        db.session.commit()
        return self._out(group), 201

    @blp.route("/admin/groups/<name>/members", methods=["POST"])
    @blp.arguments(GroupMemberIn)
    @blp.doc(responses={
        200: "Member present (idempotent).",
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED (group or user missing)",
    })
    def add_group_member(self, name: str, args: dict[str, object]) -> dict[str, object]:
        require_admin()
        member = groups_svc.add_member(
            db.session, group_name=name, user_sub=str(args["user"])
        )
        db.session.add(AuditLog(
            action="group.member_add", actor_sub=g.current_user.sub,
            target=f"group:{name}",
        ))
        db.session.commit()
        return {"member_id": member.id}

    @blp.route("/admin/groups/<name>/members", methods=["DELETE"])
    @blp.arguments(GroupMemberIn)
    @blp.doc(responses={
        200: "Member removed.",
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED (group, user, or membership missing)",
    })
    def remove_group_member(self, name: str, args: dict[str, object]) -> dict[str, object]:
        require_admin()
        groups_svc.remove_member(
            db.session, group_name=name, user_sub=str(args["user"])
        )
        db.session.add(AuditLog(
            action="group.member_remove", actor_sub=g.current_user.sub,
            target=f"group:{name}",
        ))
        db.session.commit()
        return {"deleted": True}

    # ------------------------------------------------------------------
    # Group privileges (bind/unbind a template to the group)
    # ------------------------------------------------------------------

    @blp.route("/admin/groups/<name>/privileges", methods=["GET"])
    @blp.doc(responses={
        200: "The group's bindings (bare list, GroupPrivilegeOut items).",
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED",
    })
    def group_privileges(self, name: str) -> object:
        require_admin()
        group = self._group_or_404(name)
        rows = (
            db.session.execute(
                db.select(ClusterBinding, Cluster.name)
                .join(Cluster, ClusterBinding.cluster_id == Cluster.id)
                .filter(ClusterBinding.user_id == group.id)
                .order_by(ClusterBinding.id)
            )
        ).all()
        items = [
            {
                "cluster": cluster_name,
                "namespace": binding.namespace,
                "template": binding.template,
                "created_at": binding.created_at,
            }
            for binding, cluster_name in rows
        ]
        return jsonify(items), 200

    @blp.route("/admin/groups/<name>/privileges", methods=["POST"])
    @blp.arguments(GroupBindIn)
    @blp.response(200, GroupPrivilegeOut)
    @blp.doc(responses={
        200: "Bound (GroupPrivilegeOut).",
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND / RESOURCE_KIND_NOT_SUPPORTED",
        422: "INVALID_KUBECONFIG (scope mismatch)",
        502: "CLUSTER_UNREACHABLE",
    })
    def bind_group(self, name: str, args: dict[str, object]) -> dict[str, object]:
        """Bind a template to the group on a cluster — mirrors the user
        bind endpoint, the subject is the group (k8s ``Group`` subject)."""
        require_admin()
        group = self._group_or_404(name)
        cluster = _cluster_by_name_or_404(str(args["cluster"]))
        namespace = args.get("namespace")
        assert namespace is None or isinstance(namespace, str)
        binding = permission.bind(
            user_sub=group.name,
            cluster_id=cluster.id,
            namespace=namespace,
            template_name=str(args.get("template") or ""),
            actor_sub=g.current_user.sub,
            db_session=db.session,
            k8s=kc.pool.get(cluster),
            subject_kind="Group",
        )
        namespace = binding.namespace
        assert namespace is None or isinstance(namespace, str)
        return {
            "cluster": cluster.name,
            "namespace": namespace,
            "template": binding.template,
            "created_at": binding.created_at,
        }

    @blp.route("/admin/groups/<name>/privileges", methods=["DELETE"])
    @blp.arguments(GroupBindIn)
    @blp.doc(responses={
        200: "Unbound.",
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND / NO_BINDINGS / RESOURCE_KIND_NOT_SUPPORTED",
        502: "CLUSTER_UNREACHABLE",
    })
    def unbind_group(self, name: str, args: dict[str, object]) -> dict[str, object]:
        require_admin()
        group = self._group_or_404(name)
        cluster = _cluster_by_name_or_404(str(args["cluster"]))
        namespace = args.get("namespace")
        assert namespace is None or isinstance(namespace, str)
        permission.unbind(
            user_sub=group.name,
            cluster_id=cluster.id,
            namespace=namespace,
            actor_sub=g.current_user.sub,
            db_session=db.session,
            k8s=kc.pool.get(cluster),
            subject_kind="Group",
        )
        return {"deleted": True}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _group_or_404(name: str) -> Group:
        group = db.session.execute(
            db.select(Group).filter_by(name=name)
        ).scalar_one_or_none()
        if group is None:
            from app.core.errors import ResourceKindNotSupportedError
            raise ResourceKindNotSupportedError(f"group {name!r} not found")
        return group

    @staticmethod
    def _members(group: Group) -> list[dict[str, object]]:
        rows = (
            db.session.execute(
                db.select(User, GroupMember)
                .join(GroupMember, GroupMember.user_id == User.id)
                .filter(GroupMember.group_id == group.id)
                .order_by(User.display_name.asc(), User.sub)
            )
        ).all()
        return [
            {
                "sub": user.sub,
                "display_name": user.display_name,
                "email": user.email,
                "auth_source": user.auth_source,
            }
            for user, _member in rows
        ]

    @classmethod
    def _out(cls, group: Group) -> dict[str, object]:
        member_count = db.session.execute(
            db.select(GroupMember.id).filter_by(group_id=group.id)
        ).scalars().all()
        return {
            "id": group.id,
            "name": group.name,
            "display_name": group.display_name or group.name,
            "source": group.source,
            "member_count": len(member_count),
            "created_at": group.created_at,
        }
