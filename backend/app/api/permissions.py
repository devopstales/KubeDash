"""Permission management — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(TICKET-04, ADR-0013): ``/admin/permissions/*`` (templates CRUD, bind,
unbind) + ``/permissions/my-access`` (any authenticated user).

Replaces the base-structure 501 stubs. The bind/unbind handlers are THIN:
they resolve the cluster by name and delegate to
``services/permission.bind``/``unbind`` (the synchronous apply + Role GC,
ADR-0008) — the audit rows are written inside the service, never here
(no double-audit). Template mutations DO audit here (the service has no
template seam).

409 choices (recorded in the Task 4 report — the frozen v1 contract has no
user/template-conflict code, so the stable 409 carriers are reused with
clear messages):
- bootstrap admin immutable → ``CLUSTER_ALREADY_EXISTS``
- template name collision → ``CLUSTER_ALREADY_EXISTS``
- custom template still referenced by a binding → ``CLUSTER_ALREADY_EXISTS``
- built-in template mutation/deletion → ``BUILTIN_TEMPLATE_PROTECTED``
"""
from flask import g, jsonify
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import (
    BuiltinTemplateProtectedError,
    ClusterAlreadyExistsError,
    ClusterNotFoundError,
    InvalidKubeconfigError,
    ResourceKindNotSupportedError,
)
from app.core.security import require_admin
from app.extensions import db
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.rbac_template import RBACTemplate
from app.models.user import User
from app.schemas.permissions import BindIn, BindingOut, TemplateIn, TemplateOut
from app.services import k8s_client as kc
from app.services import permission


def _template_out(t: RBACTemplate) -> dict[str, object]:
    return {
        "id": t.id,
        "name": t.name,
        "description": t.description or "",
        "scope": t.scope,
        "rules": list(t.rules or []),
        "builtin": t.builtin,
        "created_by": t.created_by,
        "created_at": t.created_at,
    }


def _rules_from_args(args: dict[str, object]) -> list[dict[str, object]]:
    """Coerce the schema-loaded ``rules`` (``object`` under mypy strict —
    marshmallow's ``List(Dict)``) to the list-of-dicts the handler + the
    k8s client consume. ``cast`` keeps the coercion visible to mypy without
    suppressing a real error at the call sites."""
    from typing import cast

    raw = args.get("rules")
    if raw is None:
        return []
    return [dict(r) for r in cast("list[dict[str, object]]", raw)]


def _validate_rules(rules: list[dict[str, object]]) -> None:
    """R2 rules-shape validation → 422 (the only stable 422). Each rule must
    carry non-empty ``verbs`` and ``resources``."""
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise InvalidKubeconfigError(f"rule {i} must be an object")
        verbs = rule.get("verbs")
        resources = rule.get("resources")
        if not isinstance(verbs, list) or not verbs or not all(
            isinstance(v, str) and v for v in verbs
        ):
            raise InvalidKubeconfigError(f"rule {i} needs a non-empty 'verbs' list")
        if not isinstance(resources, list) or not resources:
            raise InvalidKubeconfigError(f"rule {i} needs a non-empty 'resources' list")


def _cluster_by_name_or_404(name: str) -> Cluster:
    from typing import cast

    cluster = cast(
        "Cluster | None",
        db.session.execute(db.select(Cluster).filter_by(name=name)).scalar_one_or_none(),
    )
    if cluster is None:
        raise ClusterNotFoundError(f"cluster {name!r} not found")
    return cluster


class PermissionsApi(Api):
    """The real ``/api/v1/admin/permissions/*`` + ``/permissions/my-access``
    routes — replaces the base-structure stubs."""

    resources_namespace = "permissions"
    tags = ["Permissions"]
    blp = Blueprint("permissions", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        apply_auth(app)

    # ------------------------------------------------------------------
    # Templates CRUD (R2)
    # ------------------------------------------------------------------

    @blp.route("/admin/permissions/templates", methods=["GET"])
    @blp.doc(
        responses={
            200: ("Every template, built-ins first (bare list, TemplateOut items).", None),
            403: "RBAC_DENIED",
        }
    )
    def list_templates(self) -> object:
        require_admin()
        rows = db.session.execute(
            db.select(RBACTemplate).order_by(RBACTemplate.builtin.desc(), RBACTemplate.name)
        ).scalars().all()
        items = [_template_out(t) for t in rows]
        return jsonify(items), 200

    @blp.route("/admin/permissions/templates", methods=["POST"])
    @blp.arguments(TemplateIn)
    @blp.response(201, TemplateOut)
    @blp.doc(responses={
        403: "RBAC_DENIED",
        409: "CLUSTER_ALREADY_EXISTS (name collision)",
        422: "INVALID_KUBECONFIG (rules shape)",
    })
    def create_template(self, args: dict[str, object]) -> tuple[dict[str, object], int]:
        """Create a CUSTOM template (built-ins are seeded by migration, not
        created here). 422 (rules shape) before 409 (name collision)."""
        require_admin()
        scope = args.get("scope")
        if scope is None or scope not in ("namespace", "cluster"):
            raise InvalidKubeconfigError("scope must be 'namespace' or 'cluster'")
        rules = _rules_from_args(args)
        _validate_rules(rules)
        name = str(args["name"])
        exists = db.session.execute(
            db.select(RBACTemplate).filter_by(name=name)
        ).scalar_one_or_none()
        if exists is not None:
            raise ClusterAlreadyExistsError("template name already exists")
        t = RBACTemplate(
            name=name,
            description=str(args.get("description") or ""),
            scope=scope,
            rules=rules,
            created_by=g.current_user.sub,
        )
        db.session.add(t)
        db.session.add(AuditLog(
            action="template.create", actor_sub=g.current_user.sub, target=name,
        ))
        db.session.commit()
        return _template_out(t), 201

    @blp.route("/admin/permissions/templates/<name>", methods=["GET"])
    @blp.response(200, TemplateOut)
    @blp.doc(responses={403: "RBAC_DENIED", 404: "RESOURCE_KIND_NOT_SUPPORTED"})
    def get_template(self, name: str) -> dict[str, object]:
        require_admin()
        t = db.session.execute(
            db.select(RBACTemplate).filter_by(name=name)
        ).scalar_one_or_none()
        if t is None:
            raise ResourceKindNotSupportedError(f"template {name!r} not found")
        return _template_out(t)

    @blp.route("/admin/permissions/templates/<name>", methods=["PUT"])
    @blp.arguments(TemplateIn)
    @blp.response(200, TemplateOut)
    @blp.doc(responses={
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED",
        409: "BUILTIN_TEMPLATE_PROTECTED",
        422: "INVALID_KUBECONFIG (rules shape)",
    })
    def update_template(self, args: dict[str, object], name: str) -> dict[str, object]:
        """Update a CUSTOM template only; a built-in → 409."""
        require_admin()
        t = db.session.execute(
            db.select(RBACTemplate).filter_by(name=name)
        ).scalar_one_or_none()
        if t is None:
            raise ResourceKindNotSupportedError(f"template {name!r} not found")
        if t.builtin:
            raise BuiltinTemplateProtectedError(f"built-in template {name!r} cannot be updated")
        scope = args.get("scope")
        if scope is None or scope not in ("namespace", "cluster"):
            raise InvalidKubeconfigError("scope must be 'namespace' or 'cluster'")
        rules = _rules_from_args(args)
        _validate_rules(rules)
        t.scope = scope
        t.rules = rules
        t.description = str(args.get("description") or "")
        db.session.add(AuditLog(
            action="template.update", actor_sub=g.current_user.sub, target=name,
        ))
        db.session.commit()
        return _template_out(t)

    @blp.route("/admin/permissions/templates/<name>", methods=["DELETE"])
    @blp.doc(responses={
        403: "RBAC_DENIED",
        404: "RESOURCE_KIND_NOT_SUPPORTED",
        409: "BUILTIN_TEMPLATE_PROTECTED / CLUSTER_ALREADY_EXISTS (referenced)",
    })
    def delete_template(self, name: str) -> dict[str, object]:
        """Delete a CUSTOM template. Built-in → 409
        ``BUILTIN_TEMPLATE_PROTECTED``; still referenced by a binding → 409
        ``CLUSTER_ALREADY_EXISTS`` naming the referencing binding(s)."""
        require_admin()
        t = db.session.execute(
            db.select(RBACTemplate).filter_by(name=name)
        ).scalar_one_or_none()
        if t is None:
            raise ResourceKindNotSupportedError(f"template {name!r} not found")
        if t.builtin:
            raise BuiltinTemplateProtectedError(f"built-in template {name!r} cannot be deleted")
        referencing = db.session.execute(
            db.select(ClusterBinding)
            .join(User, ClusterBinding.user_id == User.id)
            .filter(ClusterBinding.template == name)
            .order_by(ClusterBinding.id)
        ).scalars().all()
        if referencing:
            parts: list[str] = []
            for b in referencing:
                u = db.session.get(User, b.user_id)
                sub = u.sub if u is not None else str(b.user_id)
                parts.append(f"user {sub} on cluster {b.cluster_id}")
            raise ClusterAlreadyExistsError(
                f"template {name!r} is referenced by binding(s): {', '.join(parts)}"
            )
        db.session.delete(t)
        db.session.add(AuditLog(
            action="template.delete", actor_sub=g.current_user.sub, target=name,
        ))
        db.session.commit()
        return {"deleted": name}

    # ------------------------------------------------------------------
    # Bind / unbind (R3/R4) — thin: resolve + delegate to the service
    # ------------------------------------------------------------------

    @blp.route("/admin/permissions/bind", methods=["POST"])
    @blp.arguments(BindIn)
    @blp.response(200, BindingOut)
    @blp.doc(responses={
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND / RESOURCE_KIND_NOT_SUPPORTED",
        422: "INVALID_KUBECONFIG (scope mismatch)",
        502: "CLUSTER_UNREACHABLE",
    })
    def bind(self, args: dict[str, object]) -> dict[str, object]:
        """Resolve the cluster by NAME, then ``services/permission.bind``
        (synchronous apply, ADR-0008). The service's errors are already the
        stable codes — propagate, don't wrap. The audit row is written by
        the service (no double-audit here)."""
        require_admin()
        cluster = _cluster_by_name_or_404(str(args["cluster"]))
        namespace = args.get("namespace")
        assert namespace is None or isinstance(namespace, str)
        binding = permission.bind(
            user_sub=str(args["user"]),
            cluster_id=cluster.id,
            namespace=namespace,
            template_name=str(args.get("template") or ""),
            actor_sub=g.current_user.sub,
            db_session=db.session,
            k8s=kc.pool.get(cluster),
        )
        namespace = binding.namespace
        assert namespace is None or isinstance(namespace, str)
        return {
            "cluster": cluster.name,
            "namespace": namespace,
            "template": binding.template,
            "created_at": binding.created_at,
        }

    @blp.route("/admin/permissions/bind", methods=["DELETE"])
    @blp.arguments(BindIn)
    @blp.doc(responses={
        403: "RBAC_DENIED",
        404: "CLUSTER_NOT_FOUND / NO_BINDINGS",
        502: "CLUSTER_UNREACHABLE",
    })
    def unbind(self, args: dict[str, object]) -> dict[str, object]:
        """Resolve the cluster by NAME, then ``services/permission.unbind``
        (RoleBinding delete + Role GC). Propagates ``NoBindingsError`` (404)
        etc. The audit row is written by the service."""
        require_admin()
        cluster = _cluster_by_name_or_404(str(args["cluster"]))
        namespace = args.get("namespace")
        assert namespace is None or isinstance(namespace, str)
        permission.unbind(
            user_sub=str(args.get("user") or ""),
            cluster_id=cluster.id,
            namespace=namespace,
            actor_sub=g.current_user.sub,
            db_session=db.session,
            k8s=kc.pool.get(cluster),
        )
        return {"deleted": True}

    # ------------------------------------------------------------------
    # My access (R5) — ANY authenticated user, NOT admin-gated
    # ------------------------------------------------------------------

    @blp.route("/permissions/my-access", methods=["GET"])
    @blp.doc(
        responses={
            200: ("The caller's bindings (bare list, BindingOut items); [] when none.", None),
            401: "UNAUTHORIZED",
        }
    )
    def my_access(self) -> object:
        """R5: the CALLER's bindings only — never another user's. ``[]``
        (not a 404) when the caller has none. No admin gate."""
        user = g.current_user
        rows = (
            db.session.execute(
                db.select(ClusterBinding, Cluster.name)
                .join(Cluster, ClusterBinding.cluster_id == Cluster.id)
                .filter(ClusterBinding.user_id == user.id)
                .order_by(ClusterBinding.id)
            )
        ).all()
        items = [
            {
                "cluster": cluster_name,
                "namespace": b.namespace,
                "template": b.template,
                "created_at": b.created_at,
            }
            for b, cluster_name in rows
        ]
        return jsonify(items), 200

    @blp.route("/admin/permissions/users/<user_sub>/bindings", methods=["GET"])
    @blp.doc(
        responses={
            200: ("The user's bindings (bare list, BindingOut items); [] when none.", None),
            403: "RBAC_DENIED",
            404: "RESOURCE_KIND_NOT_SUPPORTED (unknown user sub)",
        }
    )
    def list_user_bindings(self, user_sub: str) -> object:
        """Admin view of ANOTHER user's bindings — the surface
        ``/permissions/my-access`` deliberately withholds (R5 is caller-only).
        Admin-gated: a non-admin cannot enumerate someone else's grants."""
        require_admin()
        user = (
            db.session.execute(db.select(User).filter_by(sub=user_sub))
        ).scalar_one_or_none()
        if user is None:
            raise ResourceKindNotSupportedError(f"user {user_sub!r} not found")
        rows = (
            db.session.execute(
                db.select(ClusterBinding, Cluster.name)
                .join(Cluster, ClusterBinding.cluster_id == Cluster.id)
                .filter(ClusterBinding.user_id == user.id)
                .order_by(ClusterBinding.id)
            )
        ).all()
        items = [
            {
                "cluster": cluster_name,
                "namespace": b.namespace,
                "template": b.template,
                "created_at": b.created_at,
            }
            for b, cluster_name in rows
        ]
        return jsonify(items), 200
