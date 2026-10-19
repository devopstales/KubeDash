"""Permission service — per .skillgrid/artifacts/04-adr-0013-permission-management.md.

TICKET-03 (tracer core): ``bind``/``unbind`` apply the template's RBAC
objects in the target cluster (synchronous, ADR-0008) and keep the
``cluster_bindings`` row + the ``audit_log`` in lockstep. Pure Python — no
Flask imports: ``db_session`` is a SQLAlchemy session, ``k8s`` is a
``K8sClient`` for the target cluster, and audit rows are ``AuditLog``
appends on the SAME session (they commit atomically with the binding — no
separate recorder seam). Task 4's API layer passes the dependencies in.
"""
from typing import Any, cast

from app.core.errors import (
    ClusterNotFoundError,
    ClusterUnreachableError,
    InvalidKubeconfigError,
    NoBindingsError,
    ResourceKindNotSupportedError,
)
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.rbac_template import RBACTemplate
from app.models.user import User

#: ADR-0013: every object KubeDash applies/collects carries these labels.
TEMPLATE_LABEL = "kubedash.io/template"
USER_LABEL = "kubedash.io/user"


def _audit(db_session: Any, *, actor_sub: str, action: str, target: str,
           cluster: str, namespace: str | None, template: str | None) -> None:
    """Append an ``AuditLog`` row to the caller's session (committed atomically
    with the binding — the audit seam, per the brief's "pick one"). ``cluster``
    is the human-readable cluster name (bind); the unbind path passes the
    cluster id as a string (it only holds the id, not the name)."""
    db_session.add(AuditLog(
        action=action, actor_sub=actor_sub, target=target,
        cluster=cluster, namespace=namespace, template=template,
    ))


def bind(
    *,
    user_sub: str,
    cluster_id: int,
    namespace: str | None,
    template_name: str,
    actor_sub: str,
    db_session: Any,
    k8s: Any,
) -> ClusterBinding:
    """Bind a template to a user on a cluster (synchronous apply, ADR-0008).

    Order (the tracer core — do not reorder):
    1. resolve template/user/cluster → 404 (missing cluster →
       ``ClusterNotFoundError``; missing template/user →
       ``ResourceKindNotSupportedError``, the only other generic stable 404).
    2. scope guard → 422 ``InvalidKubeconfigError`` (the only stable 422).
    3. **idempotency check FIRST** — an existing (user, cluster, namespace,
       template) row is returned WITHOUT re-applying and WITHOUT a new audit
       row (200 no-op).
    4. apply Role + RoleBinding (or ClusterRole + ClusterRoleBinding) — a
       cluster failure maps to 502 ``ClusterUnreachableError`` and records
       NOTHING.
    5. commit the binding row + an ``audit_log`` bind row (same transaction).
    """
    # ponytail: the flask-sqlalchemy session proxy rejects a legacy Query in
    # execute() (ObjectNotExecutableError) — ``.statement`` lifts it back to
    # a 2.0 Select. (Tasks 1-2's k8s_client.py built the select() form
    # directly; both styles work in bare SQLAlchemy, only the proxy differs.)
    template = db_session.execute(
        db_session.query(RBACTemplate).filter_by(name=template_name).statement
    ).scalar_one_or_none()
    if template is None:
        raise ResourceKindNotSupportedError(f"template {template_name!r} not found")
    user = db_session.execute(
        db_session.query(User).filter_by(sub=user_sub).statement
    ).scalar_one_or_none()
    if user is None:
        raise ResourceKindNotSupportedError(f"user {user_sub!r} not found")
    cluster = db_session.get(Cluster, cluster_id)
    if cluster is None:
        raise ClusterNotFoundError("cluster not found")

    if template.scope == "cluster" and namespace is not None:
        raise InvalidKubeconfigError("cluster-scoped template; omit namespace")
    if template.scope == "namespace" and namespace is None:
        raise InvalidKubeconfigError("namespace-scoped template requires a namespace")

    existing = db_session.execute(
        db_session.query(ClusterBinding).filter_by(
            user_id=user.id, cluster_id=cluster_id, namespace=namespace,
            template=template_name,
        ).statement
    ).scalar_one_or_none()
    if existing is not None:
        # 200 no-op: no re-apply, no new audit row. (cast: the Any-typed
        # session returns Any; the row is a ClusterBinding by construction.)
        return cast(ClusterBinding, existing)

    role_name = f"kubedash-{template_name}"
    labels = {TEMPLATE_LABEL: template_name}
    binding_labels = {USER_LABEL: user_sub, TEMPLATE_LABEL: template_name}
    try:
        if namespace is not None:
            k8s.apply_role(namespace, role_name, template.rules, labels)
            k8s.apply_role_binding(
                namespace, f"kubedash-{user_sub}-{namespace}",
                role_name, user_sub, binding_labels,
            )
        else:
            k8s.apply_cluster_role(role_name, template.rules, labels)
            k8s.apply_cluster_role_binding(
                f"kubedash-{user_sub}-cluster", role_name, user_sub, binding_labels,
            )
    except ClusterUnreachableError:
        raise
    except Exception as e:
        raise ClusterUnreachableError("cluster unreachable during bind") from e

    binding = ClusterBinding(
        user_id=user.id, cluster_id=cluster_id, role="viewer",
        namespace=namespace, template=template_name,
    )
    db_session.add(binding)
    _audit(
        db_session, actor_sub=actor_sub, action="bind", target=user_sub,
        cluster=cluster.name, namespace=namespace, template=template_name,
    )
    db_session.commit()
    return binding


def unbind(
    *,
    user_sub: str,
    cluster_id: int,
    namespace: str | None,
    actor_sub: str,
    db_session: Any,
    k8s: Any,
) -> None:
    """Unbind a user from a cluster (Role GC, ADR-0013).

    Order: 1. find the row → 404 ``NoBindingsError``; 2. delete the
    RoleBinding (the scope the row was bound with is authoritative); 3. Role
    GC — delete the Role/ClusterRole only when no other binding on that
    (cluster, namespace-or-cluster) still references the same template;
    4. delete the row + audit, committed together.
    """
    binding = (
        db_session.query(ClusterBinding)
        .join(User, ClusterBinding.user_id == User.id)
        .filter(
            User.sub == user_sub,
            ClusterBinding.cluster_id == cluster_id,
            ClusterBinding.namespace == namespace,
        )
        .order_by(ClusterBinding.id.desc())
        .first()
    )
    if binding is None:
        raise NoBindingsError("no binding found")

    template = binding.template or "viewer"  # legacy rows bind the built-in viewer
    role_name = f"kubedash-{template}"
    try:
        if binding.namespace is not None:
            k8s.delete_role_binding(binding.namespace, f"kubedash-{user_sub}-{binding.namespace}")
        else:
            k8s.delete_cluster_role_binding(f"kubedash-{user_sub}-cluster")
        remaining = db_session.execute(
            db_session.query(ClusterBinding)
            .filter_by(cluster_id=cluster_id, namespace=binding.namespace, template=template)
            .filter(ClusterBinding.id != binding.id)
            .statement
        ).scalars().all()
        if not remaining:
            if binding.namespace is not None:
                k8s.delete_role(binding.namespace, role_name)
            else:
                k8s.delete_cluster_role(role_name)
    except ClusterUnreachableError:
        raise
    except Exception as e:
        raise ClusterUnreachableError("cluster unreachable during unbind") from e

    db_session.delete(binding)
    _audit(
        db_session, actor_sub=actor_sub, action="unbind", target=user_sub,
        cluster=str(cluster_id), namespace=binding.namespace, template=template,
    )
    db_session.commit()
