"""Permission service — per .skillgrid/artifacts/04-adr-0013-permission-management.md.

TICKET-03 (tracer core): ``bind``/``unbind`` apply the template's RBAC
objects in the target cluster (synchronous, ADR-0008) and keep the
``cluster_bindings`` row + the ``audit_log`` in lockstep. Pure Python — no
Flask imports: ``db_session`` is a SQLAlchemy session, ``k8s`` is a
``K8sClient`` for the target cluster, and audit rows are ``AuditLog``
appends on the SAME session (they commit atomically with the binding — no
separate recorder seam). Task 4's API layer passes the dependencies in.
"""
import base64
from typing import Any, cast

import yaml

from app.core.errors import (
    ClusterNotFoundError,
    ClusterUnreachableError,
    InternalError,
    InvalidKubeconfigError,
    NoBindingsError,
    ResourceKindNotSupportedError,
)
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.rbac_template import RBACTemplate
from app.models.user import User
from app.services import k8s_client
from app.services.kubeconfig_render import render_kubeconfig

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


# ---------------------------------------------------------------------------
# TICKET-05 (tracer 2) — self-service kubeconfig (ARCHITECTURE.md §5B,
# ADR-0011 / ADR-0002).
# ---------------------------------------------------------------------------


def _ca_from_kubeconfig(cluster_id: int, kubeconfig_enc: bytes) -> tuple[str, str]:
    """(server, ca_data_b64) from a registry cluster's encrypted kubeconfig.

    The CA comes from the DECRYPTED registry kubeconfig (ADR-0002) — never a
    stored column. CA cases, in order:
    1. ``certificate-authority-data`` — already base64, passed through.
    2. ``certificate-authority`` — a file PATH; the file's bytes are read and
       base64'd (a path relative to the registry kubeconfig is meaningless
       outside the server that wrote it, so it is read as given).
    3. neither — ``""`` (the renderer omits the CA field).

    The server is ``clusters[0].cluster.server`` (the registered kubeconfig is
    single-cluster — POST /clusters validates it via the kubernetes loader),
    falling back to the ``Cluster.api_server`` column.
    """
    from app.extensions import db  # ponytail: local import — the module-level
    # session model imports (binding/cluster/user) are needed by bind/unbind
    # at import time, but the db session proxy resolves the same way here.

    plain = k8s_client.decrypt_kubeconfig(kubeconfig_enc)
    doc = yaml.safe_load(plain.decode())
    assert isinstance(doc, dict)
    entry: dict[str, Any] = {}
    clusters = doc.get("clusters")
    if isinstance(clusters, list) and clusters:
        first = clusters[0]
        if isinstance(first, dict) and isinstance(first.get("cluster"), dict):
            entry = cast(dict[str, Any], first["cluster"])
    server = entry.get("server") or ""
    if not server:
        row = db.session.get(Cluster, cluster_id)
        server = row.api_server if row is not None else ""
    ca = entry.get("certificate-authority-data")
    if ca:
        return str(server), str(ca)
    ca_path = entry.get("certificate-authority")
    if ca_path:
        # ponytail: FileNotFoundError is a corrupt registry row, not a
        # request-time error class of its own — let it 500 through the
        # generic handler (no new stable code, per the brief).
        with open(str(ca_path), "rb") as f:
            return str(server), base64.b64encode(f.read()).decode()
    return str(server), ""


def generate_kubeconfig(
    *,
    user_sub: str,
    db_session: Any,
    settings: Any,
) -> str:
    """Render the caller's self-service kubeconfig (§5B) as a YAML string.

    Order: 1. load the user + their bindings → ``NoBindingsError`` (404)
    when there are none (a user with zero bindings has nothing to download);
    2. one cluster entry per DISTINCT bound cluster (decrypt + CA extraction,
    ``_ca_from_kubeconfig``); 3. one context PER BINDING (context name
    ``kubedash-<cluster.name>`` — same cluster, two namespaces → two
    contexts; a cluster-scoped binding omits ``namespace``); 4.
    ``render_kubeconfig`` — ``InternalError`` (500) when
    ``settings.plugin_server`` is None/empty (never emit an empty
    ``--server=``). Pure: no Flask imports, the session is passed in.
    """
    user = db_session.execute(
        db_session.query(User).filter_by(sub=user_sub).statement
    ).scalar_one_or_none()
    if user is None:
        # The auth hook already guarantees the row exists; a deleted row is a
        # missing-user 404, NOT a no-bindings one (the stable codes differ).
        raise NoBindingsError("no binding found")
    bindings = (
        db_session.query(ClusterBinding)
        .filter_by(user_id=user.id)
        .order_by(ClusterBinding.cluster_id, ClusterBinding.id)
        .all()
    )
    if not bindings:
        raise NoBindingsError("no binding found")

    # Distinct clusters, in binding order (first binding's cluster is first —
    # that is also current-context's cluster).
    cluster_ids: list[int] = []
    for b in bindings:
        if b.cluster_id not in cluster_ids:
            cluster_ids.append(b.cluster_id)
    cluster_rows = {
        c.id: c for c in db_session.execute(
            db_session.query(Cluster).filter(Cluster.id.in_(cluster_ids)).statement
        ).scalars().all()
    }

    plugin_server = settings.plugin_server
    if not plugin_server:
        raise InternalError("KUBEDASH_PLUGIN_SERVER is not set")

    clusters: list[dict[str, str]] = []
    contexts: list[dict[str, str]] = []
    for cid in cluster_ids:
        c = cluster_rows[cid]
        server, ca = _ca_from_kubeconfig(cid, c.kubeconfig_enc)
        name = f"kubedash-{c.name}"
        clusters.append({"name": name, "server": server, "ca_data_b64": ca})
    for b in bindings:
        # One context PER BINDING. Two bindings on the same cluster share the
        # context NAME (``kubedash-<cluster>``) but are distinct list entries
        # with their own namespace — kubectl resolves a context by name, so
        # the entries stay addressable by name and each namespace is present
        # in the file (the §5B shape, ARCHITECTURE.md: "one context per
        # cluster + namespace" rendered as one entry per binding).
        namespace = b.namespace or ""
        contexts.append(
            {"name": f"kubedash-{cluster_rows[b.cluster_id].name}", "namespace": namespace}
        )
    return render_kubeconfig(clusters, contexts, str(plugin_server))
