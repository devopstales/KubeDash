"""ClusterApi (R3) — the encrypted-kubeconfig registry + per-cluster client
pool seam (ADR-0002, one-way-door).

``on_init`` carries the shared auth-hook pattern from Task 3's ``ClustersApi``
exemplar (now extracted to ``app/api/_authhook.py``): flask-smorest 0.47 has
no ``Api.on_before_request``, so the hook is registered app-wide on the real
app and scopes itself to the ``/api/v1/*`` domain routes.
"""
from typing import Any

import yaml
from flask import g, jsonify
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.config import get_settings
from app.core.errors import (
    ClusterAlreadyExistsError,
    ClusterNotFoundError,
    ClusterUnreachableError,
    InvalidKubeconfigError,
    RbacDeniedError,
)
from app.extensions import db
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.schemas.cluster import ClusterIn, ClusterOut, ClusterUpdate, HealthOut
from app.services import k8s_client as kc
from app.services.k8s_client import (
    LOCAL_CLUSTER_ID,
    bound_cluster_or_404,
    encrypt_kubeconfig,
    resolve_admin_source,
)


def _out(c: Cluster) -> dict[str, object]:
    return {
        "id": c.id,
        "name": c.name,
        "api_server": c.api_server,
        "context": c.context,
        "status": c.status,
        "last_probe_at": c.last_probe_at,
        # TICKET-16: every REAL registry row is source "registry" (the list's
        # synthetic admin entry is source "admin" — the literal is built in
        # list_clusters, not here).
        "source": "registry",
    }


def _local_cluster() -> Cluster:
    """The synthetic local cluster (ADR-0021): the cluster KubeDash runs in.

    No ``clusters`` row exists for id 0, so ``bound_cluster_or_404`` would
    404 first — the synthetic object bypasses the binding gate and goes
    straight to ``pool.get``, whose internal ``id: 0`` branch routes to the
    admin client or raises ``ClusterNotFoundError`` for non-admins.
    """
    return Cluster(
        id=LOCAL_CLUSTER_ID,
        name="local",
        api_server="local",
        kubeconfig_enc=b"",
        context=None,
    )


def _require_cluster_admin(user: Any, cluster_id: int, action: str) -> None:
    """PUT/DELETE gate: the caller must be a platform admin OR hold an
    ``"admin"`` binding on this cluster (the registering user's
    auto-binding). ``.first()`` — a duplicated admin binding row must not
    500 the gate query."""
    has_admin_binding = (
        db.session.execute(
            db.select(ClusterBinding).filter_by(
                user_id=user.id, cluster_id=cluster_id, role="admin"
            )
        )
        .first()
        is not None
    )
    if user.role != "admin" and not has_admin_binding:
        raise RbacDeniedError(f"only the cluster admin or a platform admin can {action}")


class ClusterApi(Api):
    """The real ``/api/v1/clusters`` routes — replaces the Task 3 stub."""

    resources_namespace = "clusters"
    tags = ["Clusters"]
    blp = Blueprint("clusters", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        # The shared auth-hook pattern (app-wide before_request scoped to
        # /api/v1/* domain routes, skipping /api/v1/auth/*): flask-smorest
        # 0.47 has no Api.on_before_request, so it binds on the real app and
        # scopes itself; Flask deduplicates the shared _check across every
        # domain Api's on_init.
        apply_auth(app)

    @blp.route("/clusters", methods=["POST"])
    @blp.arguments(ClusterIn)
    @blp.response(201, ClusterOut)
    @blp.doc(responses={409: "CLUSTER_ALREADY_EXISTS", 422: "INVALID_KUBECONFIG"})
    def register_cluster(self, args: dict[str, object]) -> object:
        user = g.current_user
        # 422 first: an unparseable kubeconfig is stored NOTHING (briefing
        # edge case) — validation precedes the duplicate-name check.
        try:
            doc = yaml.safe_load(str(args["kubeconfig"]))
        except yaml.YAMLError as e:
            raise InvalidKubeconfigError("kubeconfig is not valid YAML") from e
        if not isinstance(doc, dict):
            raise InvalidKubeconfigError("kubeconfig must be a YAML mapping")
        # 409: the name is unique across the registry, not per user.
        exists = db.session.execute(
            db.select(Cluster).filter_by(name=str(args["name"]))
        ).scalar_one_or_none()
        if exists is not None:
            raise ClusterAlreadyExistsError(f"cluster {args['name']!r} already exists")
        cluster = Cluster(
            name=str(args["name"]),
            api_server=str(args["api_server"]),
            # OD-2: the ONLY form that ever reaches the database.
            kubeconfig_enc=encrypt_kubeconfig(str(args["kubeconfig"]).encode()),
            context=str(args["context"]),
        )
        db.session.add(cluster)
        db.session.flush()
        # Auto-bind: the registering user owns the cluster they registered.
        db.session.add(ClusterBinding(user_id=user.id, cluster_id=cluster.id, role="admin"))
        db.session.commit()
        # Location header per the REST convention for 201 Created.
        resp = jsonify(_out(cluster))
        resp.status_code = 201
        resp.headers["Location"] = f"/api/v1/clusters/{cluster.id}"
        return resp

    @blp.route("/clusters", methods=["GET"])
    # ponytail: smorest dumps the handler's return value THROUGH the response
    # schema (a zero-field schema would marshal a list to {}), and the OpenAPI
    # spec wants a typed 200 — so the response is documented via @blp.doc and
    # the bare list is returned directly (docs-only, no dump).
    @blp.doc(
        responses={
            200: ("Caller's bound clusters (bare list).", None),
            401: "UNAUTHORIZED",
        }
    )
    def list_clusters(self) -> object:
        """Only the caller's bound clusters — the binding gate (R3)."""
        user = g.current_user
        # Role per cluster: a user may hold MULTIPLE bindings (template
        # grants 'viewer', registering auto-binds 'admin') — the highest role
        # wins; it drives the UI's manage-button gating (the API enforces it
        # independently on mutations, so this is never a trust boundary).
        role_map: dict[int, str] = {}
        for cid, role in db.session.execute(
            db.select(ClusterBinding.cluster_id, ClusterBinding.role).filter_by(
                user_id=user.id
            )
        ).all():
            if role == "admin" or cid not in role_map:
                role_map[cid] = role
        rows = (
            db.session.execute(
                db.select(Cluster)
                .where(
                    Cluster.id.in_(
                        db.select(ClusterBinding.cluster_id).filter_by(user_id=user.id)
                    )
                )
                .order_by(Cluster.id)
            )
            .scalars()
            .all()
        )
        items = [{**_out(c), "role": role_map.get(c.id)} for c in rows]
        if user.role == "admin":
            # ADR-0021 (TICKET-16): the synthetic local cluster — the cluster
            # KubeDash runs in (OD-D, reserved id 0). This block is the
            # visibility seam: permission management later extends it
            # (e.g. per-cluster binding status) without touching the pool.
            # I13: api_server is the RESOLVED source — the file path in
            # kubeconfig-file mode (the literal, not the resolve_admin_source
            # tag), "in-cluster" in in-cluster mode.
            s = get_settings()
            # I13: api_server is the RESOLVED source — the explicit file path
            # in kubeconfig-file mode, the default kubeconfig path in
            # local-kubeconfig mode (main's probe), "in-cluster" in in-cluster
            # mode. Status is probed via the admin client's readyz (5 s cap).
            src = resolve_admin_source(s)
            if src == "kubeconfig-file":
                api_server = s.admin_kubeconfig
            elif src == "local-kubeconfig":
                import os

                api_server = os.environ.get(
                    "KUBECONFIG", os.path.expanduser("~/.kube/config")
                )
            else:
                api_server = "in-cluster"
            # Probe the admin client for a live status (up / down). The pool's
            # id-0 branch builds the admin client (cached after first call).
            try:
                client = kc.pool.get(_local_cluster())
                status = "up" if client.readyz() else "down"
            except Exception:
                status = "down"
            items.insert(
                0,
                {
                    "id": LOCAL_CLUSTER_ID,
                    "name": "local",
                    "api_server": api_server,
                    "context": None,
                    "status": status,
                    "last_probe_at": None,
                    "source": "admin",
                    "role": "admin",
                },
            )
        return jsonify(items), 200

    @blp.route("/clusters/<int:cluster_id>", methods=["GET"])
    @blp.response(200, ClusterOut)
    @blp.doc(responses={404: "CLUSTER_NOT_FOUND"})
    def get_cluster(self, cluster_id: int) -> dict[str, object]:
        if cluster_id == LOCAL_CLUSTER_ID:
            # id 0: the synthetic local cluster — the pool's role gate IS the
            # gate (non-admin → CLUSTER_NOT_FOUND), no binding lookup. The
            # gate call must precede the answer: without it a non-admin gets
            # 200 on the synthetic row. The returned client is NOT used in
            # the payload — the row is answered from the synthetic object.
            kc.pool.get(_local_cluster())
            return _out(_local_cluster())
        cluster = bound_cluster_or_404(g.current_user, cluster_id)
        return _out(cluster)

    @blp.route("/clusters/<int:cluster_id>", methods=["PUT"])
    @blp.arguments(ClusterUpdate)
    @blp.response(200, ClusterOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED",
            404: "CLUSTER_NOT_FOUND",
            409: "CLUSTER_ALREADY_EXISTS",
            422: "INVALID_KUBECONFIG",
        }
    )
    def update_cluster(self, args: dict[str, object], cluster_id: int) -> dict[str, object]:
        """Update a registered cluster (4.1 `settings/cluster-config` parity).

        The synthetic local cluster (id 0) is not a registry row and is not
        editable. Same gate as delete: platform admin or the cluster's
        registering admin (binding role == "admin"). ``kubeconfig`` omitted
        or empty keeps the stored ciphertext; a supplied document is
        validated before ANY field is written.
        """
        if cluster_id == LOCAL_CLUSTER_ID:
            raise ClusterNotFoundError("synthetic local cluster is not editable")
        user = g.current_user
        # Gate FIRST (F020): a platform admin without a binding must reach
        # the gate — the strict binding lookup would 404 them before the
        # role branch is consulted. The 404 for a missing row follows the
        # gate (a non-admin gets 403, which leaks nothing either).
        _require_cluster_admin(user, cluster_id, "update")
        cluster = db.session.get(Cluster, cluster_id)
        if cluster is None:
            raise ClusterNotFoundError("cluster not found")
        name = str(args["name"])
        duplicate = db.session.execute(
            db.select(Cluster).filter(Cluster.name == name, Cluster.id != cluster.id)
        ).scalar_one_or_none()
        if duplicate is not None:
            raise ClusterAlreadyExistsError(f"cluster {name!r} already exists")
        kubeconfig = args.get("kubeconfig")
        if kubeconfig:
            try:
                doc = yaml.safe_load(str(kubeconfig))
            except yaml.YAMLError as e:
                raise InvalidKubeconfigError("kubeconfig is not valid YAML") from e
            if not isinstance(doc, dict):
                raise InvalidKubeconfigError("kubeconfig must be a YAML mapping")
        # Validation passed: apply every field in one commit (no partial row).
        cluster.name = name
        cluster.api_server = str(args["api_server"])
        cluster.context = str(args["context"])
        if kubeconfig:
            cluster.kubeconfig_enc = encrypt_kubeconfig(str(kubeconfig).encode())
        db.session.commit()
        # A rotated kubeconfig / changed api_server must not keep serving
        # through a cached client.
        kc.pool.invalidate(cluster.id)
        return _out(cluster)

    @blp.route("/clusters/<int:cluster_id>", methods=["DELETE"])
    @blp.doc(responses={404: "CLUSTER_NOT_FOUND", 403: "RBAC_DENIED"})
    def delete_cluster(self, cluster_id: int) -> object:
        """Delete a registered cluster and its bindings.

        The synthetic local cluster (id 0) is not deletable — it is the
        cluster KubeDash runs in, not a registry row. Admin role or the
        cluster's registering admin (binding role == "admin") may delete.
        """
        if cluster_id == LOCAL_CLUSTER_ID:
            raise ClusterNotFoundError("synthetic local cluster is not deletable")
        user = g.current_user
        # Gate FIRST (F020): a platform admin without a binding must reach
        # the gate — the strict binding lookup would 404 them before the
        # role branch is consulted.
        _require_cluster_admin(user, cluster_id, "delete")
        cluster = db.session.get(Cluster, cluster_id)
        if cluster is None:
            raise ClusterNotFoundError("cluster not found")
        # Delete bindings first (FK constraint), then the cluster row.
        db.session.execute(
            db.delete(ClusterBinding).filter_by(cluster_id=cluster.id)
        )
        db.session.delete(cluster)
        db.session.commit()
        kc.pool.invalidate(cluster.id)
        return jsonify({"deleted": cluster.id}), 200

    @blp.route("/clusters/<int:cluster_id>/health", methods=["GET"])
    @blp.response(200, HealthOut)
    @blp.doc(responses={404: "CLUSTER_NOT_FOUND", 502: "CLUSTER_UNREACHABLE"})
    def cluster_health(self, cluster_id: int) -> dict[str, str]:
        if cluster_id == LOCAL_CLUSTER_ID:
            cluster = _local_cluster()
            # Non-admin: the pool's id-0 branch raises ClusterNotFoundError
            # (CLUSTER_NOT_FOUND) before any probe.
        else:
            cluster = bound_cluster_or_404(g.current_user, cluster_id)
        up = kc.pool.get(cluster).readyz()
        if not up:
            raise ClusterUnreachableError(f"cluster {cluster.name!r} /readyz failed")
        return {"status": "up"}
