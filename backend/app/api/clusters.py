"""ClusterApi (R3) — the encrypted-kubeconfig registry + per-cluster client
pool seam (ADR-0002, one-way-door).

``on_init`` carries the shared auth-hook pattern from Task 3's ``ClustersApi``
exemplar (now extracted to ``app/api/_authhook.py``): flask-smorest 0.47 has
no ``Api.on_before_request``, so the hook is registered app-wide on the real
app and scopes itself to the ``/api/v1/*`` domain routes.
"""
import yaml
from flask import g, jsonify
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import (
    ClusterAlreadyExistsError,
    ClusterUnreachableError,
    InvalidKubeconfigError,
)
from app.extensions import db
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.schemas.cluster import ClusterIn, ClusterOut, HealthOut
from app.services import k8s_client as kc
from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404, encrypt_kubeconfig


def _out(c: Cluster) -> dict[str, object]:
    return {
        "id": c.id,
        "name": c.name,
        "api_server": c.api_server,
        "context": c.context,
        "status": c.status,
        "last_probe_at": c.last_probe_at,
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
    def register_cluster(self, args: dict[str, object]) -> tuple[dict[str, object], int]:
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
        return _out(cluster), 201

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
        rows = (
            db.session.execute(
                db.select(Cluster)
                .join(ClusterBinding, ClusterBinding.cluster_id == Cluster.id)
                .filter(ClusterBinding.user_id == user.id)
                .order_by(Cluster.id)
            )
            .scalars()
            .all()
        )
        return jsonify([_out(c) for c in rows]), 200

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
