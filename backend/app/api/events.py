"""Events — GET /api/v1/clusters/<id>/events (Task 4, R3).

Cluster-wide event read through the pool seam (ADR-0010's informer cache
interposes here later). The ADR-0004 enforcement point is ``rbac.can`` on
``list events`` (cluster-wide, namespace=None) — asked BEFORE any data
fetch, 403 RBAC_DENIED on deny.

Response is newest-first by ``last_timestamp`` desc; the endpoint's order
is authoritative (the frontend table renders it pre-sorted). Default limit
100 (the endpoint returns at most 100 events).
"""

from flask import g
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import RbacDeniedError
from app.services import rbac
from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404, pool

#: Default maximum events returned by the endpoint.
_DEFAULT_LIMIT = 100


def _cluster_for(user: object, cluster_id: int) -> object:
    if cluster_id == LOCAL_CLUSTER_ID:
        from app.api.clusters import _local_cluster

        return _local_cluster()
    return bound_cluster_or_404(user, cluster_id)


def _to_snake_case(item: dict) -> dict:
    """Map a single kubernetes ``to_dict()`` event to the EventOut shape.

    The kubernetes library already produces snake_case keys in ``to_dict()``
    (``lastTimestamp`` → ``last_timestamp``, ``involvedObject`` →
    ``involved_object``). This helper picks out the fields the endpoint
    contracts on, dropping anything else.
    """
    io = item.get("involvedObject") or item.get("involved_object") or {}
    return {
        "type": item.get("type", ""),
        "reason": item.get("reason", ""),
        "involved_object": {
            "kind": io.get("kind", ""),
            "name": io.get("name", ""),
            "namespace": io.get("namespace", ""),
        },
        "message": item.get("message", ""),
        "count": item.get("count"),
        "last_timestamp": item.get("lastTimestamp") or item.get("last_timestamp"),
    }


class EventsApi(Api):
    resources_namespace = "events"
    tags = ["Events"]
    blp = Blueprint("events", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        apply_auth(app)

    # ponytail: smorest dumps the handler's return value THROUGH the response
    # schema (a bare schema class would marshal a list to {}), so the response
    # is documented via @blp.doc and the bare list is returned directly
    # (docs-only, no dump). Same pattern as clusters.py list_clusters.
    @blp.route("/clusters/<int:cluster_id>/events", methods=["GET"])
    @blp.doc(
        responses={
            200: ("Cluster events, newest-first (EventOut list).", None),
            403: "RBAC_DENIED (no cluster-wide list events)",
            404: "CLUSTER_NOT_FOUND (binding gate)",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def list_events(self, cluster_id: int) -> list[dict[str, object]]:
        cluster = _cluster_for(g.current_user, cluster_id)
        # ADR-0004: cluster-wide list events gate, asked BEFORE any data
        # fetch — a denied user must not trigger a cluster call.
        if not rbac.can(g.current_user, cluster, "list", "events", None, None, ""):
            raise RbacDeniedError("list on events")
        items = pool.get(cluster).list_events(None)
        # Sort newest-first by last_timestamp desc (missing timestamp sorts
        # last). The endpoint's order is authoritative.
        items.sort(
            key=lambda e: e.get("lastTimestamp") or e.get("last_timestamp") or "",
            reverse=True,
        )
        return [_to_snake_case(e) for e in items[:_DEFAULT_LIMIT]]
