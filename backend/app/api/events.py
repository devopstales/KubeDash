"""Events — GET /api/v1/clusters/<id>/events (Task 4, R3).

Cluster-wide event read through the pool seam (ADR-0010's informer cache
interposes here later). The ADR-0004 enforcement point is ``rbac.can`` on
``list events`` (cluster-wide, namespace=None) — asked BEFORE any data
fetch, 403 RBAC_DENIED on deny.

The documented response contract is ``EventOut`` (schemas/events.py) —
docs-only: the runtime payload is a bare list (the smorest dump limitation
below), so ``EventOut`` never runs at request time; it is the typed shape
the OpenAPI spec shows for this route.

Response is newest-first by ``last_timestamp`` desc; the endpoint's order
is authoritative (the frontend table renders it pre-sorted). Default limit
100 (the endpoint returns at most 100 events).
"""

from flask import g
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import RbacDeniedError
from app.schemas.events import EventOut  # noqa: F401 — docs-only OpenAPI contract
from app.services import rbac
from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404, pool

#: Default maximum events returned by the endpoint.
_DEFAULT_LIMIT = 100


def _cluster_for(user: object, cluster_id: int) -> object:
    if cluster_id == LOCAL_CLUSTER_ID:
        from app.api.clusters import _local_cluster

        return _local_cluster()
    return bound_cluster_or_404(user, cluster_id)


def _to_event_out(item: dict) -> dict:
    """Map one ``CoreV1Event.to_dict()`` item to the ``EventOut`` contract.

    kubernetes 37.0.1's ``to_dict()`` emits snake_case keys
    (``last_timestamp``, ``involved_object``) and a ``datetime`` for
    ``last_timestamp`` — which Flask's jsonify serializes to an RFC-1123
    string in the wire payload. This helper picks out the ``EventOut``
    fields, dropping everything else.
    """
    io = item.get("involved_object") or {}
    return {
        "type": item.get("type") or "",
        "reason": item.get("reason") or "",
        "involved_object": {
            "kind": io.get("kind") or "",
            "name": io.get("name") or "",
            "namespace": io.get("namespace") or "",
        },
        "message": item.get("message") or "",
        "count": item.get("count"),
        "last_timestamp": item.get("last_timestamp"),
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
    # (docs-only, no dump). Same pattern as clusters.py list_clusters —
    # EventOut is the documented item contract, not a runtime serializer.
    @blp.route("/clusters/<int:cluster_id>/events", methods=["GET"])
    @blp.doc(
        responses={
            200: ("Cluster events, newest-first (bare list of EventOut items).", None),
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
        # last). The client's to_dict() form carries a datetime — isoformat()
        # is the comparable canonical form (lexicographic == chronological for
        # aware UTC datetimes); a mixed datetime/str key would TypeError.
        # The endpoint's order is authoritative.
        def _ts_key(item: dict) -> str:
            ts = item.get("last_timestamp")
            if ts is None:
                return ""
            return ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

        items.sort(key=_ts_key, reverse=True)
        return [_to_event_out(e) for e in items[:_DEFAULT_LIMIT]]
