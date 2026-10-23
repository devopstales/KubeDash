"""Metrics — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md
(ADR-0003). The Prometheus query/query_range clients land with the
observability change; the stub routes keep 501 NOT_IMPLEMENTED.

``GET /clusters/<id>/metrics/summary`` is the cluster dashboard's allocation
rollup (Task 3). It is a DERIVED count, so the ADR-0004 enforcement point is a
two-tier gate on the rollup itself — a derived value must never be readable by
a user who cannot see the underlying resources:

- Tier 1 (whole summary): cluster-wide ``list pods`` AND ``list nodes``
  (namespace=None, matching the cluster-wide fetch). Denied -> 403
  RBAC_DENIED; a per-namespace-only user is 403 by design (tested).
- Tier 2 (used only): ``get nodes`` on group ``metrics.k8s.io``. Denied ->
  still 200, ``metrics_denied: true``, ``metrics_available: false``,
  ``used:*`` null — declared requests/limits/capacity stay present (they come
  from pods/nodes, not from the Metrics API).

The two flags are distinct by design (OWASP A05/A10, data integrity): the
endpoint must not tell an operator "install metrics-server" when the real
state is "you lack the metrics.k8s.io read grant". ``metrics_denied`` is the
SAR verdict for the used tier; ``metrics_available`` is the Metrics API's
health as seen by the caller.

Certainty rule (AGENTS.md): a Metrics API 404/5xx is the EXPECTED state, not
an error — ``node_usage`` answers ``(False, {})`` and the endpoint answers 200
with ``metrics_available: false`` and null used. Never 500, never 0.
"""

from flask import g
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.api._cluster import cluster_for as _cluster_for
from app.core.errors import NotImplementedError_, RbacDeniedError
from app.schemas.metrics import MetricsSummaryOut, NodeMetricsOut, NodeUsageOut
from app.services import rbac
from app.services.cluster_allocation import compute_summary
from app.services.k8s_client import pool

blp = Blueprint("metrics", __name__, url_prefix="/v1")


class MetricsApi(Api):
    resources_namespace = "metrics"
    tags = ["Metrics"]
    blp = blp  # register_apis registers instance.blp

    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/metrics/query", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def query(self) -> object:
        raise NotImplementedError_("metrics query not implemented in base structure")

    @blp.route("/metrics/query_range", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def query_range(self) -> object:
        raise NotImplementedError_("metrics query_range not implemented in base structure")

    @blp.route("/clusters/<int:cluster_id>/metrics/summary", methods=["GET"])
    @blp.response(200, MetricsSummaryOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED (no cluster-wide list pods/nodes)",
            404: "CLUSTER_NOT_FOUND (binding gate)",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def summary(self, cluster_id: int) -> dict[str, object]:
        cluster = _cluster_for(g.current_user, cluster_id)
        user = g.current_user
        # Tier 1 — the rollup is derived from BOTH lists, so both cluster-wide
        # grants are required (ADR-0004). Ask BEFORE any data fetch: on deny
        # no count of either kind may be computed.
        if not rbac.can(user, cluster, "list", "pods", None, None, ""):
            raise RbacDeniedError("list on pods")
        if not rbac.can(user, cluster, "list", "nodes", None, None, ""):
            raise RbacDeniedError("list on nodes")
        client = pool.get(cluster)
        nodes = client.list_nodes(None)
        pods = client.list_pods(None)
        # Tier 2 — used is a distinct source with its own gate: if the user
        # cannot read metrics.k8s.io nodes, usage is neither fetched nor
        # rendered (unknown, never 0). Declared state is unaffected.
        # ``metrics_denied`` is the SAR verdict for this tier; it is reported
        # separately from the Metrics API's health so the UI can say "you lack
        # the grant" instead of "install metrics-server" (see module docstring).
        metrics_allowed = rbac.can(user, cluster, "get", "nodes", None, None, "metrics.k8s.io")
        if metrics_allowed:
            available, usage = client.node_usage()
        else:
            available, usage = False, {}
        summary = compute_summary(nodes, pods, usage if available else None)
        return {"metrics_available": available, "metrics_denied": not metrics_allowed, **summary}

    @blp.route("/clusters/<int:cluster_id>/metrics/nodes", methods=["GET"])
    @blp.response(200, NodeMetricsOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED (no get nodes on metrics.k8s.io)",
            404: "CLUSTER_NOT_FOUND (binding gate)",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def node_metrics(self, cluster_id: int) -> dict[str, object]:
        """The per-node CPU/memory series for the node view (blueprint Task 3).

        The node table's used tier joins this to ``/resources/nodes`` by node
        name. Gated on ``get nodes`` on ``metrics.k8s.io`` (tier 2 of the
        ADR-0004 two-tier gate): a user without the grant sees ``unknown``
        used, not a 403 on the table (declared state still renders). The
        Metrics API's health is reported as ``metrics_available`` — an absent
        metrics-server is 200 with ``metrics_available: false``, never 500.
        """
        cluster = _cluster_for(g.current_user, cluster_id)
        metrics_allowed = rbac.can(
            g.current_user, cluster, "get", "nodes", None, None, "metrics.k8s.io"
        )
        if not metrics_allowed:
            return {
                "cluster": cluster.name,
                "metrics_available": False,
                "source": "metrics.k8s.io",
                "items": [],
            }
        available, items = pool.get(cluster).node_metrics()
        return {
            "cluster": cluster.name,
            "metrics_available": available,
            "source": "metrics.k8s.io",
            "items": items,
        }

    @blp.route("/clusters/<int:cluster_id>/nodes/<path:node_name>/usage", methods=["GET"])
    @blp.response(200, NodeUsageOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED (no metrics.k8s.io read)",
            404: "CLUSTER_NOT_FOUND (binding gate)",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def node_usage(self, cluster_id: int, node_name: str) -> dict[str, object]:
        """A single node's observed (used) tier for the node detail view.

        Tier 2 of the ADR-0004 two-tier gate, in isolation: ``get`` on
        ``metrics.k8s.io`` nodes. Denied -> 200 with ``metrics_denied: true``
        and null used (never 403 — the node's declared state still renders,
        and the used tier degrades to unknown, not error). The Metrics API's
        health is reported separately as ``metrics_available`` (certainty
        rule: a missing metrics-server is expected, not an error).
        """
        cluster = _cluster_for(g.current_user, cluster_id)
        metrics_allowed = rbac.can(
            g.current_user, cluster, "get", "nodes", None, None, "metrics.k8s.io"
        )
        if not metrics_allowed:
            return {
                "metrics_available": False,
                "metrics_denied": True,
                "used_millicores": None,
                "used_bytes": None,
            }
        available, usage = pool.get(cluster).node_usage(node_name)
        return {
            "metrics_available": available,
            "metrics_denied": False,
            "used_millicores": usage.get("cpu_millicores") if usage else None,
            "used_bytes": usage.get("memory_bytes") if usage else None,
        }
