"""Metrics summary response schema (Task 3).

The rollup shape is produced by the pure ``cluster_allocation.compute_summary``
(same dict, snake_case). ``used_*`` are nullable by the certainty rule: a
value the endpoint cannot read is ``None``, never ``0``. Overcommit is NOT
precomputed — the client derives it from the raw sums.
"""

from marshmallow import Schema, fields


class CpuSummary(Schema):
    capacity_millicores = fields.Integer()
    used_millicores = fields.Integer(allow_none=True)
    requests_millicores = fields.Integer()
    limits_millicores = fields.Integer()


class MemorySummary(Schema):
    capacity_bytes = fields.Integer()
    used_bytes = fields.Integer(allow_none=True)
    requests_bytes = fields.Integer()
    limits_bytes = fields.Integer()


class PodSummary(Schema):
    capacity = fields.Integer()
    running = fields.Integer()
    pending = fields.Integer()
    completed = fields.Integer()


class NodeMetricOut(Schema):
    """One row of ``GET /clusters/<id>/metrics/nodes``. Used fields are
    nullable (certainty rule): a node absent from the metrics list or the node
    list renders ``None``, never ``0``."""

    name = fields.String()
    cpu_used_millicores = fields.Integer(allow_none=True)
    cpu_capacity_millicores = fields.Integer(allow_none=True)
    memory_used_bytes = fields.Integer(allow_none=True)
    memory_capacity_bytes = fields.Integer(allow_none=True)


class NodeMetricsOut(Schema):
    """``GET /clusters/<id>/metrics/nodes`` — the per-node series for the node
    view (blueprint Task 3). ``metrics_available`` says whether the Metrics API
    answered; the source is fixed at ``metrics.k8s.io`` (ratified, ADR-0003)."""

    cluster = fields.String()
    metrics_available = fields.Boolean()
    source = fields.String()
    items = fields.List(fields.Nested(NodeMetricOut))


class PvcUsageItem(Schema):
    """One row of ``GET /clusters/<id>/metrics/pvcs`` — the PVC storage
    usage aggregated from the kubelet /stats/summary (4.1's
    ``k8sPVCMetric`` read). Bytes are raw (not KB); ``percentage_used`` is
    used / capacity * 100, ``0.0`` when capacity is zero (the 4.1
    division-by-zero guard)."""

    name = fields.String()
    capacity_bytes = fields.Integer()
    used_bytes = fields.Integer()
    available_bytes = fields.Integer()
    percentage_used = fields.Float()


class PvcUsageOut(Schema):
    """``GET /clusters/<id>/metrics/pvcs`` — the PVC-usage observed tier for
    the /storage/pvc list's Usage column. KUBELET stats/summary, NOT
    metrics.k8s.io (the ``source`` says which observed tier is missing).
    ``metrics_available`` says whether any node yielded stats (ADR-0003
    query-only: unavailable is 200 + false, never 500); ``metrics_denied``
    says whether the caller lacks the ``get nodes`` grant (distinct: the UI
    must not tell a denied user "install metrics-server")."""

    cluster = fields.String()
    namespace = fields.String()
    source = fields.String()
    metrics_available = fields.Boolean()
    metrics_denied = fields.Boolean()
    items = fields.List(fields.Nested(PvcUsageItem))


class NodeUsageOut(Schema):
    """``GET /clusters/<id>/nodes/<name>/usage`` — a single node's observed
    (used) tier. ``metrics_available`` says whether the Metrics API answered;
    ``metrics_denied`` whether the caller lacks the ``metrics.k8s.io`` grant
    (distinct: the UI must not tell a denied user "install metrics-server").
    ``used_*`` are nullable by the certainty rule: an absent metrics source or
    an unscraped node is ``None``, never ``0``."""

    metrics_available = fields.Boolean()
    metrics_denied = fields.Boolean()
    used_millicores = fields.Integer(allow_none=True)
    used_bytes = fields.Integer(allow_none=True)


class MetricsSummaryOut(Schema):
    """``GET /clusters/<id>/metrics/summary`` — the cluster-wide allocation
    rollup. ``metrics_available`` says whether the observed (used) tier came
    from the Metrics API; ``metrics_denied`` says whether the caller lacks
    the ``metrics.k8s.io`` read grant (a distinct state: the UI must not tell
    a denied user "install metrics-server"). Declared state is always present.

    ponytail: marshmallow 4.3.1 does not auto-instance a ``Schema`` subclass
    declared as a class attribute — the nested dump silently drops the key
    (response arrives with only the top-level scalar). ``fields.Nested`` with
    the class argument instantiates on access; if a marshmallow major bump
    revives plain-class nesting, drop the ``Nested`` wrappers.
    """

    metrics_available = fields.Boolean()
    metrics_denied = fields.Boolean()
    cpu = fields.Nested(CpuSummary)
    memory = fields.Nested(MemorySummary)
    pods = fields.Nested(PodSummary)
