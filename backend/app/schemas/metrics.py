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
