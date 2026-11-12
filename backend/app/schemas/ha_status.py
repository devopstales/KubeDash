"""HA Status response schema (spec 2026-11-10-ha-status-page).

Match the ``app/schemas/permissions.py`` style: plain marshmallow ``Schema``
classes, docs-only where the response is a bare dict (smorest dumps handler
returns THROUGH the response schema).
"""
from marshmallow import Schema, fields


class SubStatusOut(Schema):
    """One local subscription's replication state (per node)."""

    name = fields.String()
    status = fields.String()


class NodeOut(Schema):
    """One cluster member's probe result. ``dsn`` is host:port only — the
    full DSN carries credentials and must not reach the UI."""

    name = fields.String()
    reachable = fields.Bool()
    probe_error = fields.String(allow_none=True)
    sub_statuses = fields.List(fields.Nested(SubStatusOut))
    lag_bytes = fields.Int()
    lag_interval_s = fields.Float()
    apply_workers = fields.Int()
    workers_streaming = fields.Bool()
    conflicts = fields.Int()
    exceptions_pending = fields.Int()
    lock_held_locally = fields.Bool()
    lock_holder_pid = fields.Int(allow_none=True)
    lock_holder_state = fields.String(allow_none=True)
    elapsed_ms = fields.Int()
    dsn = fields.String()


class LeaderOut(Schema):
    """The leader election state (one lease row + the aggregated lock
    verdict + the best-effort candidate count)."""

    replica_id = fields.String()
    fence = fields.Int()
    heartbeat_age_s = fields.Float()
    lock_verdict = fields.String()
    token = fields.String(allow_none=True)
    acquired_at = fields.String(allow_none=True)
    renew_at = fields.String(allow_none=True)
    lease_duration_s = fields.Float()
    candidates = fields.Int(allow_none=True)


class QueueOut(Schema):
    """The ``tasks`` queue state (counts by status + oldest pending)."""

    pending = fields.Int()
    processing = fields.Int()
    done = fields.Int()
    oldest_pending_at = fields.String(allow_none=True)


class SectionOut(Schema):
    """One failure domain's derived verdict."""

    status = fields.String()
    reasons = fields.List(fields.String())


class HaStatusOut(Schema):
    """The full HA report — two sections (database HA + KubeDash leader
    election), overall status = worst section, reasons = all, database
    first. A sick cluster is a 200 with ``reachable: false`` nodes, never
    a 500 (acceptance)."""

    probed_at = fields.String()
    spock_version = fields.String()
    nodes = fields.List(fields.Nested(NodeOut))
    leader = fields.Nested(LeaderOut)
    queue = fields.Nested(QueueOut)
    status = fields.String()
    reasons = fields.List(fields.String())
    database = fields.Nested(SectionOut)
    election = fields.Nested(SectionOut)
