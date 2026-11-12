"""HA Status — pgEdge active-active health + KubeDash leader election.

Read-only report for the ``/settings/cluster-status`` admin page (spec
2026-11-10-ha-status-page). Two failure domains, derived separately:

- **Database HA** (pgEdge/Spock): per-node reachability, both replication
  directions (each node exposes only its receive direction — one
  ``spock.lag_tracker`` row per node), apply workers, conflicts, exceptions.
- **KubeDash HA** (leader election): ``leader_lease`` freshness + the
  advisory-lock cross-check (F12-F14: the session-local lock is only
  visible from the node hosting the leader's session, so the verdict
  aggregates per-node lock sightings; "not seen while a node is
  unreachable" is NOT an alarm).

The SQL is lifted verbatim from prototype 001
(``.skillgrid/meta/.prototype/001-spock-probe-visibility/probe.py``),
validated against pgEdge/Spock 5.0.1 on the dev cluster 2026-11-10; the
pure derivation came from ``modules/ha_derive.py`` in the spec folder.
Flask-free (the ``app/services/`` seam rule): the app engine arrives from
the call site, each node probe opens a short-lived read-only engine.

**Read-only invariant**: every statement here is SELECT / function call —
an app write would replicate under ``autoddl`` (briefing R6).
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine

LAG_EXCEEDED_S = 60.0
HEARTBEAT_STALE_S = 10.0
PROBE_TIMEOUT_S = 3.0
# The leader lease's duration: ``Leader(stale_seconds=10)``
# (app/core/leader.py) is the Kubernetes Lease ``leaseDurationSeconds``
# analogue — a follower may take over once the heartbeat is older than this.
# Kept here (not imported: app/services is Flask-free and leader.py imports
# Flask). Update both if the election timing changes.
LEASE_DURATION_S = 10.0

# --- probe SQL (prototype 001, validated 2026-11-10) ------------------------
_LOCAL_NODE_SQL = (
    "SELECT n.node_name FROM spock.local_node l "
    "JOIN spock.node n ON n.node_id = l.node_id"
)
_SUBSCRIPTIONS_SQL = "SELECT sub_name FROM spock.subscription"
_SUB_STATUS_SQL = (
    "SELECT subscription_name, status, provider_node, slot_name "
    "FROM spock.sub_show_status(:name)"
)
_LAG_SQL = (
    "SELECT origin_name, receiver_name, replication_lag_bytes, "
    "replication_lag FROM spock.lag_tracker"
)
_APPLY_WORKERS_SQL = (
    "SELECT worker_pid, worker_subid, worker_status "
    "FROM spock.get_apply_worker_status()"
)
_CHANNEL_TOTALS_SQL = (
    "SELECT coalesce(sum(n_tup_ins),0) ins, coalesce(sum(n_tup_upd),0) upd, "
    "coalesce(sum(n_tup_del),0) dels, coalesce(sum(n_conflict),0) conflicts, "
    "coalesce(sum(n_dca),0) dca FROM spock.get_channel_stats()"
)
_EXCEPTIONS_SQL = (
    "SELECT count(*) n, coalesce(max(retry_errored_at), "
    "min(remote_commit_ts)) last FROM spock.exception_status"
)
# The leader's session-local advisory lock: pg_advisory_lock(hashtext(rid))
# (single-integer form — app/core/leader.py) surfaces as classid = 4294967295
# (0xFFFFFFFF as oid), objid = hashtext(rid), objsubid = 1.
_LOCK_SQL = (
    "SELECT l.pid, l.granted, a.state FROM pg_locks l "
    "JOIN pg_stat_activity a ON a.pid = l.pid "
    "WHERE l.locktype = 'advisory' AND l.classid = 4294967295::oid "
    "AND l.objid = hashtext(:rid)::oid AND l.objsubid = 1"
)

# --- catalog SQL (one read on the app's own node) ---------------------------
_VERSION_SQL = "SELECT spock.spock_version()"
_MEMBERS_SQL = "SELECT node_name FROM spock.node ORDER BY node_name"
_INTERFACES_SQL = "SELECT if_name, if_dsn FROM spock.node_interface"
_LEASE_SQL = (
    "SELECT replica_id, token, acquired_at, heartbeat_at, fence "
    "FROM leader_lease WHERE id = 1"
)
_QUEUE_SQL = "SELECT status, count(*), min(enqueued_at) FROM tasks GROUP BY status"

# KubeDash's own namespace for the best-effort candidates read (F14).
_NAMESPACE_FILE = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")

_ORDER = {"healthy": 0, "degraded": 1, "down": 2}


# --- derivation (lifted from prototype 001 modules/ha_derive.py) ------------


@dataclass(frozen=True)
class NodeProbeData:
    """One node's probe result.

    ``lag_bytes`` / ``lag_interval_s`` are for the direction INTO this node
    (the only direction a node exposes — every node carries exactly one
    receive-direction row).
    """

    node_name: str
    reachable: bool
    # connection_refused | timeout | auth | server_down | other:<Exc>
    probe_error: str | None = None
    # (subscription_name, status) per local subscription; empty when unreachable
    sub_statuses: tuple[tuple[str, str], ...] = ()
    lag_bytes: int = 0
    lag_interval_s: float = 0.0
    apply_workers: int = 0
    workers_streaming: bool = False
    conflicts: int = 0
    exceptions_pending: int = 0
    lock_held_locally: bool = False
    lock_holder_pid: int | None = None
    lock_holder_state: str | None = None
    elapsed_ms: int = 0


@dataclass(frozen=True)
class LeaseState:
    """The ``leader_lease`` row as read from the app engine (one read)."""

    present: bool
    replica_id: str | None = None
    fence: int | None = None
    heartbeat_age_s: float | None = None
    acquired_at: str | None = None


@dataclass(frozen=True)
class LeaderInfo:
    replica_id: str
    fence: int
    heartbeat_age_s: float
    lock_verdict: str  # "held on n1 (pid 7899, idle)" / "not seen on any reachable node" / ...


@dataclass(frozen=True)
class SectionDerivation:
    status: str  # "healthy" | "degraded" | "down"
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ElectionDerivation(SectionDerivation):
    leader: LeaderInfo | None = None


def _lock_verdict(nodes: list[NodeProbeData]) -> str:
    holders = [n for n in nodes if n.reachable and n.lock_held_locally]
    if holders:
        n = holders[0]
        return (
            f"held on {n.node_name} (pid {n.lock_holder_pid}, "
            f"{n.lock_holder_state or 'state unknown'})"
        )
    if any(n.reachable for n in nodes):
        return "not seen on any reachable node"
    return "no reachable node to check"


def derive_database_status(
    nodes: list[NodeProbeData],
    *,
    lag_exceeded_s: float = LAG_EXCEEDED_S,
) -> SectionDerivation:
    """Database HA: per-node reachability, replication, lag, exceptions."""
    reasons: list[str] = []
    worst = 0

    for n in nodes:
        if not n.reachable:
            worst = 2
            reasons.append(f"node_unreachable:{n.node_name}")
            continue
        for _sub_name, status in n.sub_statuses:
            if status != "replicating":
                worst = 2
                reasons.append(f"subscription_not_replicating:{n.node_name}")
                break
        if n.lag_bytes > 0 and n.lag_interval_s > lag_exceeded_s:
            worst = max(worst, 1)
            reasons.append(f"lag_exceeded:{n.node_name}")
        if n.exceptions_pending > 0:
            worst = max(worst, 1)
            reasons.append(f"exceptions_pending:{n.node_name}")

    return SectionDerivation(status=["healthy", "degraded", "down"][worst], reasons=tuple(reasons))


def derive_election_status(
    nodes: list[NodeProbeData],
    lease: LeaseState,
    *,
    heartbeat_stale_s: float = HEARTBEAT_STALE_S,
) -> ElectionDerivation:
    """KubeDash HA: leader lease freshness + advisory-lock cross-check.

    Lock-reason rules (F12-F14):
    - heartbeat FRESH: none seen with ALL nodes reachable ->
      lock_lease_mismatch; none seen while SOME node is unreachable -> NO
      alarm (the lock may sit on the unreachable node).
    - heartbeat STALE: lock seen on a reachable node -> lock_without_heartbeat
      (a wedged leader); lock not seen -> no_leader.
    Election failure is degraded, never down (fail-closed: no scheduled
    work, not a data-loss condition).
    """
    reasons: list[str] = []
    lock_line = _lock_verdict(nodes)

    if not lease.present:
        reasons.append("leader_lease_missing")
    elif lease.heartbeat_age_s is None or lease.heartbeat_age_s > heartbeat_stale_s:
        reasons.append("leader_heartbeat_stale")
        if lock_line.startswith("held on"):
            reasons.append("lock_without_heartbeat")
        elif lock_line == "not seen on any reachable node":
            reasons.append("no_leader")
    elif lock_line == "not seen on any reachable node" and all(n.reachable for n in nodes):
        reasons.append("lock_lease_mismatch")

    leader = LeaderInfo(
        lease.replica_id or "?",
        lease.fence if lease.fence is not None else 0,
        lease.heartbeat_age_s or 0.0,
        lock_line,
    )
    return ElectionDerivation(
        status="degraded" if reasons else "healthy",
        reasons=tuple(reasons),
        leader=leader,
    )


def derive_status(
    nodes: list[NodeProbeData],
    lease: LeaseState,
    *,
    lag_exceeded_s: float = LAG_EXCEEDED_S,
    heartbeat_stale_s: float = HEARTBEAT_STALE_S,
) -> dict[str, Any]:
    """Overall = worst of the two sections; reasons = all, database first."""
    database = derive_database_status(nodes, lag_exceeded_s=lag_exceeded_s)
    election = derive_election_status(nodes, lease, heartbeat_stale_s=heartbeat_stale_s)
    worst = max(_ORDER[database.status], _ORDER[election.status])
    leader = election.leader
    return {
        "status": ["healthy", "degraded", "down"][worst],
        "reasons": list(database.reasons + election.reasons),
        "database": {"status": database.status, "reasons": list(database.reasons)},
        "election": {"status": election.status, "reasons": list(election.reasons)},
        "leader": {
            "replica_id": leader.replica_id if leader is not None else "?",
            "fence": leader.fence if leader is not None else 0,
            "heartbeat_age_s": leader.heartbeat_age_s if leader is not None else 0.0,
            "lock_verdict": leader.lock_verdict if leader is not None else "",
        },
    }


# --- probe seam --------------------------------------------------------------


def classify_error(exc: BaseException) -> str:
    """Classify a probe failure (the point of the probe: a sick cluster
    reports ``reachable: false`` with a reason, never a 500)."""
    chain = [exc]
    while chain[-1].__cause__ is not None:
        chain.append(chain[-1].__cause__)
    for e in chain:
        if isinstance(e, ConnectionRefusedError):
            return "connection_refused"
        msg = str(e).lower()
        if isinstance(e, TimeoutError) or "timed out" in msg or "timeout" in msg:
            return "timeout"
        if "password" in msg or "insufficient" in msg or "auth" in msg:
            return "auth"
        if "connection refused" in msg:
            return "connection_refused"
        if "server closed" in msg or "connection reset" in msg or "broken pipe" in msg:
            return "server_down"
    return f"other:{type(exc).__name__}"


def _interval_to_seconds(iv: Any) -> float:
    """A Postgres ``interval`` -> seconds (float, 3 dp)."""
    if iv is None:
        return 0.0
    return float(round(iv.days * 86400 + iv.seconds + iv.microseconds / 1e6, 3))


def _probe_engine(dsn: str, timeout_s: float) -> Engine:
    """Short-lived probe engine for ``dsn``. ``spock.node_interface``
    stores DSNs in libpq KEYWORD format (``host=... dbname=... user=...
    port=...``), which ``create_engine`` rejects — so detect the shape:
    a URL (contains ``://``) passes through unchanged, a keyword string
    is parsed into a ``URL``. INI overrides (F8) are always URLs; the
    keyword path is the in-cluster default."""
    if "://" in dsn:
        return create_engine(dsn, connect_args={"connect_timeout": timeout_s})
    params: dict[str, str] = {}
    for part in dsn.split():
        key, sep, value = part.partition("=")
        if sep:
            params[key] = value
    url = URL.create(
        "postgresql",
        host=params.get("host"),
        port=int(params["port"]) if params.get("port") else None,
        database=params.get("dbname"),
        username=params.get("user"),
        password=params.get("password"),
    )
    return create_engine(url, connect_args={"connect_timeout": timeout_s})


def probe_node(dsn: str, replica_id: str, timeout_s: float = PROBE_TIMEOUT_S) -> NodeProbeData:
    """Probe one node: open a short-lived engine on its DSN, run the fixed
    read-only SQL set, close it. A failure is a RESULT (reachable=False +
    classified error), not an exception — the endpoint never 500s on the
    thing it is there to diagnose (acceptance: it degrades, it reports)."""
    t0 = time.monotonic()
    node = NodeProbeData(node_name="", reachable=False)
    engine = _probe_engine(dsn, timeout_s)
    try:
        with engine.connect() as conn:
            (row,) = conn.execute(text(_LOCAL_NODE_SQL)).fetchall()
            node_name = row[0]
            sub_statuses: list[tuple[str, str]] = []
            for (sub,) in conn.execute(text(_SUBSCRIPTIONS_SQL)).fetchall():
                for r in conn.execute(text(_SUB_STATUS_SQL), {"name": sub}).fetchall():
                    sub_statuses.append((r[0], r[1]))
            lag_bytes, lag_s = 0, 0.0
            for r in conn.execute(text(_LAG_SQL)).fetchall():
                lag_bytes = int(r[2] or 0)
                lag_s = _interval_to_seconds(r[3])
            workers = 0
            streaming = False
            for r in conn.execute(text(_APPLY_WORKERS_SQL)).fetchall():
                workers += 1
                if r[2] == "running":
                    streaming = True
            (totals,) = conn.execute(text(_CHANNEL_TOTALS_SQL)).fetchall()
            conflicts = int(totals[3] or 0)
            (exc,) = conn.execute(text(_EXCEPTIONS_SQL)).fetchall()
            exceptions_pending = int(exc[0] or 0)
            lock_pid: int | None = None
            lock_state: str | None = None
            for r in conn.execute(text(_LOCK_SQL), {"rid": replica_id}).fetchall():
                if r[1]:  # granted
                    lock_pid = int(r[0])
                    lock_state = r[2]
            node = NodeProbeData(
                node_name=node_name,
                reachable=True,
                sub_statuses=tuple(sub_statuses),
                lag_bytes=lag_bytes,
                lag_interval_s=lag_s,
                apply_workers=workers,
                workers_streaming=streaming,
                conflicts=conflicts,
                exceptions_pending=exceptions_pending,
                lock_held_locally=lock_pid is not None,
                lock_holder_pid=lock_pid,
                lock_holder_state=lock_state,
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )
    except Exception as exc:  # noqa: BLE001 — classification is the point
        node = NodeProbeData(
            node_name=node.node_name,
            reachable=False,
            probe_error=classify_error(exc),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    finally:
        engine.dispose()
    return node


# --- catalog + report assembly ------------------------------------------------


def _read_catalog(engine: Engine) -> dict[str, Any]:
    """One read on the app's own node: spock version + members + interface
    DSNs + the leader_lease row + task-queue counts."""
    with engine.connect() as conn:
        (row,) = conn.execute(text(_VERSION_SQL)).fetchall()
        spock_version = row[0]
        members = [r[0] for r in conn.execute(text(_MEMBERS_SQL)).fetchall()]
        interfaces = {
            r[0]: r[1] for r in conn.execute(text(_INTERFACES_SQL)).fetchall()
        }
        lease = None
        rows = conn.execute(text(_LEASE_SQL)).fetchall()
        if rows:
            (rid, token, acquired_at, heartbeat_at, fence) = rows[0]
            now = conn.execute(text("SELECT now()")).scalar()
            lease = {
                "replica_id": rid,
                "token": str(token),
                "acquired_at": str(acquired_at),
                "heartbeat_at": str(heartbeat_at),
                "heartbeat_age_s": round((now - heartbeat_at).total_seconds(), 1),
                "fence": fence,
            }
        queue: dict[str, Any] = {
            "pending": 0,
            "processing": 0,
            "done": 0,
            "oldest_pending_at": None,
        }
        for status, count, oldest in conn.execute(text(_QUEUE_SQL)).fetchall():
            if status == "pending":
                queue["oldest_pending_at"] = str(oldest) if oldest else None
            queue[status] = int(count)
    return {
        "spock_version": spock_version,
        "members": members,
        "interfaces": interfaces,
        "lease": lease,
        "queue": queue,
    }


def _dsn_display(dsn: str | None) -> str:
    """``host:port`` only — the DSN carries credentials and must not leak
    into the UI (briefing: the response shows host:port + node name, never
    the DSN string)."""
    if not dsn:
        return ""
    from urllib.parse import urlsplit

    parts = urlsplit(dsn)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return netloc or parts.path


def _own_namespace() -> str:
    """KubeDash's own namespace (in-cluster) — the best-effort candidates
    read is namespaced; host-run dev falls back to ``default`` (the read
    404s there, which is the null fallback)."""
    try:
        return _NAMESPACE_FILE.read_text().strip() or "default"
    except OSError:
        return "default"


def _candidate_count(admin_client: Any, replica_id: str) -> int | None:
    """Best-effort: pod(replica_id) → ownerRefs → ReplicaSet → Deployment
    → spec.replicas. ANY failure (no client, 404, transport) → None (F14:
    the candidate count is a diagnostic nicety, never a report blocker)."""
    if admin_client is None or not replica_id or replica_id == "?":
        return None
    try:
        ns = _own_namespace()
        pod = admin_client.get_pod(ns, replica_id)
        if not pod:
            return None
        refs = (pod.get("metadata") or {}).get("ownerReferences") or []
        rs_name = next(
            (r["name"] for r in refs if r.get("kind") == "ReplicaSet"), None
        )
        if not rs_name:
            return None
        # ReplicaSet name = "<deployment>-<rs-hash>" — strip the hash.
        dep_name = rs_name.rsplit("-", 1)[0]
        dep = admin_client.get_deployment(ns, dep_name)
        if not dep:
            return None
        replicas = (dep.get("spec") or {}).get("replicas")
        return int(replicas) if replicas is not None else None
    except Exception:  # noqa: BLE001 — best-effort by contract (F14)
        return None


def build_report(
    engine: Engine,
    dsn_overrides: Mapping[str, str] | None = None,
    *,
    admin_client: Any = None,
    replica_count: int | None = None,
    timeout_s: float = PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """Assemble the HA report: catalog read on the app engine, one probe per
    cluster member (INI DSN overrides win over ``spock.node_interface`` —
    F8), best-effort candidate count, derivation.

    ``replica_count`` is the configured KubeDash replica count (the chart's
    ``replicaCount``). It is the fallback for ``leader.candidates`` when the
    Deployment cannot be read (no K8s client, RBAC, host-run dev): the page
    then reports the configured number instead of "unknown", and a plain
    single-node run reports 1.

    Returns a plain dict shaped exactly like ``HaStatusOut`` — the API
    layer validates, it does not re-derive (blueprint Key links).
    """
    overrides = dict(dsn_overrides or {})
    catalog = _read_catalog(engine)
    lease = catalog["lease"]
    replica_id = lease["replica_id"] if lease else None

    nodes: list[dict[str, Any]] = []
    probes: list[NodeProbeData] = []
    for name in catalog["members"]:
        dsn = overrides.get(name) or catalog["interfaces"].get(name)
        if dsn is None:
            probe = NodeProbeData(node_name=name, reachable=False, probe_error="no_dsn")
        else:
            probe = probe_node(dsn, replica_id or "?", timeout_s=timeout_s)
        probes.append(probe)
        nodes.append(
            {
                "name": name,
                "reachable": probe.reachable,
                "probe_error": probe.probe_error,
                "sub_statuses": [
                    {"name": s, "status": st} for s, st in probe.sub_statuses
                ],
                "lag_bytes": probe.lag_bytes,
                "lag_interval_s": probe.lag_interval_s,
                "apply_workers": probe.apply_workers,
                "workers_streaming": probe.workers_streaming,
                "conflicts": probe.conflicts,
                "exceptions_pending": probe.exceptions_pending,
                "lock_held_locally": probe.lock_held_locally,
                "lock_holder_pid": probe.lock_holder_pid,
                "lock_holder_state": probe.lock_holder_state,
                "elapsed_ms": probe.elapsed_ms,
                "dsn": _dsn_display(overrides.get(name) or catalog["interfaces"].get(name)),
            }
        )

    lease_state = LeaseState(
        present=lease is not None,
        replica_id=lease["replica_id"] if lease else None,
        fence=lease["fence"] if lease else None,
        heartbeat_age_s=lease["heartbeat_age_s"] if lease else None,
        acquired_at=lease["acquired_at"] if lease else None,
    )
    derivation = derive_status(probes, lease_state)
    leader = dict(derivation["leader"])
    if lease:
        leader["token"] = lease["token"]
        leader["acquired_at"] = lease["acquired_at"]
    detected = _candidate_count(admin_client, replica_id or "")
    leader["candidates"] = detected if detected is not None else replica_count
    # Kubernetes Lease-object fields (holderIdentity / acquireTime /
    # renewTime / leaseDurationSeconds / leaseTransitions), so the page can
    # show the election the way `kubectl get lease -o yaml` does.
    leader["renew_at"] = lease["heartbeat_at"] if lease else None
    leader["lease_duration_s"] = LEASE_DURATION_S

    return {
        # derivation first: its `leader` entry is replaced by the enriched
        # one below (token / acquired_at / candidates).
        **derivation,
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "spock_version": str(catalog["spock_version"]),
        "nodes": nodes,
        "leader": leader,
        "queue": catalog["queue"],
    }
