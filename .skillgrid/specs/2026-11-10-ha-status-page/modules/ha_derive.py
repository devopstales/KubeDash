"""ha_derive — pure status derivation for the HA Status report (liftable module).

Prototype 001 (`.skillgrid/meta/.prototype/001-spock-probe-visibility/`)
extracted this from the throwaway probe server so the real build
(`backend/app/services/ha_status.py`, blueprint Task 2) can lift it
unchanged: wrap the I/O (probe_node / catalog reads) around it.

Pure: no imports beyond the standard library, no I/O, no globals.
All thresholds are injected as keyword arguments (no prototype-specific
constants) so the build passes its own.

Two failure domains, derived separately (the UI renders them under
separate headers; the overall verdict is the worst of the two):

1. **Database HA** (pgEdge active-active) — `derive_database_status`:
   down     : node_unreachable:<name>, subscription_not_replicating:<node>
   degraded : lag_exceeded:<node> (F17: requires lag_bytes > 0),
              exceptions_pending:<node>
2. **KubeDash HA** (leader election) — `derive_election_status`:
   degraded : leader_lease_missing, leader_heartbeat_stale,
              lock_lease_mismatch, lock_without_heartbeat, no_leader
   (never `down`: a failed election is fail-closed — no scheduled work —
   not a data-loss condition)

`derive_status` composes: overall status = worst section; reasons = all,
database section first. Lock-reason rules (F12-F14):
- heartbeat FRESH: none seen with ALL nodes reachable -> lock_lease_mismatch;
  none seen while SOME node is unreachable -> NO alarm (the lock may sit
  on the unreachable node — the per-replica advisory lock is only visible
  from the node hosting the leader's session).
- heartbeat STALE: lock seen on a reachable node -> lock_without_heartbeat
  (a wedged leader); lock not seen -> no_leader.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

_ORDER = {"healthy": 0, "degraded": 1, "down": 2}


@dataclass(frozen=True)
class NodeProbeData:
    """One node's probe result, as the real `probe_node` will return it.

    `lag_bytes` / `lag_interval_s` are for the direction INTO this node
    (the only direction a node exposes — prototype finding, see
    prototype.md): every node carries exactly one receive-direction row.
    """

    node_name: str
    reachable: bool
    probe_error: Optional[str] = None  # classified: connection_refused | timeout | auth | other:<ExcName>
    # (subscription_name, status) per local subscription; empty when unreachable
    sub_statuses: tuple[tuple[str, str], ...] = ()
    lag_bytes: int = 0
    lag_interval_s: float = 0.0
    apply_workers: int = 0
    workers_streaming: bool = False
    conflicts: int = 0
    exceptions_pending: int = 0
    lock_held_locally: bool = False
    lock_holder_pid: Optional[int] = None
    lock_holder_state: Optional[str] = None
    elapsed_ms: int = 0


@dataclass(frozen=True)
class LeaseState:
    """The leader_lease row as read from the app engine (one read, not per node)."""

    present: bool
    replica_id: Optional[str] = None
    fence: Optional[int] = None
    heartbeat_age_s: Optional[float] = None


@dataclass(frozen=True)
class LeaderInfo:
    replica_id: str
    fence: int
    heartbeat_age_s: float
    lock_verdict: str  # human line: "held on n1 (pid 7899, idle)" / "not seen on any reachable node" / ...


@dataclass(frozen=True)
class SectionDerivation:
    status: str  # "healthy" | "degraded" | "down"
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ElectionDerivation(SectionDerivation):
    leader: Optional[LeaderInfo] = None


@dataclass(frozen=True)
class StatusDerivation:
    status: str  # overall: worst of the two sections
    reasons: tuple[str, ...] = field(default_factory=tuple)
    leader: Optional[LeaderInfo] = None
    database: Optional[SectionDerivation] = None
    election: Optional[ElectionDerivation] = None


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
    lag_exceeded_s: float = 60.0,
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
    heartbeat_stale_s: float = 10.0,
) -> ElectionDerivation:
    """KubeDash HA: leader lease freshness + advisory-lock cross-check."""
    reasons: list[str] = []
    lock_line = _lock_verdict(nodes)
    stale = not lease.present or lease.heartbeat_age_s is None or lease.heartbeat_age_s > heartbeat_stale_s

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
    lag_exceeded_s: float = 60.0,
    heartbeat_stale_s: float = 10.0,
) -> StatusDerivation:
    """Overall = worst of the two sections; reasons = all, database first."""
    db = derive_database_status(nodes, lag_exceeded_s=lag_exceeded_s)
    el = derive_election_status(nodes, lease, heartbeat_stale_s=heartbeat_stale_s)
    worst = max(_ORDER[db.status], _ORDER[el.status])
    status = ["healthy", "degraded", "down"][worst]
    return StatusDerivation(
        status=status,
        reasons=db.reasons + el.reasons,
        leader=el.leader,
        database=db,
        election=el,
    )
