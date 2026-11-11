"""ha_derive — pure status derivation for the HA Status report (liftable module).

Prototype 001 (`.skillgrid/meta/.prototype/001-spock-probe-visibility/`)
extracted this from the throwaway probe server so the real build
(`backend/app/services/ha_status.py`, blueprint Task 2) can lift it
unchanged: wrap the I/O (probe_node / catalog reads) around it.

Pure: no imports beyond the standard library, no I/O, no globals.
All thresholds are injected as keyword arguments (no prototype-specific
constants) so the build passes its own.

Contract (blueprint Task 2, R4 matrix):
  down (worst)  : node_unreachable:<name>, subscription_not_replicating:<node>
  degraded      : lag_exceeded:<node>, exceptions_pending:<node>,
                  leader_heartbeat_stale, leader_lease_missing,
                  lock_lease_mismatch, lock_without_heartbeat, no_leader
  healthy       : no reasons
All applicable reasons are listed; the worst status wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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
class StatusDerivation:
    status: str  # "healthy" | "degraded" | "down"
    reasons: tuple[str, ...] = field(default_factory=tuple)
    leader: Optional[LeaderInfo] = None


def _lock_verdict(nodes: list[NodeProbeData]) -> Optional[LeaderInfo | str]:
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


def derive_status(
    nodes: list[NodeProbeData],
    lease: LeaseState,
    *,
    lag_exceeded_s: float = 60.0,
    heartbeat_stale_s: float = 10.0,
) -> StatusDerivation:
    """R4 matrix: per-node reachability/replication + lease/lock freshness -> status + reasons.

    Lock-reason rules (F12-F14):
    - heartbeat FRESH: a lock sighting is expected on exactly one node;
      none seen with ALL nodes reachable -> lock_lease_mismatch;
      none seen while SOME node is unreachable -> NO alarm (the lock may
      sit on the unreachable node — the per-replica advisory lock is only
      visible from the node hosting the leader's session).
    - heartbeat STALE: lock seen on a reachable node -> lock_without_heartbeat
      (a wedged leader holds the lock but stopped heartbeating);
      lock not seen -> no_leader.
    """
    reasons: list[str] = []
    worst = 0  # 0 healthy, 1 degraded, 2 down

    def add(status: int, reason: str) -> None:
        nonlocal worst
        worst = max(worst, status)
        reasons.append(reason)

    for n in nodes:
        if not n.reachable:
            add(2, f"node_unreachable:{n.node_name}")
            continue
        for sub_name, status in n.sub_statuses:
            if status != "replicating":
                add(2, f"subscription_not_replicating:{n.node_name}")
                break
        if n.lag_bytes > 0 and n.lag_interval_s > lag_exceeded_s:
            add(1, f"lag_exceeded:{n.node_name}")
        if n.exceptions_pending > 0:
            add(1, f"exceptions_pending:{n.node_name}")

    leader: Optional[LeaderInfo] = None
    if not lease.present:
        add(1, "leader_lease_missing")
    elif lease.heartbeat_age_s is None or lease.heartbeat_age_s > heartbeat_stale_s:
        add(1, "leader_heartbeat_stale")
        lock_line = _lock_verdict(nodes)
        if isinstance(lock_line, str) and lock_line.startswith("held on"):
            add(1, "lock_without_heartbeat")
        elif isinstance(lock_line, str) and lock_line == "not seen on any reachable node":
            add(1, "no_leader")
        leader = LeaderInfo(
            lease.replica_id or "?",
            lease.fence if lease.fence is not None else 0,
            lease.heartbeat_age_s or 0.0,
            lock_line if isinstance(lock_line, str) else "unknown",
        )
    else:
        lock_line = _lock_verdict(nodes)
        if isinstance(lock_line, str) and lock_line == "not seen on any reachable node":
            all_reachable = all(n.reachable for n in nodes)
            if all_reachable:
                add(1, "lock_lease_mismatch")
        leader = LeaderInfo(
            lease.replica_id or "?",
            lease.fence if lease.fence is not None else 0,
            lease.heartbeat_age_s or 0.0,
            lock_line if isinstance(lock_line, str) else "unknown",
        )

    status = {0: "healthy", 1: "degraded", 2: "down"}[worst]
    return StatusDerivation(status=status, reasons=tuple(reasons), leader=leader)
