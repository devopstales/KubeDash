---
type: InvariantContract
title: "Task enqueue and reaping run only on the elected leader; claims run on every replica"
description: "Leader election is the single-row leader_lease table (1 s follower poll / 5 s heartbeat / 10 s stale) + a PER-REPLICA session-scoped advisory lock (hashtext of own replica_id — liveness marker, NOT a cross-node mutex) + the strict fence LWW (ADR-0031); every candidate replica runs the in-process pgqueue worker thread (ADR-0029), but only the leader enqueues INTERVALS and sweeps the reaper — claims are safe on every replica via FOR UPDATE SKIP LOCKED. (Supersedes the leader-only RQ worker, ADR-0006/0007/0008.)"
tags: [leader-election, pgqueue, tasks, adr-0029]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/wsgi.py
      all_of: ['kubedash-worker', 'is_leader', 'INTERVALS']
    - path: backend/app/core/pgqueue.py
      all_of: ['FOR UPDATE SKIP LOCKED']
    - path: backend/app/core/leader.py
      all_of: ['pg_try_advisory_lock', 'leader_lease']
    - path: backend/tests/test_worker_gate.py
      all_of: ['test_run_once_skips_when_not_leader', 'test_run_once_enqueues_due_tasks_when_leader']
claims:
  - subject: enqueue gate
    literal: 'if not is_leader():'
  - subject: claim concurrency
    literal: 'FOR UPDATE SKIP LOCKED'
  - subject: atomic acquisition
    literal: 'pg_try_advisory_lock'
  - subject: observable lease row
    literal: 'leader_lease'
---

# Task enqueue and reaping run only on the leader

All replicas serve HTTP identically, and — as candidates
(`KUBEDASH_ROLE=leader` on every chart pod) — all run the in-process
pgqueue worker thread (`kubedash-worker`, ADR-0029). What the leader
alone owns is *enqueue/scheduling* and *reaping*; *claiming and
running* tasks is safe on any replica because the claim is atomic.

**The contract.**

- Election: followers poll the `leader_lease` row `id = 1` (`replica_id`,
  `token`, `acquired_at`, `heartbeat_at`, `fence`) every 1 s; a fresh
  lease owned by another replica → no-op (steady state: one leader,
  N−1 passive followers holding no lock). When the lease is stale
  (heartbeat older than 10 s) or absent, that replica takes its OWN
  session-scoped advisory lock — key `hashtext(<own replica_id>)`,
  per-replica by design (`backend/app/core/leader.py` `_binds`) — and
  upserts the row with `fence = fence + 1`. The advisory lock is a
  session-liveness marker, NOT a cross-node mutex (ADR-0031: "two peers
  on different Postgres nodes can both hold their local session's
  lock"); the **fence is the cross-node LWW tiebreaker** — every leader
  write is fenced `WHERE fence = :f`, a fenced-out leader's write
  affects 0 rows and it demotes. The leader heartbeats every 5 s.
- `backend/wsgi.py` starts the `kubedash-worker` daemon thread in the
  Gunicorn master. Each tick: the enqueue of due `INTERVALS`
  (`app.tasks.health.run` 60 s, `app.tasks.cluster_sync.run` 300 s)
  happens **only while `is_leader()` is true** (checked per task and
  per poll); the claim (`pgqueue`, `FOR UPDATE SKIP LOCKED`) + run
  happens on **every** replica — concurrent claimants skip each other's
  locked rows, so exactly-once claim holds across replicas; the reaper
  (stale claims + expired jtis + expired kv rows) runs **only while
  `is_leader()` is true**.

**Why.** Duplicate enqueue or reaping corrupts state (double syncs,
double expiry sweeps); a leader-less install simply has no scheduled
work (fail-closed, not a crash). Claims need no gate because
`SKIP LOCKED` row locks are cluster-wide under active-active
(ADR-0031). The old shape — "the leader alone runs the worker" (RQ,
ADR-0007/0008) — is superseded by ADR-0029/0031. The lease row keeps
the arbiter inside the system-of-record DB — no new infrastructure —
and the per-replica advisory lock doubles as a session-death liveness
marker (released by Postgres when the leader's session dies,
observable in `pg_locks`).

**Verification (2026-11-09).** Grepped: the per-tick `is_leader` gate
in `backend/wsgi.py` (`_run_once` / `_reap_once`), the
`FOR UPDATE SKIP LOCKED` claim in `backend/app/core/pgqueue.py`, the
advisory-lock SQL and `leader_lease` upsert (incl. the `fence` column)
in `backend/app/core/leader.py`.

**Pinned by.** `backend/tests/test_worker_gate.py`
(`test_run_once_skips_when_not_leader`,
`test_run_once_enqueues_due_tasks_when_leader`,
`test_reap_once_skips_when_not_leader`,
`test_reap_once_sweeps_when_leader`), `backend/tests/test_leader.py`
(single leader, no double-lead, fast failover),
`backend/tests/core/test_pgqueue.py` (claim/reap semantics).

**Related.** ADR-0029 (queue on Postgres), ADR-0031 (active-active +
fence), ADR-0006 (single container),
`workflows/leader-task-execution.md`.
