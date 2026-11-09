---
type: InvariantContract
title: "Task enqueue and reaping run only on the elected leader; claims run on every replica"
description: "Leader election is a Postgres advisory lock (pg_try_advisory_lock) + a single-row leader_lease table (+ strict fence, ADR-0031); every candidate replica runs the in-process pgqueue worker thread (ADR-0029), but only the leader enqueues INTERVALS and sweeps the reaper — claims are safe on every replica via FOR UPDATE SKIP LOCKED. (Supersedes the leader-only RQ worker, ADR-0006/0007/0008.)"
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

- Election is unchanged: `SELECT pg_try_advisory_lock(...)` in
  `backend/app/core/leader.py` (non-blocking; the advisory lock is the
  arbiter, so two replicas can never both hold it), observable
  `leader_lease` row `id = 1` (`replica_id`, `token`, `acquired_at`,
  `heartbeat_at`, `fence` — the ADR-0031 strict fence). The leader
  heartbeats every 5 s; a replica treats `heartbeat_at` as stale after
  10 s and attempts acquisition (followers poll at 1 s).
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
ADR-0007/0008) — is superseded by ADR-0029/0031. The advisory lock
keeps the arbiter inside the system-of-record DB — no new
infrastructure.

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
