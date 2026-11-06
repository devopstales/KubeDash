---
type: InvariantContract
title: "The RQ worker and periodic tasks run only on the elected leader replica"
description: "Leader election is a Postgres advisory lock (pg_try_advisory_lock on hashtext of the replica id) plus a single-row leader_lease table; wsgi.py spawns the in-process RQ worker only when kubedash_role == 'leader'. (ADR-0006/0007/0008.)"
tags: [leader-election, rq, tasks, adr-0008]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/wsgi.py
      all_of: ['if settings.kubedash_role != "leader":', '"app.tasks.health.run"', '"app.tasks.cluster_sync.run"']
    - path: backend/app/core/leader.py
      all_of: ['pg_try_advisory_lock', 'pg_advisory_unlock', 'leader_lease']
    - path: backend/tests/test_leader.py
      all_of: ['test_second_replica_does_not_double_lead', 'test_failover_after_leader_stop_is_fast']
claims:
  - subject: worker spawn gate
    literal: 'if settings.kubedash_role != "leader":'
  - subject: atomic acquisition
    literal: 'pg_try_advisory_lock'
  - subject: observable lease row
    literal: 'leader_lease'
---

# The RQ worker runs only on the leader

All replicas serve HTTP identically; exactly one — the leader — runs the
in-process RQ worker and the periodic task enqueue loop.

**The contract.**

- Acquisition is `SELECT pg_try_advisory_lock(hashtext(:rid))`
  (non-blocking; `pg_advisory_unlock` on release) in
  `backend/app/core/leader.py` — the advisory lock is the arbiter, so two
  replicas can never both hold it.
- The lease is observable: `leader_lease` row `id = 1` with
  `replica_id`, `token` (UUID), `acquired_at`, `heartbeat_at`.
- The leader heartbeats every 5 s; a replica treats `heartbeat_at` as
  stale after 10 s and attempts acquisition (followers poll at 1 s).
- `backend/wsgi.py` skips the worker entirely when
  `kubedash_role != "leader"` (the chart sets `KUBEDASH_ROLE=leader` on
  every replica — "candidates"; the election decides). The worker runs
  as a subprocess thread named `kubedash-worker` on queue `"kubedash"`,
  enqueuing exactly `wsgi.INTERVALS`
  (`app.tasks.health.run` 60 s, `app.tasks.cluster_sync.run` 300 s).

**Why.** Duplicate periodic work corrupts state (double syncs, double
expiry sweeps); a leader-less install simply has no background work
(fail-closed, not a crash). The advisory lock keeps the arbiter inside
the system-of-record DB — no new infrastructure.

**Verification (2026-11-06).** Grepped: the role gate at
`backend/wsgi.py:154`, the advisory-lock SQL and `leader_lease` upsert at
`backend/app/core/leader.py:94-144`, heartbeat/stale intervals 5 s/10 s
at `leader.py:40-41`.

**Pinned by.** `backend/tests/test_leader.py` (single leader, no
double-lead, fast failover), `backend/tests/test_worker_gate.py` (no
worker thread on followers; enqueue set == `INTERVALS`).

**Related.** ADR-0007 (RQ), ADR-0008 (election), ADR-0006 (single
container), `workflows/leader-task-execution.md`.
