---
type: BusinessWorkflow
title: "Leader election → periodic task execution → failover"
description: "How N identical replicas elect one leader (pg advisory lock + leader_lease row + strict fence, 5 s heartbeat / 10 s stale); every candidate runs the in-process pgqueue worker thread, the leader alone enqueues INTERVALS into the Postgres tasks table, any replica claims via FOR UPDATE SKIP LOCKED, and a dead leader fails over within the stale window. (ADR-0029/0031.)"
tags: [leader-election, pgqueue, workflow, adr-0029]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/wsgi.py
      all_of: ['INTERVALS', 'kubedash-worker', 'is_leader']
    - path: backend/app/core/leader.py
      all_of: ['pg_try_advisory_lock', 'leader_lease']
    - path: charts/kubedash/templates/deployment.yaml
      all_of: ['KUBEDASH_ROLE', 'KUBEDASH_REPLICA_ID']
---

# Leader election → task execution → failover

All chart replicas are **candidates** (`KUBEDASH_ROLE=leader` on every
pod; `KUBEDASH_REPLICA_ID` from the Downward API). Exactly one actually
leads.

## The flow

1. **Startup (every replica).** `backend/wsgi.py` starts the leader
   thread (`backend/app/core/leader.py`): `SELECT
   pg_try_advisory_lock(...)` — non-blocking; whoever holds the lock
   upserts `leader_lease` row `id = 1` (`replica_id`, `token` UUID,
   `acquired_at`, `heartbeat_at`, `fence`). The `kubedash-worker`
   daemon thread also starts in the Gunicorn master.
2. **Heartbeat.** The leader updates `heartbeat_at` every **5 s**;
   followers poll the row every **1 s** and treat `heartbeat_at` as
   stale after **10 s**, then attempt acquisition.
3. **Task loop (every replica; enqueue leader-gated).** Each tick the
   worker thread: (a) enqueues due `INTERVALS` —
   `app.tasks.health.run` every 60 s, `app.tasks.cluster_sync.run`
   every 300 s — into the Postgres `tasks` table **only while
   `is_leader()` is true** (checked per task and per poll — a
   leadership loss stops scheduling within one 5 s window); (b) claims
   a row via `FOR UPDATE SKIP LOCKED`, runs it, and marks it done — on
   **any** replica (concurrent claimants skip each other's locked
   rows); (c) sweeps the reaper (stale claims, expired jtis, expired
   kv rows) **only while `is_leader()` is true**.
4. **Failover.** Leader dies → Postgres releases the advisory lock → a
   follower's next poll acquires it → its `is_leader` flips → that
   replica resumes enqueueing + reaping. In-flight claims become
   re-claimable through the reaper's stale window (120 s; replaces
   RQ's death penalty, ADR-0029) — no data loss, no broker.

## Failure behavior

- Postgres unavailable: election pauses (HTTP still serves; no
  periodic work — fail-closed).
- Partition that keeps the old leader's PG session alive: failover
  delays until the session drops (advisory locks are session-scoped) —
  recorded accepted cost of ADR-0008; the `fence` column (ADR-0031)
  additionally fences a stale leader's writes under active-active.
- A non-leader never enqueues: double-runs of *scheduled* work are
  impossible by construction (gate + arbiter); double-claims are
  impossible because the `SKIP LOCKED` claim is atomic.

## Verification (2026-11-09)

Anchors confirmed in all three sites. Pinned by
`backend/tests/test_leader.py` (single leader, no double-lead, fast
failover), `backend/tests/test_worker_gate.py` (the per-tick leader
gate on enqueue + reap) and `backend/tests/core/test_pgqueue.py`
(claim semantics).

**Related.** ADR-0029 (queue on Postgres), ADR-0031 (active-active +
fence), ADR-0006 (single container),
`invariants/leader-only-rq-worker.md` (the leader-gated parts).
