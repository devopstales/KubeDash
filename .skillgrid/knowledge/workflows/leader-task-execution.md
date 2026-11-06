---
type: BusinessWorkflow
title: "Leader election → periodic task execution → failover"
description: "How N identical replicas elect one leader (pg advisory lock + leader_lease row, 5 s heartbeat / 10 s stale), the leader enqueues INTERVALS onto the kubedash RQ queue, the in-process worker consumes it, and a dead leader fails over within the stale window."
tags: [leader-election, rq, workflow, adr-0008]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/wsgi.py
      all_of: ['INTERVALS', '"kubedash-worker"', 'rq.Queue("kubedash"']
    - path: backend/app/core/leader.py
      all_of: ['pg_try_advisory_lock', 'heartbeat_at = now()', 'stale_seconds']
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
   pg_try_advisory_lock(hashtext(:rid))` — non-blocking; whoever gets the
   lock upserts `leader_lease` row `id = 1` (`replica_id`, `token` UUID,
   `acquired_at`, `heartbeat_at = now()`).
2. **Heartbeat.** The leader updates `heartbeat_at` every **5 s**;
   followers poll the row every **1 s** and treat `heartbeat_at` as
   stale after **10 s**, then attempt acquisition.
3. **Task loop (leader only).** When `kubedash_role == "leader"` and the
   in-memory `is_leader` flag is set, `wsgi.py` enqueues
   `INTERVALS` — `app.tasks.health.run` every 60 s,
   `app.tasks.cluster_sync.run` every 300 s — onto queue
   `"kubedash"`; the worker runs as a subprocess thread
   (`kubedash-worker`, `rq.Worker(["kubedash"])`, `burst=True`).
   Followers log `KUBEDASH_ROLE=… — no RQ worker on this replica` and
   serve HTTP only.
4. **Failover.** Leader dies → Postgres releases the advisory lock → a
   follower's next poll acquires → its `is_leader` flips → the task loop
   and worker start. In-flight RQ tasks complete or retry under RQ's
   policy (no data loss; the bound is the 10 s stale window + lock
   release).

## Failure behavior

- Postgres unavailable: election pauses (HTTP still serves; no periodic
  work — fail-closed).
- Partition that keeps the old leader's PG session alive: failover
  delays until the session drops (advisory locks are session-scoped) —
  recorded accepted cost of ADR-0008.
- A non-leader never enqueues: double-runs are impossible by
  construction (gate + arbiter).

## Verification (2026-11-06)

Anchors confirmed in all three sites. Pinned by
`backend/tests/test_leader.py` (single leader, no double-lead, fast
failover) and `backend/tests/test_worker_gate.py` (no worker on
followers; enqueue set == `INTERVALS`).

**Related.** ADR-0007 (RQ), ADR-0008 (election), ADR-0006 (single
container), `invariants/leader-only-rq-worker.md`.
