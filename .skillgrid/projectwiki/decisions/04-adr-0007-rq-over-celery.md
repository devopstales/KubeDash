# RQ over Celery for async tasks

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

Periodic background work (cluster sync, health probes, alert
evaluation, expiry sweeps) needs an async task runner. The volume is
small — a handful of periodic tasks, no fan-out — but the choice is
hard to reverse: the runner shape dictates worker deployment and task
module structure.

#### Decision Drivers

- **Redis is already a dependency** (cache + RQ broker share it).
- **The worker must fit the single container** (ADR-0006): an
  in-process worker, not a separate container.
- **Task modules stay framework-agnostic** so the runner can be
  swapped if the workload grows (recorded exit: migrate RQ → Celery if
  fan-out/priorities are ever needed — broker is already Redis).

#### Considered Options

- **Celery.** Rejected: broker config + separate worker container +
  result backend for ~4 periodic tasks is overkill; it breaks the
  single-container shape.
- **In-process APScheduler (no queue).** Rejected: no retry policy, no
  persistence of in-flight work, and N replicas would double-run tasks
  without a queue-level gate.
- **RQ (CHOSEN).** Redis Queue: a plain queue + worker, a
  `rq.Queue` enqueue, retry with exponential backoff, and an
  in-process worker that pairs with the leader gate (ADR-0008).

#### Decision Outcome

**Chosen option: RQ with an in-process, leader-gated worker.**

- Tasks live in `backend/app/tasks/` as plain modules with a `run()`
  entry point (plus `alerts.evaluate`).
- `backend/wsgi.py` enqueues the periodic tasks from `INTERVALS`
  (currently `app.tasks.health.run` every 60 s and
  `app.tasks.cluster_sync.run` every 300 s) onto queue `"kubedash"`,
  and spawns the worker as a subprocess thread (`kubedash-worker`)
  only when `kubedash_role == "leader"`.
- Non-enqueued entry points (`access_expiry.run`, `rbac_drift.run`,
  `ns_request_expiry.run`, `alerts.evaluate`) exist as RQ-callable
  modules — `rbac_drift` is a stub no-op pending ADR-0013's drift
  detection.

##### Consequences

- Good: zero extra moving parts; retry policy for free; leader gate
  prevents double runs across replicas; swap path to Celery stays open.
- Bad: a single-process worker (no horizontal task scaling); task
  execution is bound to the leader replica's lifetime (failover
  re-runs in-flight tasks via RQ retry).
- Confirmation: `backend/tests/test_worker_gate.py` (gate + enqueue
  set), `backend/tests/tasks/test_health.py`.

#### Linking Decisions and Constraints

- ADR-0006 — in-process worker inside the single container.
- ADR-0008 — only the leader runs the worker.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §3.7/§11; verified
against `backend/wsgi.py` (`INTERVALS`, queue `"kubedash"`, role gate)
and `backend/app/tasks/` on 2026-11-06.
