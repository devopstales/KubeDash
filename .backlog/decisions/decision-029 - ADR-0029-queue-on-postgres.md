---
id: decision-029
title: "ADR-0029 Queue on Postgres: `tasks` table + `SELECT ... FOR UPDATE SKIP LOCKED` worker, replacing RQ/Redis"
date: '2026-10-27'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0029-queue-on-postgres.md`

# Queue on Postgres: `tasks` table + `SELECT ... FOR UPDATE SKIP LOCKED` worker, replacing RQ/Redis

---
status: "accepted"
date: 2026-10-27
supersedes: ADR-0007
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash runs its periodic background tasks (cluster health probe every 60 s,
cluster sync every 300 s, plus the leader-gated stubs for alerts / access
expiry / RBAC drift / NaaS grant expiry) through **RQ**, with **Redis as the
broker**. The leader-gated scheduler in `wsgi.py` enqueues due task paths onto
the `kubedash` RQ queue; an RQ worker child process drains it.

This makes Redis a **second stateful dependency** whose only job, for the task
path, is to hold a queue of a handful of periodic job names. Two facts make
that a poor fit:

1. **Postgres is already a hard requirement** (the cluster registry, the
   `leader_lease` row, auth, and — after ADR-0030 — session revocation all live
   there). The queue's payload (a task path string + a few timestamps) has no
   need to live in a different engine than the data the tasks mutate.
2. **The task volume is tiny and periodic** (4–6 tasks, no fan-out, 60 s /
   300 s cadence). RQ's strengths — horizontal worker scaling, job inspection
   UI, complex retry graphs — are unused. What is actually needed is: enqueue
   a named job, have exactly one worker claim and run it, retry a few times on
   failure, and recover if a worker dies mid-job.

The question this ADR decides: **what backs the task queue, and what are the
claim / retry / crash-recovery semantics.**

Note on the supersession trail: ADR-0007 ("RQ over Celery") exists in the
`## LOCKED` index but **has no body file on disk** (index-only, never
committed). This ADR is the first file to carry the task-runner decision; it
supersedes ADR-0007's *outcome* (RQ) and records the reasoning that was only
ever summarized in the index row.

#### Decision Drivers

- **One stateful dependency.** The queue should live in the Postgres the app
  already requires, so a queue outage and a data outage are the same (already
  HA-managed) event, not a separate one.
- **Exactly-once claim under concurrency.** With N replicas and (per ADR-0031)
  two writable Postgres nodes, two workers may try to claim the same job; the
  claim must be atomic and lock-based so a job is never double-run.
- **Crash recovery.** A worker that dies mid-job must not wedge the queue; the
  job must become re-claimable (this replaces RQ's death-penalty / SIGALRM).
- **Bounded retry with backoff.** A transiently-failing job is retried a
  bounded number of times with increasing delay, then dead-lettered (matches
  the behavior ADR-0007's RQ config provided: 3 retries, exponential backoff).
- **No new extension, no new image build.** The mechanism must work on the
  Postgres image the deployment already ships (plain SQL, no `CREATE
  EXTENSION` beyond what Postgres core provides).
- **Leader gating is preserved.** Only the leader enqueues (ADR-0008 election);
  this ADR changes the *transport*, not the *gate*.

#### Considered Options

- **Keep RQ + Redis.** Least change. Rejected: it keeps a second stateful
  dependency (Redis) alive solely to hold a queue of periodic job names, and
  blocks the "Redis has zero consumers → remove it" simplification that
  ADR-0029 + ADR-0030 together enable.

- **`pgmq` (CloudNative extension).** A Postgres extension giving `send` /
  `read` / `delete` with a visibility timeout — close to RQ semantics out of
  the box. Rejected for this change: it is a `CREATE EXTENSION` dependency
  (one more thing to pin and operate in the image), and the claim / retry /
  reaper logic it saves is small at this task volume. Revisit if the task set
  grows a fan-out workload.

- **Hand-rolled `tasks` table + `SELECT ... FOR UPDATE SKIP LOCKED` (chosen).**
  A single table; workers claim a row with a row-level lock that is naturally
  cluster-wide (it travels with the row under active-active, per ADR-0031).
  Poll-based (no `LISTEN`/`NOTIFY` — see Decision Outcome). The claim / reaper
  / retry SQL is ~100–200 lines and is *our* code, but it is plain Postgres
  core, needs no extension, and composes atomically with the data the tasks
  mutate.

#### Decision Outcome

**Chosen option: hand-rolled `tasks` table + `SELECT ... FOR UPDATE SKIP LOCKED`
worker, poll-based.**

Schema (added by an Alembic migration; the table is replicated to every
active-active node by `autoddl`, per ADR-0031):

| Column | Type | Purpose |
|---|---|---|
| `id` | `BIGSERIAL` PK | row identity |
| `path` | `TEXT` | the RQ-callable task path (e.g. `app.tasks.health.run`) |
| `status` | `TEXT` | `pending` \| `processing` \| `done` \| `failed` |
| `attempts` | `INT` | claim count, starts 0 |
| `enqueued_at` | `timestamptz` | FIFO ordering |
| `locked_at` | `timestamptz` | when the current claim began (reaper input) |
| `locked_by` | `TEXT` | replica id of the claiming worker |
| `available_at` | `timestamptz` | earliest re-claim time (backoff input) |

**Enqueue** (leader scheduler, `wsgi.py`): `INSERT INTO tasks (path,
enqueued_at, available_at, status) VALUES (:path, now(), now(), 'pending')`.
The existing `INTERVALS` dict and the per-task, per-poll `leader.is_leader()`
check are unchanged — only the transport from `queue.enqueue(path)` to this
`INSERT` changes.

**Claim** (worker loop, every node that runs a worker):

```sql
BEGIN;
SELECT * FROM tasks
 WHERE status = 'pending' AND available_at <= now()
 ORDER BY enqueued_at
 LIMIT 1
 FOR UPDATE SKIP LOCKED;
-- if a row: SET status='processing', locked_at=now(), locked_by=:rid,
--           attempts=attempts+1 ; COMMIT ; process ; mark 'done' (or re-queue)
```

`FOR UPDATE SKIP LOCKED` makes the claim atomic and non-blocking: a concurrent
claimer on another node / another replica sees the row locked and skips it, so
a job is claimed by exactly one worker. Row-level locks are cluster-wide under
the active-active setup (ADR-0031), so this holds across both writable nodes.

**Poll, not `LISTEN`/`NOTIFY`.** The worker sleeps a fixed interval (matching
the scheduler's 5 s poll cadence) and re-claims. `LISTEN`/`NOTIFY` is
deliberately *not* used: a `NOTIFY` is fire-and-forget (dropped if no one is
listening at that instant), carries no payload, and — decisively — **does not
replicate across active-active nodes**, so it is less effective on the
ADR-0031 topology than on a single node. The tasks are periodic (60 s / 300 s),
so the ~5 s poll latency is far below any requirement. The poll is also the
safety net that makes the queue correct regardless of the notification path.

**Crash recovery (reaper).** A worker that dies between claim and completion
leaves a `processing` row. A reaper (run by the leader, folded into an existing
leader task) re-queues stale claims:

```sql
UPDATE tasks
   SET status = 'pending', locked_at = NULL, locked_by = NULL,
       available_at = now() + make_interval(secs => backoff(attempts))
 WHERE status = 'processing'
   AND locked_at < now() - interval '2 minutes';
```

This replaces RQ's death-penalty: a dead worker's in-flight job becomes
re-claimable after a timeout longer than any single task's expected runtime.

**Retry + backoff.** On a task exception the worker increments `attempts` (via
the claim) and sets `status='pending'`, `available_at = now() + backoff`
(exponential: e.g. 1 min, 5 min, 25 min). After `attempts >= 3` the row is set
`status='failed'` (dead-letter) and left for inspection — matching the 3-retry
policy ADR-0007's RQ config provided.

##### Consequences

- Good, because the queue is now in the Postgres the app already requires and
  already makes HA (ADR-0031) — a queue outage is no longer a separate failure
  mode from a data outage, and the queue is transactional (a committed job
  row cannot be silently lost the way an evicted/flushed Redis key can).
- Good, because `FOR UPDATE SKIP LOCKED` row locks are cluster-wide under
  active-active, so exactly-once claim holds across both writable nodes with no
  extra coordination.
- Good, because it is plain Postgres core SQL — no `CREATE EXTENSION`, no image
  build, composes atomically with the tables the tasks mutate (enqueue and
  task-write can share a transaction).
- Bad, because we re-implement what RQ gave for free: the reaper, the
  retry/backoff, and the dead-letter path are now ~100–200 lines of our code,
  owned and tested by us.
- Bad, because the worker holds Postgres connections while claiming /
  processing; under load it needs a pool separate from the app's request pool
  (the task volume is small, so this is a sizing note, not a current pressure).
- Bad, because job *inspection* (RQ's dashboard of queued/failed jobs) is gone;
  the `tasks` table is the inspection surface (`SELECT * FROM tasks WHERE
  status='failed'`).

##### Confirmation

- Unit: two concurrent claimers on the same `tasks` row → exactly one gets it
  (the other's `SKIP LOCKED` returns no row); a `processing` row older than the
  reaper interval is re-queued by the reaper; a task that raises 3× ends
  `failed`.
- Integration (kind/dev-stack): kill the worker child mid-drain → its in-flight
  job is re-claimed after the reaper interval and completes; the leader
  failover (ADR-0008) still gates enqueue so a job is never enqueued by two
  replicas.
- The `wsgi.py` scheduler log line changes from "RQ scheduler started" to name
  the Postgres `tasks` table; no `rq.*` import remains in the enqueue path.

#### Pros and Cons of the Options

##### Keep RQ + Redis

- Good, because zero change to the running system.
- Neutral, because RQ is a proven, well-tested worker.
- Bad, because it keeps Redis alive as a stateful dependency solely for a
  queue of periodic job names, and blocks removing Redis from the stack.

##### `pgmq` extension

- Good, because visibility-timeout / retry semantics are built in (less code).
- Good, because it is Postgres-native (no second engine).
- Bad, because it is a `CREATE EXTENSION` dependency to pin and operate in the
  image, and its savings are small at this task volume.

##### Hand-rolled `tasks` + `SKIP LOCKED` (chosen)

- Good, because plain Postgres core, no extension, no image build, atomic with
  the task's data writes, and exactly-once claim holds under active-active.
- Neutral, because the claim / reaper / retry SQL is a modest, well-understood
  amount of owned code at this volume.
- Bad, because retry / death-penalty / dead-letter are re-implemented by us
  rather than inherited from a queue library.

#### More Information

- Supersedes ADR-0007 (RQ over Celery). ADR-0007 had no body file (index-only);
  this is the first file to carry the task-runner decision.
- Pairs with ADR-0030 (session revocation on Postgres): together they remove
  Redis's last two consumers, so Redis is dropped from the chart, the dev
  compose, and `KUBEDASH_REDIS_URL`.
- The active-active topology that makes the row-lock claim cluster-wide is
  ADR-0031 (pgEdge/Spock). The leader gate that decides *who enqueues* is
  ADR-0008 (unchanged).
- Revisit trigger: if the task set grows a fan-out / high-throughput workload,
  re-evaluate `pgmq` (built-in visibility timeout + retry) against this
  hand-rolled reaper.
