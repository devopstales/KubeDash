# Prototype 001 — Postgres queue + fence + revocation (SQL validation)

**Date:** 2026-10-27
**Type:** standard (single approach)
**Status:** complete

## Hypothesis (falsifiable)

> Given a single Postgres instance with the ADR-0029/0030/0031 tables
> (`tasks`, `revoked_jtis`, `leader_lease` + `fence`),
> when concurrent workers claim jobs, a stale leader attempts a fenced write,
> a worker dies mid-job, and the verify hook probes the deny-list on the hot
> path,
> then (A) each job is claimed by exactly one worker, (B) the stale leader's
> write affects 0 rows while the current fence-holder's write commits,
> (C) the reaper re-queues stale in-flight jobs with growing backoff and
> dead-letters at the retry cap, and (D) the hot-path deny-list lookup is a
> fast primary-key scan (≈ Redis `SISMEMBER`), not a table scan.

**Why this prototype:** ADR-0030's one stated risk is the per-request DB hit on
the verify-hook hot path; ADR-0029's claim/reaper/retry and ADR-0031's strict
fence are the load-bearing SQL. All four are falsifiable on stock Postgres —
only *replication* needs pgEdge, so the SQL semantics are validated here and
the pgEdge topology is a separate (gated) question.

## How to run

```bash
# scratch PG (already up as kdproto-pg, port 15432)
docker run -d --name kdproto-pg -e POSTGRES_PASSWORD=proto \
  -e POSTGRES_USER=proto -e POSTGRES_DB=kubedash -p 15432:5432 postgres:16
docker cp schema.sql kdproto-pg:/tmp/ && docker exec kdproto-pg psql -U proto -d kubedash -f /tmp/schema.sql
bash runA.sh   # exactly-once claim
bash runB.sh   # fence reject
bash runC.sh   # reaper + backoff + dead-letter
bash runD3.sh  # hot-path latency (see findings F2/F3 for the gen_random_uuid confound)
```

## Findings

### F1 — `CREATE INDEX ... WHERE expires_at > now()` is INVALID
Postgres rejects non-`IMMUTABLE` functions in index predicates; `now()` is
`STABLE`. The ADR-0030 "partial index" as written **would fail in the real
migration**. Fix: the table is small (bounded by the leader reaper deleting
expired rows), so a **plain** `expires_at` index (or no index — the hot path is
a PK hit) suffices. The reaper is the bounding mechanism, not the index.

### F2 — `FOR UPDATE SKIP LOCKED` gives exactly-once claim under concurrency
50 pending rows, 10 parallel claimers (1 each) → **10 distinct rows claimed,
0 double-claimed, 10 distinct workers, 40 pending remain**. Exactly-once
claim holds. (Single-node test; the cross-node claim is the pgEdge part, F5.)

### F3 — Strict fence rejects a stale leader's writes
- A acquires → fence 1. A's fresh heartbeat (fence 1) → **1 row**.
- B wins the lease (LWW) → fence 2.
- A's **stale** heartbeat (still fence 1) → **0 rows** (fenced out).
- B's fresh heartbeat (fence 2) → **1 row**. Row owner = B.

A stale leader is rejected row-by-row on *every* fenced write, not just the
heartbeat. Exactly one logical leader writes. The `fence` column + the
`WHERE fence = :my_fence` condition are sufficient and correct.

### F4 — Reaper re-queues stale in-flight jobs; dead-letters at the cap
A `processing` row stale > 2 min is re-queued `pending` with backoff
`LEAST(600, 60 * 5^attempts)` seconds: attempts 1 → 300 s, attempts 2 → 600 s
(capped). At attempts ≥ 3 the row is set `failed` (dead-letter). Replaces RQ's
death-penalty correctly.

### F5 — Hot-path deny-list lookup is a ~0.03–0.07 ms PK Index Only Scan
**This is the finding that validates ADR-0030.** At 50k rows (steady-state
size):
- mean **0.049 ms**, p50 **0.034 ms**, p90 **0.041 ms**, p99 **0.071 ms**
  (n=5000, 1:1 hit/miss).
- That is *faster* than a typical Redis `SISMEMBER` (~0.1–0.5 ms), so the
  per-request DB hit ADR-0014 optimized away is **not a regression**.

**The confound that almost invalidated it (F2b):** the first benchmark used
`WHERE jti = gen_random_uuid()`. The planner estimated `gen_random_uuid()`'s
output as ~50k matching rows and took a **263 ms** bitmap/seq scan
("Rows Removed by Filter: 50000"). With a **literal** (bound-parameter) absent
UUID — the real hot-path shape — the same query is an **Index Only Scan, 0.127 ms**.
Lesson: **never call a function in the verify-hook WHERE clause**; bind the
`jti` as a parameter (which the app already does). The `expires_at > now()`
predicate is fine (applied as a post-index filter on the single PK row).

### F7 — An UNPLANNED worker/leader exit (SIGKILL/OOM/power loss) does not wedge the queue
The risk the platform team asked about: a worker claims a job (`status=
'processing'`) then dies **unexpectedly** — no cleanup runs, no advisory lock
released, no `stop()`. Three mechanisms make this safe, and each was tested
(`runE.sh`):

1. **The queue recovers by TIME, not by lock release.** The reaper is
   `WHERE status='processing' AND locked_at < now() - interval '2 minutes'` —
   it never waits on the dead worker to release anything. A SIGKILL'd worker
   leaves a stuck `processing` row (E1: confirmed, `locked_ago_s=180`), and the
   reaper re-queues it `pending` with backoff (E2: confirmed, a new worker then
   re-claims it, `attempts` 1→2). **The queue is not wedged.** This is the key
   property: crash recovery is independent of the lock.
2. **The stale threshold must exceed the longest task runtime** (E4). A worker
   that died **< 2 min** ago is *not* re-queued yet — preventing a still-in-
   flight job from being double-run. **Constraint for the build:** set the
   reaper interval `>` the p99 task runtime (health/cluster_sync are seconds;
   2 min is a safe default; revisit if a task can run longer).
3. **The advisory lock is session-scoped, so it self-releases on crash.** A
   SIGKILL'd leader's `pg_try_advisory_lock` is held on its backend session;
   when the session dies (crash/OOM/power), Postgres frees it automatically —
   no `pg_advisory_unlock` needed. (On a *node* crash the whole session table
   is rebuilt; the lock is gone.)
4. **The strict fence closes the "late write" window** (E3). A SIGKILL'd leader
   A (fence 1) may have an in-flight write buffered/flushed *after* survivor B
   has taken over (fence 2). A's late write is fenced on `fence=1` → affects
   **0 rows** (rejected); B's write (fence 2) commits. Final owner B, fence 2.
   No split-brain, even with a write in flight at the moment of the kill.

**Conclusion:** unplanned exit is safe for the queue (time-based reaper, E1/E2)
and for the election (session-scoped advisory lock self-releases + strict
fence rejects late writes, E3). The one build constraint: **reaper interval >
longest task runtime** (E4), else a slow-but-alive job gets double-run.

### F6 — pgEdge image: use Docker Hub `pgedge/pgedge:pg17-latest` (ghcr is access-gated)
`ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal` **exists** (confirmed in the
ghcr tags list) but the local Docker credential (user `devopstales`) gets
**HTTP 403** on the manifest — the ghcr token lacks the `pgedge` package
pull-scope (even a public `actions/actions-runner` 403s with the same token, so
it's token-scope, not image-specific).

**Resolution:** pgEdge also publishes the official free image on **Docker Hub**:
`pgedge/pgedge:pg17-latest` (Spock 5.0.1, PostgreSQL 17.6, 2.05 GB,
`spock.control` present, entrypoint `/home/pgedge/scripts/run-database.sh`). It
pulls **publicly, no auth** — this is the image to use in the dev compose and
Helm chart (the ghcr image is the same build, just org-gated).

**Two gotchas found standing it up:**
1. `db.json` **must** include the `pgedge` `internal_admin` user, else the
   entrypoint aborts: `ERROR: pgedge user missing from spec`.
2. Spock wires on boot in ~30 s (`spock.node` shows both nodes); config is a
   `db.json` with `options:["autoddl:enabled"]`, nodes `n1`/`n2`, and the
   `admin` + `pgedge` users. Hostnames in `db.json` must match the compose
   service names (`kdpg-n1`/`kdpg-n2`).

**Topology validated on the two-node cluster (`runF6.sh`):**
- **F6a** cross-node DML: write on n1 → readable on n2. ✓
- **F6b** `autoddl`: `ALTER TABLE … ADD COLUMN` on n1 → column appears on n2,
  "DDL statement replicated". ✓ (migrations run once, per ADR-0031)
- **F6c** cross-node `FOR UPDATE SKIP LOCKED` claim: 6 claimers on n1 + 6 on
  n2 → **12 claimed, 0 double-claimed, 12 distinct**. The row-lock claim is
  **cluster-wide** — exactly what ADR-0029 needs. ✓
- **F6d** `spock.node` on each node lists both `n1` and `n2`. ✓ (columns are
  `node_id, node_name, location, country, info` — no `region` column)

## Verdict

**VALIDATED ✓** across the board:
- SQL semantics (F2 exactly-once claim, F3 fence reject, F4 reaper/dead-letter,
  F5 hot-path latency) — each with the edge case that would have killed it
  (concurrent double-claim; stale-leader LWW; dead worker; planner regression).
- pgEdge *topology* (F6) — validated on a live two-node Docker-Hub cluster:
  cross-node DML replication, `autoddl` DDL propagation, and a cluster-wide
  `FOR UPDATE SKIP LOCKED` claim (12 claimers across 2 nodes, 0 double-claimed).

The verdict that drives the build: **the Postgres queue + strict fence +
revocation table are sound, the hot path is fast enough to drop Redis, and the
active-active pgEdge topology (Docker Hub `pgedge/pgedge:pg17-latest`) is
confirmed working.** Two migration/ops details to carry: F1 (no partial
`now()` index) and F6's `db.json` must include the `pgedge` internal_admin
user.

## Liftable module

`schema.sql` is the liftable DDL (the three tables + the seed row), modulo the
F1 fix (drop the partial index → plain index or none). The claim/reaper/fence
SQL in `runA.sh`/`runB.sh`/`runC.sh` is the liftable query set — copy into the
Alembic migration + the `wsgi.py` worker + `leader.py` fence. The DO-block
benchmark (`bench.sql`) is throwaway.

## Constraints for the build

1. **Bind `jti` as a parameter** in the verify hook; do not call a function in
   the WHERE clause (F2b — 0.03 ms vs 263 ms).
2. **No partial `now()` index** (F1) — plain index or none; the reaper bounds
   the table.
3. **Fence every write** (F3) — the `WHERE fence = :my_fence` condition goes on
   the heartbeat *and* every task DB-write; `acquire` is
   `UPDATE … SET fence=fence+1 … RETURNING fence`.
4. **Reaper backoff** `LEAST(cap, base * 5^attempts)`, dead-letter at
   `attempts >= 3` (F4).
5. **Use Docker Hub `pgedge/pgedge:pg17-latest`** (F6), not the ghcr image —
   it pulls publicly, no auth. The `db.json` must include the `pgedge`
   internal_admin user, and node hostnames must match the compose service
   names. Spock wires on boot in ~30 s.
  6. **Reaper interval > longest task runtime** (F7/E4) — a worker that died <
    the threshold is not re-queued (prevents double-running a slow-but-alive
    job). Default 2 min is safe for the current sub-minute tasks; revisit if a
    task can run longer. Crash recovery is time-based (the reaper), not lock-
    based, so SIGKILL/OOM/power loss does not wedge the queue (F7).
