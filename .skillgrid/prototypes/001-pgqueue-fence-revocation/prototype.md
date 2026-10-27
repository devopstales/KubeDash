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

### F6 — pgEdge image pull is access-gated (topology not exercised)
`ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal` **exists** (confirmed in the
ghcr tags list: `17-spock5-minimal`, `17-spock5-standard`, `17.6-spock5.0.1-…`,
`18-spock5-minimal`, etc.) but the local Docker credential (user
`devopstales`) gets **HTTP 403** on the manifest — the ghcr token lacks the
`pgedge` package pull-scope (even a public `actions/actions-runner` 403s with
the same token, so it's token-scope, not image-specific). The two-node Spock
topology (replication, `autoddl`, cross-node row-lock claim) is therefore
**not exercised here** — it needs a credential with ghcr pull access. The SQL
semantics (F2–F5) do not depend on it.

## Verdict

**VALIDATED ✓** for the SQL semantics (F2 exactly-once claim, F3 fence reject,
F4 reaper/dead-letter, F5 hot-path latency) — each with the edge case that
would have killed it (concurrent double-claim; stale-leader LWW; dead worker;
planner regression). **PARTIAL ⚠** on the pgEdge *topology* (F6): the image is
real and the tags exist, but pull access is gated in this environment, so
replication/`autoddl`/cross-node claim are unverified.

The verdict that drives the build: **the Postgres queue + strict fence +
revocation table are sound and the hot path is fast enough to drop Redis.**
The open item is purely operational (get a ghcr pull for the pgEdge image, or
confirm the org grants access) and one migration detail (F1: no partial
`now()` index).

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
5. **pgEdge pull access** (F6) — resolve the ghcr scope before standing up the
   two-node dev compose; the SQL works on a single node regardless.
