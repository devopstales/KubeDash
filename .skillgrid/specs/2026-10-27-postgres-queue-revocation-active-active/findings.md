# Findings — postgres-queue-revocation-active-active

Consolidated prototype/sketch verdicts for the Postgres queue + revocation +
active-active change (ADR-0029 / ADR-0030 / ADR-0031). `writing-blueprints`
reads this; it does not re-run the experiments.

## Prototype: 001-pgqueue-fence-revocation

- **Verdict:** VALIDATED ✓ (SQL semantics + pgEdge two-node topology)
- **What we learned:**
  - `FOR UPDATE SKIP LOCKED` gives exactly-once claim under 10-way concurrency
    (10 distinct rows, 0 double-claimed).
  - The strict `fence` token correctly rejects a stale leader's writes
    (stale fence → 0 rows; current fence → 1 row) under an LWW split-brain.
  - The reaper re-queues stale in-flight jobs with `LEAST(cap, base*5^attempts)`
    backoff and dead-letters at `attempts >= 3`.
  - **The verify-hook hot path is ~0.03–0.07 ms** (PK Index Only Scan at 50k
    rows) — faster than Redis `SISMEMBER`, so dropping Redis for the
    deny-list is not a regression. The 263 ms seen in a first pass was the
    `gen_random_uuid()` *function call* in the WHERE clause confusing the
    planner, not the lookup.
  - `CREATE INDEX … WHERE expires_at > now()` is **invalid** (`now()` is
    STABLE, not IMMUTABLE) — use a plain index or none; the reaper bounds the
    table.
  - pgEdge image: **use Docker Hub `pgedge/pgedge:pg17-latest`** (Spock 5.0.1,
    PG 17.6) — pulls publicly, no auth. The ghcr image is org-gated (403 here).
    **Two-node topology validated on a live cluster:** cross-node DML
    replication, `autoddl` DDL propagation, and a cluster-wide `FOR UPDATE SKIP
    LOCKED` claim (12 claimers across 2 nodes, 0 double-claimed). `db.json`
    must include the `pgedge` internal_admin user; hostnames must match the
    compose service names; Spock wires on boot in ~30 s.
- **What's liftable:** `schema.sql` (DDL, modulo the F1 index fix) and the
  claim/reaper/fence SQL in `runA.sh`/`runB.sh`/`runC.sh` → the Alembic
  migration + `wsgi.py` worker + `leader.py` fence.
- **Constraints for the build:**
  1. Bind `jti` as a parameter in the verify hook; no function in the WHERE
     clause (0.03 ms vs 263 ms).
  2. No partial `now()` index; plain index or none.
  3. Fence every write (`WHERE fence = :my_fence`); acquire =
     `UPDATE … fence=fence+1 … RETURNING fence`.
  4. Reaper backoff `LEAST(cap, base*5^attempts)`, dead-letter at
     `attempts >= 3`.
  5. Use Docker Hub `pgedge/pgedge:pg17-latest` (public pull); `db.json` needs
     the `pgedge` internal_admin user + hostnames matching compose service
     names; Spock wires in ~30 s.
