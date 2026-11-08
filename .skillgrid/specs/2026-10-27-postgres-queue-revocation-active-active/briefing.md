# Briefing — Postgres queue, session revocation, OIDC state, SAR cache, active-active Postgres

**Status:** PROPOSED
**Tier:** T3 (high-risk: migration, auth hot path, concurrency, dev-infra switch)
**Build shape:** Tracer thread (the queue end-to-end — migrate → enqueue → claim → run → reap — is the first working slice; revocation/session/SAR/fence and the Redis removal thicken around it)
**Spec:** this change. **Decisions:** ADR-0029, ADR-0030, ADR-0031.

## Context

KubeDash's only stateful dependencies beyond Postgres are **Redis** (the RQ task broker, the `jti` revocation deny-list, the OIDC `state` CSRF nonce, and the SAR verdict cache) and the RQ/Redis broker for the leader-only periodic tasks. Under active-active Postgres the Redis dependency is the weak link: it is an extra stateful service that must itself be HA, and it holds auth state on a per-request hot path.

This change moves **all four** Redis consumers to Postgres and drops Redis entirely, and runs Postgres **active-active** (pgEdge/Spock, multi-primary) instead of active-passive.

## Requirements (falsifiable)

1. **Task queue on Postgres (ADR-0029).** A `tasks` table with `FOR UPDATE SKIP LOCKED` claim; a leader-only reaper re-queues stale `processing` rows on a time-based interval (not lock-based); failed tasks retry 3× with `LEAST(cap, base*5^attempts)` backoff then dead-letter. No Redis/RQ.
2. **Session revocation on Postgres (ADR-0030).** A `revoked_jtis` table (PK `jti`). `POST /auth/logout` inserts the access-token `jti` (TTL = access-token lifetime); `verify_jwt` raises 401 on a hit. The lookup is a PK lookup with `jti` bound as a parameter (no function in the WHERE clause).
3. **OIDC state (session store) on Postgres.** A `kv` table (generic TTL key-value). `new_state()`/`consume_state()` store and one-shot-delete the CSRF nonce; a mismatch/already-consumed state → `StateMismatchError`.
4. **SAR verdict cache on Postgres.** `rbac.can` reads/writes the `kv` table under the unchanged `sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>` key (ADR-0004 addendum: every SAR attribute in the key); a hit never re-asks the cluster.
5. **Strict fence (ADR-0031).** `leader_lease` gains a monotonic `fence` column. Acquire = `INSERT … fence=fence+1 … ON CONFLICT DO UPDATE … RETURNING fence`; the stale check stays as a fast path but the fence is the cross-node LWW (the advisory lock is session-local, not a cross-node mutex). Every leader write is fenced `WHERE fence = :my_fence`; a fenced-out leader demotes on 0 rows.
6. **Active-active dev topology (ADR-0031).** The dev default is a two-node `pgedge/pgedge:pg17-latest` cluster (Spock, `autoddl`). `db.json` includes the `pgedge` internal_admin user; node hostnames match the compose service names. Redis is dropped from the dev stack.
7. **Redis removed from the stack.** No module in `backend/app` references `redis_client` or `flask_redis`; `flask-redis` is out of `pyproject.toml`; `KUBEDASH_REDIS_URL`/`redis_url` are gone from config.

## Intent / non-goals

- **In:** the four Redis consumers, the fence, the dev compose, the dependency/config removal.
- **Out:** the Helm chart's Postgres section and the prod active-active rollout (a follow-on change; this change delivers the code + migrations + dev topology). The SAR cache's *value* (the verdict) is unchanged — only its storage backend moves.
- **Not a perf target:** Postgres PK lookups at ~0.03–0.07 ms (prototype-validated) are *faster* than Redis `SISMEMBER`, so the revocation hot path is not a regression.

## Constraints (from `findings.md`)

- Bind `jti` and `kv` keys as **parameters** — no function in the WHERE clause (findings #1).
- No partial index with `now()` in the predicate (`now()` is STABLE, not IMMUTABLE) — plain index or none (findings #2).
- Fence every leader write; acquire returns the new fence (findings #3).
- Reaper backoff `LEAST(cap, base*5^attempts)`, dead-letter at `attempts >= 3` (findings #4).
- Docker Hub `pgedge/pgedge:pg17-latest`; `db.json` needs the `pgedge` user + matching hostnames (findings #5).
- Reaper interval > longest task runtime; crash recovery is time-based (findings #6).

## Threats (drives the threat matrix in the blueprint)

- **Concurrency:** two replicas / two pgEdge nodes claiming the same queue row.
- **Crash / unplanned exit:** SIGKILL/OOM mid-claim or mid-lease.
- **Auth hot path:** `verify_jwt` runs per request; the revocation lookup must stay a fast PK lookup.
- **Split-brain:** two leaders believing they are leader under active-active; the fence is the tiebreaker.
- **Migration one-way:** the `fence` column + three new tables.

## Fast-Track classification

**standard / risky** — full pipeline mandatory (migration, new trust boundary on the auth hot path, multi-domain impact: auth + RBAC + queue + leader + infra, well over 400 lines). No fast-track waiver.
