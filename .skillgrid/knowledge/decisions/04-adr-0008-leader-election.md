# Leader election via PG advisory lock + lease table

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

The chart deploys N identical replicas (all `kubedash_role=leader` —
"candidates"); exactly one must run the RQ worker and the periodic
tasks (ADR-0006/0007), while all replicas serve HTTP. The election
needs: no new infrastructure (Postgres is already the metadata DB), no
split-brain, and failover fast enough that periodic tasks don't gap
visibly (target: < 15 s).

#### Decision Drivers

- **No new dependency.** K8s Lease objects and etcd/Consul add either a
  coupling to the platform or a new datastore; Postgres is the
  system-of-record anyway.
- **Atomic acquisition.** Two replicas must never both believe they
  hold the lease; the acquisition must be a single atomic step.
- **Observable state.** The lease row is inspectable by the operator
  (`replica_id`, `acquired_at`, `heartbeat_at`, `token`).

#### Considered Options

- **Kubernetes Lease API.** Rejected: couples the app to its own
  deployment platform (breaks the "any PG-backed install" shape).
- **Row-lock hand-off (`SELECT ... FOR UPDATE`)** alone. Rejected as the
  primary mechanism: a row lock doesn't bound how long a dead leader's
  claim persists without an explicit staleness test.
- **Postgres advisory lock + `leader_lease` table (CHOSEN).** The
  advisory lock gives atomic mutual exclusion; the lease row gives
  observable state and the staleness test.

#### Decision Outcome

**Chosen option: `pg_try_advisory_lock(hashtext(replica_id))` + a
single-row `leader_lease` table.**

- `backend/app/core/leader.py`: acquisition is
  `SELECT pg_try_advisory_lock(hashtext(:rid))` (non-blocking;
  `pg_advisory_unlock` on release); the lease row (`id = 1`) is
  upserted with `replica_id`, `token` (UUID), `acquired_at`,
  `heartbeat_at`.
- The leader heartbeats `heartbeat_at` every **5 s**; any replica
  treating `heartbeat_at` as stale after **10 s** attempts acquisition;
  followers poll at 1 s. In-memory `is_leader` flag drives the RQ
  worker (it idles when not leader).
- Failover: leader dies → advisory lock released by Postgres → a
  follower's next poll acquires → its worker starts. No data loss;
  in-flight RQ tasks retry under RQ's policy.

##### Consequences

- Good: zero new infra; atomic (the lock is the arbiter); observable
  row; failover bounded by the 10 s staleness window.
- Bad: a Postgres outage pauses election (HTTP still serves); the
  advisory lock is session-scoped — a network partition that keeps the
  old leader's PG session alive delays failover until the session
  drops.
- Confirmation: `backend/tests/test_leader.py`
  (`test_single_replica_becomes_leader`,
  `test_second_replica_does_not_double_lead`,
  `test_failover_after_leader_stop_is_fast`), `test_worker_gate.py`.

#### Linking Decisions and Constraints

- ADR-0006 / ADR-0007 — the elected leader is the only replica running
  the in-process RQ worker.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §3.7; verified
against `backend/app/core/leader.py` (advisory-lock SQL, intervals) on
2026-11-06.
