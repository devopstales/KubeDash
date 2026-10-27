---
id: decision-030
title: "ADR-0030 Session revocation on Postgres: `revoked_jtis` deny-list table, replacing the Redis `jti` set"
date: '2026-10-27'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0030-session-revocation-on-postgres.md`

# Session revocation on Postgres: `revoked_jtis` deny-list table, replacing the Redis `jti` set

---
status: "accepted"
date: 2026-10-27
supersedes: ADR-0014
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

ADR-0014 (session revocation propagation) established the core guarantee:
logging out of the web session immediately invalidates the kubectl session and
the cert-based access path, not at token expiry. Its mechanism is an
**additive, TTL-bounded `jti` deny-list in Redis**: on logout the JWT's `jti`
is added to a Redis set with `TTL = JWT expiry` (15 min), and the JWT verify
hook checks that set on every request (the `/kubectl/auth/v1/token` endpoint
and the ADR-0019 ingress `/auth/verify` endpoint check it for KubeDash-issued
tokens).

ADR-0014 chose Redis for one reason, stated in its Consequences: *"to avoid a
DB hit on the request hot path."* That reason was sound **while Redis was
already a hard dependency** for the RQ broker — the deny-list reused a
dependency that was already up, so the hot-path `SISMEMBER` was "free."

ADR-0029 moves the task queue off Redis (onto a Postgres `tasks` table). After
that change, the session-revocation deny-list is **Redis's only remaining
consumer**. The question this ADR decides: **does the deny-list stay in Redis
(keeping Redis alive for one set), or does it move to Postgres so Redis can be
removed from the stack entirely?**

The constraint that shapes the answer: the deny-list is checked on the
**request hot path** (every authenticated request runs the verify hook). ADR-0014
explicitly optimized to keep a DB round-trip off that path. Moving it to
Postgres re-introduces a DB hit per request — the cost must be bounded.

#### Decision Drivers

- **Remove Redis entirely.** The strategic goal of ADR-0029 + this ADR is that
  Redis has zero consumers and is dropped from the chart, the dev compose, and
  `KUBEDASH_REDIS_URL`. The deny-list is the last consumer.
- **The hot-path lookup must stay cheap.** A per-request DB hit is acceptable
  only if it is a primary-key (or unique-index) lookup, not a scan. The cost
  delta versus a Redis `SISMEMBER` must be measured, not assumed.
- **Bounded, self-cleaning state.** The deny-list must not grow unbounded with
  user count; entries expire at the JWT lifetime (15 min), as in ADR-0014.
- **Cross-replica / cross-node visibility.** A revocation performed against one
  replica (or one active-active node) must be visible to every other — the same
  property ADR-0014 required of Redis.
- **Reuse the existing OIDC + CSR machinery.** The RP-initiated logout and CSR
  revocation halves of ADR-0014 are unchanged; only the *store* of the `jti`
  deny-list moves.
- **Air-gap (ADR-0020).** A Postgres table introduces no runtime egress; no new
  dependency (the DB is already required).

#### Considered Options

- **Keep the Redis `jti` set.** Preserves ADR-0014 exactly and keeps the
  hot-path check a sub-millisecond `SISMEMBER`. Rejected: it keeps Redis alive
  as a stateful dependency for a single set, defeating the "remove Redis" goal
  that ADR-0029 + this ADR exist to achieve.

- **`revoked_jtis` table in Postgres (chosen).** A table keyed on `jti` with an
  `expires_at`; the verify hook does a bounded PK lookup; a leader reaper
  deletes expired rows (replacing Redis TTL self-cleaning). Re-introduces a
  per-request DB hit, but bounded to a primary-key lookup, and removes Redis.

- **Short TTLs only (no deny-list).** Revert to relying on the 15-min JWT
  expiry. Rejected: it abandons ADR-0014's core guarantee (a logged-out /
  stolen token works until natural expiry), which was the whole point of the
  revocation work.

#### Decision Outcome

**Chosen option: `revoked_jtis` table in Postgres.**

Schema (added by an Alembic migration; replicated to every active-active node
by `autoddl`, per ADR-0031):

| Column | Type | Purpose |
|---|---|---|
| `jti` | `UUID` PK | the JWT `jti` (primary key — the hot-path lookup is a PK hit) |
| `expires_at` | `timestamptz` | when the entry self-expires (= the JWT's expiry, 15 min) |

A partial index `WHERE expires_at > now()` keeps the reaper's scan small and
keeps the table physically bounded to live entries.

**Revocation (logout).** `POST /auth/logout` performs, in addition to the
unchanged ADR-0014 steps (delete the `refresh_tokens` row; call the IdP
`end_session_endpoint`; revoke the user's CSR):

```sql
INSERT INTO revoked_jtis (jti, expires_at)
VALUES (:jti, now() + interval '15 minutes')
ON CONFLICT (jti) DO NOTHING;
```

**Verify hook (hot path).** On every authenticated request (and on
`/kubectl/auth/v1/token` and the ADR-0019 `/auth/verify` endpoint for
KubeDash-issued tokens):

```sql
SELECT 1 FROM revoked_jtis WHERE jti = :jti AND expires_at > now();
```

A row returned → the token is revoked → `401`. This is a **primary-key
lookup** (one row, index-only), not a scan. The `AND expires_at > now()`
predicate means a logically-expired but not-yet-reaped row does not false-
positive.

**Reaper (self-cleaning, replaces Redis TTL).** A leader task (folded into an
existing leader task, e.g. the `access_expiry` task once wired, or a small
dedicated task) runs periodically:

```sql
DELETE FROM revoked_jtis WHERE expires_at < now();
```

This replaces the Redis TTL self-cleaning: state is bounded to live (unreaped)
entries, and the partial index keeps both the delete and any residual scan
small.

##### Consequences

- Good, because **Redis is removed** from the chart, the dev compose, and
  `KUBEDASH_REDIS_URL` — after ADR-0029 (queue) and this ADR (revocation),
  Redis has zero consumers. Postgres is the only stateful dependency.
- Good, because the deny-list is now in the same engine as the rest of the
  auth state (`refresh_tokens`, users), so a revocation and the token records
  it references are transactionally coherent and both survive the same HA
  path (ADR-0031).
- Good, because cross-replica / cross-node visibility is inherited from
  Postgres (the row is replicated to every active-active node) — the same
  property ADR-0014 required of Redis, without a separate cache.
- Good, because air-gap safe (no new egress, no new dependency) and the state
  is bounded (partial index + reaper), matching ADR-0014's "self-cleaning"
  driver.
- Bad, because the verify hook now does a **DB hit on the request hot path** —
  the exact cost ADR-0014 optimized away. It is bounded to a PK lookup, but it
  is a real per-request round-trip that did not exist before. **This is the one
  performance risk in the change and must be benchmarked** (see Confirmation)
  before Redis is removed.
- Bad, because a Postgres outage now also interrupts revocation checking
  (previously a Redis outage interrupted it but Postgres was separate). Under
  ADR-0031 the two are the same HA-managed dependency, so this is not a *new*
  failure class — but it does mean the hot path and the data share a fate.
- Bad, because the cert path still requires the cluster's CA to support
  revocation (CRL/OCSP or bundle removal) — unchanged from ADR-0014, carried
  forward.

##### Confirmation

- **Benchmark (gate for removing Redis):** measure the verify-hook `SELECT`
  p50/p99 against the `revoked_jtis` PK at representative request rates, with
  the table at steady-state size (a day's worth of logouts, bounded by the
  reaper). Acceptance: the added per-request latency is within the budget the
  API already absorbs (to be fixed in the prototype; the ADR does not assume a
  number).
- Functional: log in, capture the `jti`, log out, replay the same JWT → `401`
  (deny-list hit) before the 15-min expiry; after the reaper deletes the
  expired row, a *new* token for the same user is not affected.
- Cross-node: revoke against node A of the active-active pair (ADR-0031); a
  request routed to node B returns `401` (the row replicated).
- The kubectl plugin's next `get-token` refresh fails after logout → browser
  re-auth (unchanged from ADR-0014). A revoked CSR is rejected by the K8s API
  server's client-CA check (unchanged).
- No `redis` import remains in the auth/verify path; `KUBEDASH_REDIS_URL` is
  removed from the chart, the dev compose, and `config.py`.

#### Pros and Cons of the Options

##### Keep the Redis `jti` set (ADR-0014 as-is)

- Good, because the hot-path check stays a sub-millisecond `SISMEMBER` with no
  DB round-trip.
- Neutral, because it is the proven, already-shipped mechanism.
- Bad, because it keeps Redis alive as a stateful dependency for a single set,
  blocking the "remove Redis" simplification.

##### `revoked_jtis` table in Postgres (chosen)

- Good, because it removes Redis's last consumer, making Postgres the only
  stateful dependency; cross-node visibility is inherited; air-gap safe; bounded.
- Neutral, because the lookup is a PK hit (cheap), and the OIDC/CSR halves of
  revocation are unchanged.
- Bad, because it puts a (bounded) DB hit on the request hot path — the cost
  ADR-0014 optimized away — and must be benchmarked before Redis is dropped.

##### Short TTLs only (no deny-list)

- Good, because it is the simplest (no deny-list state at all).
- Neutral, because short-lived JWTs are already in place.
- Bad, because it abandons ADR-0014's guarantee — a logged-out / stolen token
  works until natural expiry.

#### More Information

- Supersedes ADR-0014 (session revocation propagation). The ADR-0014 file is
  retained untouched (IRON RULE); its `## LOCKED` row is flipped to "In force:
  no". The guarantee (logout invalidates kubectl + cert access immediately) is
  preserved; only the *store* of the `jti` deny-list moves from Redis to
  Postgres.
- Pairs with ADR-0029 (queue on Postgres): together they remove Redis's last
  two consumers. Neither is sufficient alone to drop Redis.
- The active-active topology that replicates the `revoked_jtis` row to every
  node is ADR-0031 (pgEdge/Spock). The ingress verify endpoint (ADR-0019)
  reuses the same table.
- Revisit trigger: if the verify-hook benchmark shows the PK lookup is
  unacceptable at target request rates, the fallback is a **short-TTL
  in-process (per-replica) L1 cache in front of the table** (revocations are
  rare; a per-replica 1–2 s cache absorbs the hot path while the table remains
  the source of truth) — not a return to Redis.
