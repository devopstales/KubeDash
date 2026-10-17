# Session revocation propagation

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash issues two kinds of credential that derive from the same login: the
web-session JWT and the kubectl credential-plugin token (and, for cert-based
access, a KubeDash-serving CSR certificate). Today, ending the web session
(Flask logout) does not invalidate the kubectl session — a logged-out user's
`kubectl` keeps working until the token's natural expiry. OpenUnison's
distinguishing guarantee is that *logging out of the web session invalidates
the kubectl session too*. We need the same property: revocation must propagate
across every credential path immediately, not at natural expiry.

The constraint: KubeDash is multi-replica (N followers), so a revocation must
be visible to every replica without a DB round-trip on the hot path.

#### Decision Drivers

- Revocation must be **immediate**, not bounded by token TTL — a logged-out
  user's `kubectl` must stop working now.
- Revocation must be visible to **every replica** without a DB hit on the
  request hot path.
- It must cover **all three credential paths**: web JWT, kubectl plugin token,
  and the cert-based (CSR) path.
- Revocation state must be **bounded** (self-cleaning) so it does not grow
  unbounded with user count.
- It must reuse the existing OIDC and CSR machinery (no new IdP or CA
  dependency).

#### Considered Options

- Per-token stateful check in the database on every request (a revocation
  column / lookup).
- An additive Redis `jti` revocation set, TTL-bounded to the JWT lifetime,
  plus OIDC RP-initiated logout and CSR revocation.
- Rely on short token TTLs alone (no revocation).

#### Decision Outcome

Chosen option: "additive Redis `jti` revocation set + OIDC RP-initiated
logout + CSR revocation", because it gives immediate cross-replica revocation
without a DB hit on the hot path, and it covers all three credential paths.

On `POST /auth/logout` KubeDash: (1) deletes the `refresh_tokens` row;
(2) adds the JWT `jti` to a Redis revocation set with TTL = JWT expiry (15
min); (3) calls the IdP's `end_session_endpoint` (RP-initiated logout) so the
IdP revokes the refresh token used by the kubectl plugin; (4) revokes the
user's KubeDash-serving CSR (cert path). The JWT verify hook checks the
revocation set on every request; the `/kubectl/auth/v1/token` endpoint checks
it for KubeDash-issued tokens.

##### Consequences

- Good, because a logout immediately kills web, kubectl (token), and cert
  access — matching the OpenUnison guarantee.
- Good, because the revocation set is Redis (shared across replicas) and
  self-cleans at the 15-min TTL, so there is no unbounded state and no DB hit
  on the hot path.
- Bad, because it adds a dependency on Redis being up for the verify hook to
  fully honour revocation (Redis is already a hard dependency for the RQ
  broker and rate limiting, so this is not a new failure class).
- Bad, because the cert path requires the cluster's CA to support revocation
  (CRL/OCSP or bundle removal); clusters that pin a static CA bundle must be
  told to watch it.

##### Confirmation

- A logout test: log in, capture the `jti`, log out, then replay the same JWT
  → expect `401` (revocation set hit) before the 15-min TTL.
- The kubectl plugin's next `get-token` refresh fails after logout → browser
  re-auth is triggered.
- A revoked CSR is rejected by the K8s API server's client-CA check.

#### Pros and Cons of the Options

##### Per-token stateful DB check

Add a revocation column / lookup checked on every request.

- Good, because it is exact and does not depend on a separate cache.
- Neutral, because it reuses the existing Postgres.
- Bad, because it puts a DB hit on the request hot path of every request, in
  a multi-replica system.

##### Redis jti revocation set + RP-initiated logout + CSR revocation (chosen)

An additive, TTL-bounded deny-list in Redis, combined with the IdP
end-session and CSR revocation.

- Good, because immediate, cross-replica, no DB hit on the hot path, and it
  covers all three credential paths.
- Good, because the set is self-cleaning at the 15-min TTL (bounded state).
- Bad, because it depends on Redis availability for the verify hook.
- Bad, because the cert path needs CA-side revocation support (CRL/OCSP or
  bundle removal).

##### Short TTLs only (no revocation)

No revocation mechanism; rely on the 15-min JWT / short token lifetimes.

- Good, because it is the simplest option (no new state, no logout wiring).
- Neutral, because it is already partly in place (short-lived JWTs).
- Bad, because it does not meet the guarantee — a stolen or logged-out token
  works until its natural expiry.

#### More Information

- OpenUnison documents this as its core security guarantee.
- Related: ADR-0011 (kubectl credential plugin), ADR-0019 (the ingress verify
  endpoint reuses the same `jti` revocation set).
