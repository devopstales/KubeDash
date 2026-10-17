# Session revocation propagation

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

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

## Considered Options

- Per-token stateful check in the database on every request (a revocation
  column / lookup). Correct but adds a DB hit to the hottest path.
- An additive Redis `jti` revocation set, TTL-bounded to the JWT lifetime.
  Fast, shared across replicas, self-cleaning. Revocation is a deny-list, not
  per-token state.
- Rely on short token TTLs alone (no revocation). Simplest, but does not meet
  the guarantee — a stolen token works until it expires.

## Decision Outcome

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

### Consequences

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
