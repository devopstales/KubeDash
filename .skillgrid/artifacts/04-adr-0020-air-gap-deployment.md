# Air-Gap Deployment

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash must run in **network-isolated** environments (defense, financial,
OT/IT-converged, regulated) with **no outbound internet at runtime**. Today
the design makes outbound calls (OIDC discovery on start, IdP token exchange,
image pulls, chart repo fetches) that break in an air gap. OpenUnison
documents a first-class air-gap mode. We need KubeDash to install and operate
with zero external calls at runtime.

The key question is the boundary: **air-gap ≠ no-IdP.** An air-gapped site
still has an IdP — it is just on the *internal* network. The decision is what
"zero outbound calls" means and what is deferred.

#### Decision Drivers

- **Zero outbound calls at runtime** — no phoning home, no image pulls, no
  chart repo fetches, no telemetry.
- The design must **reuse the existing local-JWT + OIDC** path (no new auth
  mechanism) — the IdP is on the internal network.
- Isolation must be **verifiable**, not just claimed (an egress check).
- It must be a **single switch** (`airGap.enabled`), not a bag of individual
  toggles easy to misconfigure.
- The boundary must be explicit: **what is deferred** (no-IdP / local password
  mode).

#### Considered Options

- Require no IdP at all (local username/password).
- Keep the OIDC design but make every outbound call internal/cached: local
  JWTs, cached JWKS/discovery, pre-loaded images, offline CLI, vendored Helm.
- A hybrid "air-gap profile" that disables each outbound call individually.

#### Decision Outcome

Chosen option: "keep OIDC, make every outbound call internal/cached, behind a
single `airGap.enabled` switch", because it achieves zero outbound calls at
runtime without a new auth path, and the IdP is on the internal network.

With `airGap.enabled: true`: (1) the hot path uses **local JWTs** (HS256,
signed by `KUBEDASH_JWT_SECRET`) — the IdP is reached only at login/refresh,
and only on the internal network; (2) OIDC discovery + JWKS are **cached**
(Postgres + a mounted file) and hot-reloaded on file change, with no live
re-discovery; (3) `imagePullPolicy: IfNotPresent` on all containers, with
images pre-loaded into the cluster registry; (4) the `kubectl kubedash`
binary is distributed as a file (not Krew's network fetch); (5) Helm chart +
subcharts are vendored into the air-gap bundle; (6) observability backends are
optional internal endpoints. A `airGap.outboundCheck` fails `/readyz` if an
unexpected external egress is attempted.

##### Consequences

- Good, because air-gap works without a new auth path — the existing local-
  JWT + internal-IdP design already satisfies "no internet at runtime".
- Good, because a single `airGap.enabled` switch + an egress check makes the
  isolation verifiable, not just claimed.
- Bad, because a pure **no-IdP** (local password) mode is **not** covered —
  it is deferred (§ 11) and needs its own ADR when pursued.
- Bad, because JWKS rotation and chart/plugin updates are manual (re-mount the
  JWKS file, re-bundle the chart) — there is no auto-update in an air gap.

##### Confirmation

- With `airGap.enabled: true`, a runtime egress to a non-internal host fails
  `/readyz` (`airGap.outboundCheck`).
- Login works against the internal IdP; the hot path makes no IdP call (local
  JWT verified).
- The cluster starts with no image pulls (`IfNotPresent`) and no chart repo
  fetch (vendored chart).
- Re-mounting the JWKS file hot-reloads (no restart) on key rotation.

#### Pros and Cons of the Options

##### No-IdP (local username/password)

A local user store + password hashing + local token issuer.

- Good, because maximum isolation (no IdP dependency at all).
- Neutral, because it is a self-contained auth path.
- Bad, because a large new auth mechanism most air-gapped sites don't need
  (they have an on-prem IdP); deferred to § 11.

##### Keep OIDC, make calls internal/cached, single switch (chosen)

Local JWTs + cached JWKS + pre-loaded images + offline CLI + vendored Helm,
behind `airGap.enabled`.

- Good, because zero outbound calls at runtime without a new auth path; the
  internal IdP is reused; isolation is verifiable via the egress check.
- Bad, because no-IdP (local password) mode is not covered (deferred).
- Bad, because JWKS/chart/plugin updates are manual in an air gap.

##### Hybrid per-call toggles

Disable each outbound call individually.

- Good, because fine-grained control.
- Neutral, because it reuses the existing code paths.
- Bad, because a bag of toggles is easy to misconfigure; a single
  `airGap.enabled` switch is safer and easier to verify.

#### More Information

- OpenUnison's air-gap knowledgebase is the reference pattern.
- Related: ADR-0001 (local JWTs), ADR-0011/0019 (the CLI + verify endpoint are
  internal calls in air-gap), § 11 (the deferred no-IdP mode).
