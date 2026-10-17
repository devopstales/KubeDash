---
id: decision-020
title: "ADR-0020 Air-Gap Deployment"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0020-air-gap-deployment.md`

# Air-Gap Deployment

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

KubeDash must run in **network-isolated** environments (defense, financial,
OT/IT-converged, regulated) with **no outbound internet at runtime**. Today
the design makes outbound calls (OIDC discovery on start, IdP token exchange,
image pulls, chart repo fetches) that break in an air gap. OpenUnison
documents a first-class air-gap mode. We need KubeDash to install and operate
with zero external calls at runtime.

The key question is the boundary: **air-gap ≠ no-IdP.** An air-gapped site
still has an IdP — it is just on the *internal* network. The decision is what
"zero outbound calls" means and what is deferred.

## Considered Options

- Require no IdP at all (local username/password). Most isolated, but a large
  new auth path (local user store, password hashing, local token issuer) that
  most air-gapped sites don't need — they have an on-prem IdP.
- Keep the OIDC design but make every outbound call internal/cached: local
  JWTs (already the design), cached JWKS/discovery, pre-loaded images, offline
  CLI, vendored Helm. The IdP is on the internal network. Air-gap without a
  new auth path.
- A hybrid "air-gap profile" that disables each outbound call individually.
  Fine-grained but easy to misconfigure; a single `airGap.enabled` switch is
  safer.

## Decision Outcome

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

### Consequences

- Good, because air-gap works without a new auth path — the existing local-
  JWT + internal-IdP design already satisfies "no internet at runtime".
- Good, because a single `airGap.enabled` switch + an egress check makes the
  isolation verifiable, not just claimed.
- Bad, because a pure **no-IdP** (local password) mode is **not** covered —
  it is deferred (§ 11) and needs its own ADR when pursued.
- Bad, because JWKS rotation and chart/plugin updates are manual (re-mount the
  JWKS file, re-bundle the chart) — there is no auto-update in an air gap.
