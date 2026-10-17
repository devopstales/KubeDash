---
id: decision-019
title: "ADR-0019 Ingress Auth Integration"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0019-ingress-auth-integration.md`

# Ingress Auth Integration

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

OpenUnison is an **ingress-native** SSO solution: the ingress controller
(NGINX, Traefik, Istio, Gateway API) authenticates each request and forwards
the user's identity to the backend. This lets a fleet of applications
(Headlamp, Argo CD, Grafana, Vault, …) be secured by the ingress using one
auth authority, without each app re-implementing SSO. KubeDash today only
secures its **own** UI; it cannot protect *other* apps. We want KubeDash to be
the auth authority the ingress asks, so both KubeDash's UI and external apps
can be secured at the edge.

The constraint: the verify endpoint is on the **hot path** of every request to
every protected app, so it must be fast and must honour revocation (a logged-
out user must be rejected at the ingress, not just in KubeDash).

## Considered Options

- Each protected app implements OIDC SSO itself. Per-app work, per-app config,
  and no shared revocation — the status quo for external apps.
- A KubeDash **subrequest verify endpoint** that ingress controllers call via
  NGINX `auth_request`, Traefik `forwardauth`, Istio/Envoy `ext_authz`, or a
  Gateway-API `ext_authz`. One auth authority, shared revocation, per-app
  config is just ingress annotations.
- A service-mesh-only approach (Istio `ext_authz`). Clean, but excludes
  non-Istio clusters (NGINX/Traefik are the majority).

## Decision Outcome

Chosen option: "a `/auth/verify` subrequest endpoint for the major ingress
controllers", because it makes KubeDash the single auth authority across
NGINX/Traefik/Istio/Gateway API with shared revocation.

`GET /auth/verify?cluster=<name>` validates the request's KubeDash JWT or
session cookie and, on success, returns `200` + `X-Remote-User`,
`X-Remote-Groups`, `X-Remote-Cluster` headers; on failure, `401`. The ingress
calls it via `auth_request`/`forwardauth`/`ext_authz` and forwards the headers
to the backend. The ingress→KubeDash call is protected by mTLS or a shared
`X-Auth-Request-Auth` token (not open to clients). The endpoint checks the
same Redis `jti` revocation set as the main API (§ 5B.1 / ADR-0014), so logout
is honoured at the edge. For backends that trust only the forwarded headers
(can't verify KubeDash JWTs), KubeDash signs them with an HMAC
(`X-Auth-Signature`) so a compromised ingress cannot forge them.

### Consequences

- Good, because one auth authority secures KubeDash's UI **and** external
  apps, and revocation is shared (the edge uses the same deny-list as the
  API).
- Good, because per-app protection is just ingress annotations/values — no
  per-app code.
- Bad, because the verify endpoint is on the hot path of every protected
  request, so it must stay lean (JWT/cookie verify + a `users` lookup only)
  and be rate-limited.
- Bad, because header-trusting backends depend on the HMAC signing secret;
  if it is shared with the ingress, a compromise of the ingress leaks the
  ability to forge identity (mitigated by re-verifying the JWT where
  possible).
