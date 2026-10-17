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

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

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

#### Decision Drivers

- One **auth authority** must secure KubeDash's UI *and* external apps (no
  per-app SSO re-implementation).
- The verify endpoint is on the **hot path** — it must be fast (lean
  verification) and rate-limited.
- **Revocation must be shared**: a logged-out user is rejected at the edge,
  not just in KubeDash.
- It must work across the **major ingress controllers** (NGINX, Traefik,
  Istio, Gateway API), not just one.
- Forwarded identity headers must be **tamper-evident** for backends that trust
  headers only.

#### Considered Options

- Each protected app implements OIDC SSO itself.
- A KubeDash **subrequest verify endpoint** that ingress controllers call via
  NGINX `auth_request`, Traefik `forwardauth`, Istio/Envoy `ext_authz`, or a
  Gateway-API `ext_authz`.
- A service-mesh-only approach (Istio `ext_authz`).

#### Decision Outcome

Chosen option: "a `/auth/verify` subrequest endpoint for the major ingress
controllers", because it makes KubeDash the single auth authority across
NGINX/Traefik/Istio/Gateway API with shared revocation.

`GET /auth/verify?cluster=<name>` validates the request's KubeDash JWT or
session cookie and, on success, returns `200` + `X-Remote-User`,
`X-Remote-Groups`, `X-Remote-Cluster` headers; on failure, `401`. The ingress
calls it via `auth_request`/`forwardauth`/`ext_authz` and forwards the headers
to the backend. The ingress→KubeDash call is protected by mTLS or a shared
`X-Auth-Request-Auth` token (not open to clients). The endpoint checks the
same Redis `jti` revocation set as the main API (ADR-0014), so logout is
honoured at the edge. For backends that trust only the forwarded headers
(can't verify KubeDash JWTs), KubeDash signs them with an HMAC
(`X-Auth-Signature`) so a compromised ingress cannot forge them.

##### Consequences

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

##### Confirmation

- A request with a valid KubeDash JWT → `/auth/verify` returns `200` +
  `X-Remote-User`/`X-Remote-Groups`; the backend sees the identity.
- A logged-out (revoked) JWT → `401` at the edge (same `jti` set as the API).
- An ingress without the `X-Auth-Request-Auth` token / mTLS → the verify call
  is rejected (not open to clients).
- A header-trusting backend verifies the `X-Auth-Signature` HMAC.

#### Pros and Cons of the Options

##### Each app implements OIDC SSO itself

Per-app SSO, per-app config.

- Good, because no shared dependency on KubeDash for auth.
- Neutral, because it is the common status quo.
- Bad, because per-app work + config, no shared revocation, no single authority
  — the problem we are trying to remove.

##### KubeDash subrequest verify endpoint (chosen)

The ingress calls `/auth/verify`; KubeDash is the single auth authority.

- Good, because one authority across NGINX/Traefik/Istio/Gateway API; shared
  revocation; per-app protection is just annotations; headers are HMAC-signed
  for header-trusting backends.
- Bad, because the verify endpoint is on the hot path (must stay lean +
  rate-limited).
- Bad, because header-trusting backends depend on the HMAC secret shared with
  the ingress.

##### Service-mesh-only (Istio ext_authz)

Auth only via the mesh's `ext_authz`.

- Good, because clean for Istio-native clusters.
- Neutral, because it reuses Envoy's authz.
- Bad, because it excludes non-Istio clusters (NGINX/Traefik are the
  majority).

#### More Information

- OpenUnison's ingress integrations (NGINX/Traefik/F5/Istio/Gateway API) are
  the reference pattern.
- Related: ADR-0014 (the verify endpoint reuses the `jti` revocation set),
  ADR-0020 (air-gap: the verify endpoint is an internal call).
