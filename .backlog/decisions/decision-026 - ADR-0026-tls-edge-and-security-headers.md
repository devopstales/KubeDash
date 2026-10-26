---
id: decision-026
title: "ADR-0026 TLS edge + security header layer"
date: '2026-10-24'
status: superseded
---

Source: `.skillgrid/knowledge/decisions/04-adr-0026-tls-edge-and-security-headers.md`

# ADR-0026: TLS edge + security header layer

## Status

accepted — 2026-10-24

## Context

The 5.0 rebase (`rebase` branch) dropped the security layer that 4.1 carried in
`src/kubedash/lib/initializers/security.py`. Verified absent on rebase: CSP (with
per-request nonce), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
COOP/CORE, X-XSS-Protection, and ProxyFix. Two concrete gaps fall out:

1. **The `Secure` cookie flag is a lie in dev.** ADR-0025 parks the session in
   HttpOnly cookies with `Secure` on by default; the dev stack sets
   `KUBEDASH_COOKIE_SECURE=false` because it speaks plain `http://localhost:8080`,
   where a `Secure` cookie is stored but never sent back. The flag's meaning —
   "the cookie only travels over TLS" — is lost on the one environment where
   auth bugs are actually found.
2. **The browser has no defense against XSS-on-session.** The access cookie is
   HttpOnly, so XSS cannot *read* the JWT, but it can still *act* on the session
   (fetch with credentials). 4.1 answered this with a nonce-bearing CSP; rebase
   answers with nothing.

The 4.1 codebase's answer to the dev-TLS half was an nginx TLS terminator
(`deploy/docker-compose/dc-nginx.yaml` + `config/nginx-kubedash.conf`) with a
mkcert root CA and the hostname `kubedash.k3s.intra` in `/etc/hosts`.

## Decision

Restore both layers, adapted to the rebase topology:

- **TLS edge (dev stack).** An `nginx` service in `dev/docker-compose.yml`
  terminates TLS on `kubedash.local:443` (mkcert cert; rootCA already trusted in
  the host keychain) and proxies to the backend **over HTTPS**
  (`proxy_pass https://` + `proxy_ssl_verify on` with the mkcert rootCA as
  `proxy_ssl_trusted_certificate`). Port 80 redirects to 443. The backend gains
  a TLS listener on `:8443` (self-signed by the same rootCA).
- **ProxyFix.** `wsgi.py` wraps the WSGI app with
  `ProxyFix(x_for=1, x_proto=1, x_host=1, x_prefix=1)` when
  `KUBEDASH_TLS_EDGE=true`. Without the flag the app behaves exactly as today
  (plain-HTTP dev fast path, test client).
- **Header layer.** A new `backend/app/core/security_headers.py` registers
  before/after-request hooks in `create_app`:
  - per-request CSP nonce (`secrets.token_urlsafe(16)`), policy:
    `default-src 'self'; font-src 'self'; style-src 'self' 'unsafe-inline';
    script-src 'self' 'nonce-…'; connect-src 'self' wss: ws:; img-src 'self' data:`
  - HSTS `max-age=31536000; includeSubDomains` — emitted only when the request
    arrived over TLS (`request.is_secure`), so plain-HTTP never gets a
    misleading header;
  - `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
    `Referrer-Policy: strict-origin-when-cross-origin`,
    `Cross-Origin-Opener-Policy: same-origin`,
    `Cross-Origin-Embedder-Policy: require-corp`,
    `Cross-Origin-Resource-Policy: same-origin`;
  - `Cache-Control: no-store` + `Pragma: no-cache` + `Expires: 0` **on
    `/api/*` only** — never global, so the ADR-0006 asset caching contract
    (`assets/` immutable, `index.html` no-cache) is preserved.
- **Consequence (recorded, not enforced here):** the OIDC `redirect_uri` for
  local dev is `https://kubedash.local:443/api/v1/auth/callback` — the IdP
  registration must advertise the edge origin.

## Options considered

- **`KUBEDASH_COOKIE_SECURE=false` for dev (the 4.1 model).** Rejected: it keeps
  the flag dishonest in dev, and 4.1's own nginx terminated TLS for a reason —
  the flag exists to catch exactly the misconfiguration this hides.
- **Trusting the `X-Forwarded-Proto` header without ProxyFix (config flag).**
  Rejected: hand-rolled forwarded-header trust is how the classic
  "HSTS on plain HTTP" and "secure cookie over HTTP" bugs are born; ProxyFix is
  the 8-line stdlib solution 4.1 already used.
- **Per-route `no-store` headers (extending the existing three in auth.py).**
  Rejected: it scatters the invariant across every future domain API; an
  after-request hook scoped to `/api/*` makes it one rule.

## Consequences

- The dev stack's browser surface is `https://kubedash.local:443`; e2e runs
  against it with the mkcert rootCA (Playwright `ignoreHTTPSErrors` is NOT used —
  the point is a verifying chain).
- `fe-dev` (vite :3000) and the direct `:8080` fast path remain plain HTTP with
  `KUBEDASH_COOKIE_SECURE=false` — a documented, deliberate carve-out, not the
  default.
- COEP `require-corp` can break cross-origin resource loads; the air-gap
  (ADR-0020) means all loads are `'self'`, so it should hold — the e2e suite is
  the backstop.
- The Helm chart (in-cluster) needs no change: the ingress already terminates
  TLS (ADR-0019), and the header layer applies to the app regardless of who
  terminates.

## Deviations from 4.1 (recorded)

- X-XSS-Protection is not set (deprecated; the CSP covers it).
- No embedded-app CSP/COOP relaxation (no `app_catalog`/`iframe_proxy` in 5.0).
- `no-store` scoped to `/api/*`, not global.
