# TLS Edge + Security Headers — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-24-tls-security-headers`
**Date:** 2026-10-24
**ADR:** `../../artifacts/04-adr-0026-tls-edge-and-security-headers.md`

## Intent

The 5.0 rebase dropped the security-header layer the 4.1 codebase had
(`src/kubedash/lib/initializers/security.py`): no CSP, no HSTS, no COOP/CORE,
no X-Frame-Options, no ProxyFix. Two gaps fall out of that:

1. **The dev stack speaks plain HTTP.** `KUBEDASH_COOKIE_SECURE=false` is set
   so the `Secure` cookie works at all (ADR-0025 delivery contract). The
   cookie flag's meaning is lost in dev: a `Secure` cookie that is never sent
   back over HTTP is a flag the app had to lie about.
2. **The browser gets no header defense.** The SPA holds an HttpOnly access
   cookie (ADR-0025); XSS can't read it but can still *act* on the session
   (fetch with credentials). 4.1 defended with a nonce-bearing CSP; rebase
   has no defense at all.

Restore both: an nginx TLS edge for the local stack (edge-terminated, with
internal HTTPS so the `Secure` cookie is honest end-to-end), ProxyFix on the
Flask side, and the full 4.1 security-header set as a new `core` module.

## Requirements

### R1 — A TLS edge terminates for the local stack

The dev stack MUST serve `https://kubedash.local:443` with a certificate the
host's browser trusts (mkcert rootCA installed in the system trust store).
Port 80 MUST redirect to 443. The edge proxies to the backend over **HTTPS**
(nginx → backend TLS) so the `Secure` cookie flag is truthful on both legs:
the browser leg and the internal leg.

### R2 — The backend trusts the proxy

When the app runs behind the TLS edge (`KUBEDASH_TLS_EDGE=true`), the WSGI
app MUST apply ProxyFix (`x_for=1, x_proto=1, x_host=1, x_prefix=1`) so
`request.is_secure` and the Host header reflect the edge, not the internal
hop. Without the flag, behavior is unchanged (plain HTTP dev fast path, test
client).

### R3 — Security headers on every response

Every response from the Flask app MUST carry:

- `Content-Security-Policy`: `default-src 'self'; font-src 'self';
  style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-…';
  connect-src 'self' wss: ws:; img-src 'self' data:` with a per-request
  nonce. No `unsafe-eval`, no CDN sources (air-gap, ADR-0020).
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` — ONLY
  when the request arrived over TLS (edge or production). Never on plain
  HTTP.
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: same-origin`

### R4 — API responses are never cached

Responses under `/api/*` MUST carry `Cache-Control: no-store` (and
`Pragma: no-cache`, `Expires: 0`). Static asset caching (ADR-0006: `assets/`
immutable, `index.html` no-cache) MUST be preserved — the no-store invariant
is scoped to the API surface, not global.

### R5 — The dev stack runs with Secure cookies end-to-end

`task dev-stack` with the TLS edge up MUST run the backend with
`KUBEDASH_COOKIE_SECURE=true`. The plain-HTTP fast path (`task dev-up` +
direct `:8080`) keeps `KUBEDASH_COOKIE_SECURE=false` and remains available.

### R6 — Consequences are recorded

- The OIDC `redirect_uri` for local dev is `https://kubedash.local:443/api/v1/auth/callback`
  (the edge origin). The ADR records this as a consequence.
- X-XSS-Protection is deliberately NOT set (deprecated; CSP covers it).
  The ADR records the deviation from 4.1.

## Non-goals

- No COOP/COEP relaxed variants for embedded apps (4.1's `app_catalog` /
  `iframe_proxy` endpoints do not exist in 5.0).
- No CORS configuration change (same-origin SPA, ADR-0006; `cors_origins`
  stays declared-but-unconsumed).
- No production chart change in this change (the Helm ingress already
  terminates TLS; ADR-0019). The header layer applies to the app regardless
  of who terminates TLS.
- `fe-dev` (vite :3000) is untouched: its API proxy stays
  `http://127.0.0.1:8080` with `KUBEDASH_COOKIE_SECURE=false`.
