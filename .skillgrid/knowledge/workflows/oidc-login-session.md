---
type: BusinessWorkflow
title: "OIDC login → cookie session → authenticated API access → refresh/logout"
description: "The web login flow end to end: /auth/login 302 to the IdP, callback issues kd_access/kd_refresh cookies, every API call authenticates via cookie or Bearer, 401 triggers a single in-flight refresh, logout revokes and propagates (ADR-0014/0025)."
tags: [auth, oidc, session, workflow]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/api/auth.py
      all_of: ['/auth/login', '/auth/callback', '/auth/logout']
    - path: backend/app/core/security.py
      all_of: ['kd_access', 'kd_refresh', 'revoked:']
    - path: frontend/src/lib/api.ts
      all_of: ["credentials: 'same-origin'", '/api/v1/auth/refresh']
---

# OIDC login → cookie session → API access

The single web authentication path (OIDC is the sole authN mode,
ADR-0001).

## The flow

1. **`GET /auth/login`** → `302` to the IdP's `/authorize` (state
   `STATE_TTL_SECONDS = 300` in Redis).
2. **`/auth/callback`** — code → token → userinfo; upsert the `users`
   row (JIT provisioning hooks run here — ADR-0017); answer `302 /`
   setting `kd_access` (HS256 JWT, 15 min), `kd_refresh` (opaque, 30 d,
   stored hashed), and the non-HttpOnly `kd_session` hint. **No
   credential in the URL** (ADR-0025).
3. **Every API call** — the SPA sends cookies
   (`credentials: 'same-origin'`; API clients/kubectl plugin send
   `Authorization: Bearer`). Each Smorest `Api`'s
   `on_before_request` hook reads Bearer first, then `kd_access`;
   verifies the JWT (HS256; `sub` = OIDC subject) against the Redis
   `revoked:{jti}` deny-list; loads the `users` row into
   `g.current_user`.
4. **Per-object authorization** — handlers call `rbac.can(...)` (SAR
   proxy, `invariants/sar-verdict-cache-key.md`); denial → 403
   `RBAC_DENIED`.
5. **401 in the SPA** — `frontend/src/lib/api.ts` runs a single
   in-flight `POST /api/v1/auth/refresh` (the `kd_refresh` cookie is the
   source; the token rotates, both cookies re-set), retries once; a
   surviving 401 clears the hint and redirects to `/login`.
6. **`/auth/logout`** — revokes the refresh rows, clears all three
   cookies, runs OIDC RP-initiated logout when supported. Revocation
   propagates to kubectl-derived credentials via the same `jti`
   deny-list (ADR-0014): a logged-out web session's tokens are rejected
   at the API and at `/auth/verify`.

## Failure behavior

- Unknown/expired `sub` → 401 (never 500). Stale `kd_session` hint with
  a dead `kd_access` → the 401 path above (the hint grants nothing).
- IdP unreachable during login/callback → the flow fails at the 302 or
  the code exchange; no local session is created.

## Verification (2026-11-06)

Anchors confirmed: `/auth/login`, `/auth/callback`, `/auth/logout` in
`backend/app/api/auth.py`; cookie + deny-list literals in
`backend/app/core/security.py`; same-origin fetch + refresh endpoint in
`frontend/src/lib/api.ts`. Pinned by `backend/tests/api/test_auth.py`
(including `test_cookie_alone_authorizes_api_calls`) and
`test_local_auth.py` (bootstrap-admin mode, ADR-0021).

**Related.** ADR-0025 (transport), ADR-0014 (revocation propagation),
ADR-0011 (the plugin's parallel path),
`invariants/session-cookie-transport.md`.
