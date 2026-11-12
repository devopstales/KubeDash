---
type: InvariantContract
title: "Browser sessions ride HttpOnly cookies; no credential in a URL or localStorage"
description: "The web session is kd_access + kd_refresh HttpOnly cookies (hint kd_session grants nothing); Authorization: Bearer is accepted only for the kubectl credential plugin and API clients. (ADR-0025.)"
tags: [session, cookies, auth, adr-0025]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/core/security.py
      all_of: ['kd_access', 'kd_refresh', '_REFRESH_COOKIE_PATH = "/api/v1/auth"', "httponly=True"]
    - path: backend/tests/api/test_auth.py
      all_of: ['test_callback_redirect_sets_cookies_not_url_tokens', 'test_cookie_alone_authorizes_api_calls']
claims:
  - subject: access cookie name
    literal: 'ACCESS_COOKIE = "kd_access"'
  - subject: refresh cookie name
    literal: 'REFRESH_COOKIE = "kd_refresh"'
  - subject: refresh cookie path scoping
    literal: '_REFRESH_COOKIE_PATH = "/api/v1/auth"'
---

# Browser sessions ride HttpOnly cookies

The SPA authenticates with cookies only; JavaScript never holds a token.

**The contract.**

- Login answers `302 /` with `kd_access` (the HS256 JWT, `Path=/`,
  `SameSite=Lax`, HttpOnly) and `kd_refresh` (opaque, `Path=/api/v1/auth`,
  `SameSite=Strict`, HttpOnly), plus the non-HttpOnly `kd_session`
  **hint** — spoofable, grants nothing (the ProtectedRoute check is
  display-only; the API re-verifies the JWT).
- `KUBEDASH_COOKIE_SECURE` defaults `True` (fail-closed); the plain-HTTP
  dev stack sets it false (ADR-0027).
- `Authorization: Bearer <jwt>` is accepted **only** for the kubectl
  credential plugin and other API clients — never by the SPA
  (`frontend/src/lib/api.ts` sends `credentials: 'same-origin'`, no
  Authorization header).
- No credential ever rides a URL (query, hash, or Referer) and no
  credential is stored in `localStorage`/`sessionStorage` (the object-ref
  registry stores identifiers, not credentials — ADR-0040).

**Why.** Scriptable UI code (and every proxy log, Referer header, and
browser history entry) sees URLs; HttpOnly cookies stay out of `document`.
The path-scoped Strict refresh cookie means `/api/v1/auth/refresh` is the
only endpoint that can consume it.

**Verification (2026-11-06).** Grepped: the cookie constants and
attributes are as above in `backend/app/core/security.py:42-47,127-150`;
`frontend/src` constructs no `?token=` and stores no credential in
localStorage (the only localStorage keys are the ADR-0040 relay
`kd_ref_<token>`, the `kd_notifications` toast list, and the
`kd-cluster-scope` selection — none a credential).

**Pinned by.** `backend/tests/api/test_auth.py` —
`test_callback_redirect_sets_cookies_not_url_tokens`,
`test_cookie_alone_authorizes_api_calls`; cookie deletion asserted at
logout.

**Related.** ADR-0025 (decision), ADR-0027 (TLS edge opt-in),
`workflows/oidc-login-session.md` (the flow this constraint shapes).
