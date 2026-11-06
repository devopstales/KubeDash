---
type: InvariantContract
title: "The 4.1 security-header layer is on every response; /api/* is no-store; HSTS only over TLS"
description: "X-Frame-Options DENY, nosniff, Referrer-Policy, cross-origin isolation headers, and a per-request-nonce CSP apply to every response; Cache-Control no-store scopes to matched /api/ routes via url_rule; Strict-Transport-Security is added only when request.is_secure. (ADR-0026/0027.)"
tags: [security-headers, csp, adr-0026, adr-0027]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/core/security_headers.py
      all_of: ['X-Frame-Options', 'max-age=31536000; includeSubDomains', 'nonce', 'no-store', 'request.is_secure']
    - path: backend/tests/test_security_headers.py
      all_of: ['test_api_response_carry_all_security_headers', 'test_hsts_present_over_tls']
claims:
  - subject: framing protection
    literal: 'X-Frame-Options'
  - subject: HSTS value (TLS only)
    literal: 'max-age=31536000; includeSubDomains'
  - subject: per-request CSP nonce
    literal: 'nonce'
---

# Security-header layer (4.1 set, two recorded deviations)

The 4.1 security-header layer is restored and scoped, per ADR-0026
(superseded-in-part by ADR-0027 for the dev-stack default).

**The contract.**

- **Every response** carries the baseline set
  (`backend/app/core/security_headers.py`): `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Embedder-Policy: require-corp`,
  `Cross-Origin-Resource-Policy: same-origin`, plus a CSP
  (`default-src 'self'; … script-src 'self' 'nonce-…'`) with a
  **per-request nonce** (`secrets.token_urlsafe(16)` in
  `g.csp_nonce`) so inline scripts can never be allowed globally.
- **HSTS** (`max-age=31536000; includeSubDomains`) is added **only when
  `request.is_secure`** — the plain-HTTP dev stack (ADR-0027) must not
  emit HSTS.
- **`/api/*` is non-cacheable:** `Cache-Control: no-store`,
  `Pragma: no-cache`, `Expires: 0` — scoped on the **matched
  `url_rule`** (not the raw path), so API responses never get browser-
  cached while static asset caching (`immutable` for hashed assets,
  `no-cache` for `index.html`) is preserved.

**Why.** Object data is identity-bearing (see
`invariants/object-nav-no-url-identity.md`); a cached `/api/*` response
in a shared browser is a stale-object and cross-user leak. The nonce CSP
is what lets the vendored Swagger page keep inline scripts without
`'unsafe-inline'` (the 2026-10-31 empty-docs fix pinned this).

**Pinned by.** `backend/tests/test_security_headers.py` — full header
set on API responses, HSTS-over-TLS presence/absence, the
rule-vs-raw-path scoping regression, and static-caching preservation.

**Related.** ADR-0026 (decision), ADR-0027 (plain-HTTP dev default),
`invariants/air-gap-bundle.md` (the CSP's `'self'` works because the
bundle is air-gapped).
