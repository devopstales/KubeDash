# TLS Edge + Security Headers — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR bodies 0001–0013
> have index entries but no bodies on disk (per AGENTS.md); the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | Unchanged. Headers and TLS are transport concerns; the `can()` gate on resource reads does not move. |
| ADR-0006 (single container) | The edge is a DEV-STACK service (nginx), not a second app container. The SPA and API stay same-origin at the edge, so the header layer needs no CORS and the ADR-0025 cookie model is unchanged. |
| ADR-0008 (leader election) | The nginx edge has ONE upstream (`host-gateway:8443`), not a load-balancing group — Postgres-advisory-lock election means any replica serves any request, so nginx does no balancing of its own. |
| ADR-0014 (revocation) | The jti deny-list path is unchanged; the refresh cookie's path scoping is unchanged. |
| ADR-0020 (air gap) | No new runtime dependency: nginx is a dev-stack image (the compose stack already runs 5 images), the certs are generated locally with mkcert, and the CSP contains no external source. |
| ADR-0021 (local admin auth) | The local login route is untouched; only its delivery environment gains TLS. |
| ADR-0025 (HttpOnly session cookie) | The `Secure` flag becomes honest end-to-end (browser leg HTTPS, internal leg HTTPS). `KUBEDASH_COOKIE_SECURE=false` remains only for the plain-HTTP dev fast path and the test client. |

## Decision created by this change

| ADR | Status | Path |
|-----|--------|------|
| ADR-0026 — TLS edge + security header layer (nginx edge with internal HTTPS, ProxyFix, 4.1 header set restored with two recorded deviations) | accepted | `../../artifacts/04-adr-0026-tls-edge-and-security-headers.md` |

## Recorded deviations from 4.1

- **X-XSS-Protection is NOT set.** Deprecated (removed from the spec); 4.1 shipped it
  alongside a CSP. Rebase ships the CSP, so the header would be cargo-cult.
- **No embedded-app header relaxation.** 4.1 relaxed CSP/COOP for `app_catalog` /
  `iframe_proxy` endpoints; neither exists in 5.0. One strict policy.
- **`Cache-Control: no-store` is scoped to `/api/*`,** not global as in 4.1 — global
  would clobber the ADR-0006 asset caching contract (`assets/` immutable).
