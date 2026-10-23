# HttpOnly Session Cookie — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR bodies 0001–0013
> have index entries but no bodies on disk (per AGENTS.md); the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | Unchanged. The credential source changes; the `can()` gate on every resource read does not. |
| ADR-0006 (single container) | The SPA and the API stay same-origin, so cookies need no CORS or cross-site configuration. |
| ADR-0011 (kubectl credential plugin) | The plugin has no cookie jar; `Authorization: Bearer` stays the first accepted source in `_auth_check`. |
| ADR-0014 (revocation propagation) | Logout still deletes the refresh rows; clearing the cookies is additive. |
| ADR-0020 (air gap) | No new dependency and no external session service; Redis already exists for OIDC state and the jti deny-list. |
| ADR-0021 (local admin auth) | The local login path changes only its delivery (cookies instead of URL parameters); its 401/403 contract is untouched. |

## Decision created by this change

| ADR | Status | Path |
|-----|--------|------|
| ADR-0025 — Browser session transport: HttpOnly cookies, Bearer retained for the kubectl plugin | accepted | `../../artifacts/04-adr-0025-http-only-session-cookie.md` |

No prior ADR is superseded: ADR-0021 defined *who* may log in locally, not *how* the session
is transported. The query-string handoff was an implementation detail with no ADR body.
