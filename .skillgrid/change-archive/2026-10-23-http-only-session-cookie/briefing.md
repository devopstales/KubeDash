# HttpOnly Session Cookie — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-23-http-only-session-cookie`
**Date:** 2026-10-23
**ADR:** `../../artifacts/04-adr-0025-http-only-session-cookie.md`

## Intent

A user's session must never travel in a URL. Today the OIDC callback and the
local login answer `302 /?token=<access>&refresh=<refresh>`, so the pair is
written to access logs, proxy logs, the `Referer` of the first asset requests,
and browser history. The SPA then parks both values in `localStorage`, where
any XSS can read them.

Move the browser session to HttpOnly cookies. Keep `Authorization: Bearer`
working for the kubectl credential plugin and API clients, which have no
cookie jar.

## Requirements

### R1 — Login delivers cookies, not URL parameters

Both login paths (`/api/v1/auth/callback` for OIDC and `/api/v1/auth/local`
for the bootstrap admin) MUST answer `302 /` and MUST set the session cookies
on that response. The `Location` header MUST NOT contain `token` or `refresh`
query parameters.

### R2 — The access cookie is HttpOnly and scoped

`kd_access` carries the access JWT with `HttpOnly`, `Secure` (configurable for
local development), `SameSite=Lax`, `Path=/`, and a `Max-Age` equal to the JWT
lifetime. JavaScript MUST NOT be able to read it.

### R3 — The refresh cookie is HttpOnly and path-scoped

`kd_refresh` carries the opaque refresh token with `HttpOnly`, `Secure`,
`SameSite=Strict`, `Path=/api/v1/auth`, and a 30-day `Max-Age`.
`POST /api/v1/auth/refresh` reads it first and accepts the JSON body only as a
fallback.

### R4 — Bearer stays accepted

`_auth_check` MUST accept `Authorization: Bearer <jwt>` first and the
`kd_access` cookie second. The kubectl plugin (ADR-0011) and existing API
clients MUST keep working unchanged.

### R5 — The SPA stops storing credentials

`apiFetch` MUST send same-origin credentials and MUST NOT read or write
`localStorage` for the token pair. A 401 that survives the refresh attempt
MUST send the browser to `/login`. The route guard MAY read the non-HttpOnly
`kd_session` hint; the hint grants nothing and every API call is still
verified server-side.

### R6 — Logout clears the session

`POST /api/v1/auth/logout` MUST revoke the refresh rows and clear
`kd_access`, `kd_refresh`, and `kd_session`. A refresh after logout MUST
return 401.
