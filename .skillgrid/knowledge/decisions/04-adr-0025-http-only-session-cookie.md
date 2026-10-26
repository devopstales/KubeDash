# Browser session transport: HttpOnly cookies, Bearer retained for the kubectl plugin

---
status: "accepted"
date: 2026-10-23
supersedes: none
---

**Decision-makers.** paladm (project owner)
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash delivered the login token pair to the browser through the URL
query string: `GET /?token=<access_jwt>&refresh=<refresh_token>`
(`app/api/auth.py`, `redirect_with_tokens`). The SPA parked both values in
`localStorage` and re-attached the access token as
`Authorization: Bearer <jwt>` on every `apiFetch`.

That contract leaks credentials through channels the application does not
control:

- the 302 `Location` and the follow-up GET appear in Gunicorn/Flask access
  logs and in every reverse-proxy/ingress log;
- the document URL is sent as `Referer` on the immediate same-origin
  `/assets/*` requests (the default `strict-origin-when-cross-origin`
  policy sends the full path and query for same-origin requests);
- browser history, the back-forward cache, extensions with history access,
  and copy-pasted URLs;
- there is no `Referrer-Policy` or `Cache-Control: no-store` on the auth
  redirect today.

The client-side `history.replaceState` scrub in the Login view runs only
after the SPA and its assets have loaded, so it does not close any of those
channels. The 30-day refresh token is the most valuable value in the URL.

`localStorage` adds a second exposure: any XSS in the SPA can read both
tokens. The backend is stateless HS256 JWT + opaque rotating refresh rows;
there is no Flask session cookie and `flask_login` is not a dependency.

#### Decision Drivers

- Credentials must never appear in a URL, a log line, or `Referer`.
- Tokens must not be readable from JavaScript (XSS blast-radius).
- The kubectl credential plugin calls the API before it has a session; it
  must keep a header-based credential (ADR-0011).
- The air-gapped, single-container deployment (ADR-0006, ADR-0020) rules out
  an external session service; Redis is already present for OIDC state and
  the revocation deny-list (ADR-0014).
- Multi-replica consistency (ADR-0008) favours a stateless access token with
  a database-backed refresh row over a sticky per-replica session.

#### Considered Options

- Keep the query-string handoff and add `Referrer-Policy` / `no-store`
- Park the token pair in `localStorage` from a JSON login response
- HttpOnly cookie transport (access + refresh) with Bearer kept as a second
  accepted source
- `flask_login` with a Redis session store and `@login_required` on page
  routes

#### Decision Outcome

Chosen option: "HttpOnly cookie transport for the browser, Bearer retained
for the kubectl plugin", because it removes the URL/log leak and the
`localStorage` XSS read in one change without introducing a stateful
session model.

- `POST /api/v1/auth/callback` and `POST /api/v1/auth/local` set two
  cookies and answer `302 /` — no credentials in `Location`.
  - `kd_access`: the access JWT, `HttpOnly; Secure; SameSite=Lax; Path=/`,
    `Max-Age` = the access JWT lifetime (900 s).
  - `kd_refresh`: the opaque refresh token,
    `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`,
    `Max-Age` = 30 days.
  - `kd_session`: the literal `1`, **not** HttpOnly, used only as a
    navigation hint by the SPA guard. It is spoofable by design and grants
    nothing; every `/api/v1/*` call is still verified server-side.
- `_auth_check` accepts `Authorization: Bearer <jwt>` first and the
  `kd_access` cookie second. Bearer is what the kubectl plugin and API
  clients send; the cookie is what the browser sends.
- `POST /api/v1/auth/refresh` reads `kd_refresh` first and falls back to the
  optional JSON body. It rotates and re-sets both cookies.
- `POST /api/v1/auth/logout` revokes the refresh rows (ADR-0014) and clears
  all three cookies.
- The SPA stops reading/writing `localStorage` for credentials. `apiFetch`
  sends same-origin credentials; a 401 that survives the refresh attempt
  redirects to `/login`.
- `ProtectedRoute` reads the `kd_session` hint instead of `kd_token`.

##### Consequences

- Good, because credentials no longer appear in URLs, logs, or `Referer`.
- Good, because JavaScript cannot read the access or refresh token, so XSS
  can no longer exfiltrate the session.
- Good, because the kubectl plugin and the browser share one verifier
  (`_auth_check`) with two accepted sources.
- Bad, because cookie auth introduces CSRF surface. Mitigated by
  `SameSite=Lax` on the access cookie, `SameSite=Strict` on the
  path-scoped refresh cookie, JSON-only state-changing endpoints, and no
  state-changing GETs. A double-submit token can be added later without a
  breaking change.
- Bad, because `Secure` requires TLS; local development sets
  `KUBEDASH_COOKIE_SECURE=false`.
- Neutral, because `/auth/local` and `/auth/callback` still answer a 302;
  only the payload moved from the `Location` to `Set-Cookie`.

##### Confirmation

- The auth redirect's `Location` header contains no `token` or `refresh`
  query parameter.
- The login response sets `kd_access` and `kd_refresh` with `HttpOnly`, and
  a browser request to `/api/v1/auth/me` with those cookies alone returns
  200.
- A request with only `Authorization: Bearer <jwt>` still returns 200.
- `localStorage` holds no token after login.
- Logging out clears the cookies and a subsequent refresh returns 401.

#### Pros and Cons of the Options

##### HttpOnly cookie transport + Bearer fallback (chosen)

- Good, because it removes the URL/log/Referer leak and the XSS read.
- Good, because the stateless JWT and the refresh-row model are unchanged.
- Good, because the kubectl plugin keeps working without a browser.
- Bad, because the CSRF surface must be reasoned about per endpoint.

##### Keep the query-string handoff, add headers

- Good, because it is a one-line header change.
- Bad, because logs and `Referer` are emitted before the header can help.
- Bad, because `localStorage` remains readable by XSS.

##### JSON login response into `localStorage`

- Good, because it removes the URL leak.
- Bad, because the XSS read remains, and the OIDC callback still has to
  land somewhere with the pair.

##### `flask_login` + Redis session store

- Good, because `@login_required` would exist for page routes.
- Bad, because the SPA shell contains no data; gating it adds state and a
  new auth model without a security gain over an HttpOnly JWT cookie.
- Bad, because it would replace the documented JWT delivery contract and
  the stateless access path that ADR-0008 relies on.

#### More Information

- OWASP Top 10:2025 A07 (Authentication Failures) and the "sensitive data
  in query strings" guidance.
- `backend/app/api/auth.py`, `backend/app/core/security.py`,
  `backend/app/api/_authhook.py`, `frontend/src/lib/api.ts`,
  `frontend/src/routes.tsx`, `frontend/src/views/Login/index.tsx`.
- ADR-0006 (single container), ADR-0011 (kubectl plugin), ADR-0014
  (revocation propagation), ADR-0020 (air gap).
