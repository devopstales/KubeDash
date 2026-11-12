# HttpOnly Session Cookie — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files to touch, tests,
> and verification. The product *why* lives in `briefing.md` and ADR-0025. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** ACCEPTED (user approved the approach 2026-10-23)

**Tier:** T2 — auth transport change, multi-file, touches security.

**Build shape:** Tracer bullet — one login path (OIDC callback) sets cookies and `/auth/me`
accepts them end-to-end, then the local path, refresh, logout, and the SPA follow.

**Goal:** Move the browser session from `?token=…&refresh=…` + `localStorage` to HttpOnly
cookies, while keeping `Authorization: Bearer` as the first accepted credential for the
kubectl plugin.

**Architecture:** The verifier (`_auth_check`) becomes source-agnostic: Bearer header first,
`kd_access` cookie second. Login routes set three cookies (`kd_access`, `kd_refresh`,
non-HttpOnly `kd_session`) and redirect to `/`. The refresh route reads `kd_refresh` from the
path-scoped cookie and rotates it. The SPA drops `localStorage` entirely; `apiFetch` sends
same-origin credentials and redirects to `/login` when a 401 survives refresh.

**Spec:** `briefing.md` (R1–R6).
**In-force ADRs:** ADR-0004 (RBAC unchanged), ADR-0006 (single container), ADR-0011 (kubectl
plugin keeps Bearer), ADR-0014 (refresh revocation), ADR-0020 (air gap), ADR-0025 (this change).

## Steps

### 1. Backend — cookie helpers and settings

- `backend/app/core/config.py`: add `cookie_secure: bool = True` (`KUBEDASH_COOKIE_SECURE`).
- `backend/app/__init__.py`: copy the override into `app.config["KUBEDASH_COOKIE_SECURE"]`
  before `register_apis`, so tests can disable `Secure` without touching the global Settings.
- `backend/app/core/security.py`:
  - constants `ACCESS_COOKIE`, `REFRESH_COOKIE`, `SESSION_HINT_COOKIE`,
    `ACCESS_TTL_SECONDS = 900` (reuse it in `issue_token_pair`);
  - `set_session_cookies(response, access, refresh)` and `clear_session_cookies(response)`;
  - `_auth_check`: Bearer first, cookie second.
- `backend/app/core/apidocs.py`: add a `CookieAuth` apiKey scheme (`in: cookie`, name
  `kd_access`) alongside `BearerAuth`.

### 2. Backend — auth routes

- `backend/app/api/auth.py`:
  - replace `redirect_with_tokens` with `login_redirect(access, refresh)` that builds
    `redirect("/")`, sets the cookies, and sets `Cache-Control: no-store`;
  - OIDC `callback` and `local` use it;
  - `refresh` reads `request.cookies.get(REFRESH_COOKIE)` then the optional body, rotates,
    re-sets the cookies, and returns the pair (the JSON pair stays for non-browser clients);
  - `logout` clears the cookies after revoking the rows.
- `backend/app/schemas/auth.py`: `RefreshIn.refresh_token` becomes optional.
- Update the module docstring's "JWT delivery contract" paragraph.

### 3. Backend — tests

- `backend/tests/api/conftest.py` and `backend/tests/conftest.py`: pass
  `KUBEDASH_COOKIE_SECURE: False` (the test client speaks `http://localhost`).
- `backend/tests/api/test_auth.py`: the callback's `Location` is exactly `/`; the cookies
  carry the pair; a cookie-only `/auth/me` returns 200; Bearer-only still returns 200.
- `backend/tests/api/test_local_auth.py`: the local route sets the same cookies and redirects
  to `/`.
- New: refresh with no body but a valid `kd_refresh` cookie; logout clears the cookies.
- The existing Bearer-based tests must pass unchanged (R4 regression guard).

### 4. Frontend — HTTP seam and guard

- `frontend/src/lib/api.ts`:
  - drop every `localStorage` token read/write;
  - send `credentials: 'same-origin'`;
  - `refreshOnce` posts an empty body (the cookie carries the token) and re-throws a dead
    session;
  - when a 401 survives refresh (or refresh itself 401s), expire the `kd_session` hint and
    `window.location.assign('/login')` unless already there.
- `frontend/src/routes.tsx`: `ProtectedRoute` checks the `kd_session` hint via
  `document.cookie`; update the comment (the hint is not a credential).
- `frontend/src/views/Login/index.tsx`: delete `parkTokens`, `initialTokens`, the URL parsing,
  and the `replaceState` scrub. Local submit uses `credentials: 'same-origin'`,
  `redirect: 'follow'`, and treats `res.ok` (the followed `/` HTML) as success.
- `frontend/src/components/AppHeader.jsx` and `frontend/src/views/Profile/index.tsx`: logout
  no longer removes `localStorage` keys; a full navigation to `/login` after the call.
- `frontend/src/lib/session.ts` (new): `hasSessionHint()`, `clearSessionHint()` — the only
  place that knows the cookie name.

### 5. Frontend — tests

- `frontend/tests/setup.ts`: add a `setSessionHint()` helper and clear it between tests.
- Update the tests that seed `localStorage.kd_token` (`Login`, `Profile`, `admin_permissions`,
  `namespaces`, `namespace_data`, `dashboard`, `api`).
- `frontend/tests/api.test.ts`: refresh is called with credentials and no body; a dead session
  triggers the `/login` navigation.

### 6. Docs and spec zone

- ADR-0025 + `.backlog/decisions/decision-025` + the LOCKED index row.
- `ARCHITECTURE.md` §… (the SPA guard paragraph): replace "checks for a stored `kd_token`"
  with the cookie transport.
- This folder's `adr.md` manifest.

## Verification

- `uv run pytest -m "not integration"` — green.
- `task fe-build` — typecheck + lint + build.
- `task fe-check` — air-gap bundle.
- `uv run pytest backend/tests/api/test_auth.py backend/tests/api/test_local_auth.py` — the
  focused auth suite.
- Manual (dev stack): login → DevTools shows `kd_access` HttpOnly, no `token=` in the URL,
  `localStorage` empty; `/auth/me` 200; logout → back at `/login`.
