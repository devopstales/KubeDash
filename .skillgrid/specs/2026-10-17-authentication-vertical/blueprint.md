# Authentication Vertical — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-execution (recommended) or simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2

**Classification:** high-risk (auth trust boundary + additive migration) — verification floor L3+ (full suite, coverage-sensitive auth tests, lint); final review escalates to `parallel-code-review`.

**Build shape:** Tracer thread — Task 1 makes local login work end-to-end against the existing spine (API → DB → JWT → SPA token parking) before the admin source, profile page, and Taskfile loop thicken the vertical. Integration risk (pbkdf2 + upsert + 302 contract reuse) is tested by the first wave.

**Goal:** Local password login (bootstrap admin) + SSO on one login page, a `/profile` landing page, admin cluster access via in-cluster/kubeconfig-file, and an offline frontend build/sync loop in the root Taskfile — per ADR-0021, air-gap-safe per ADR-0020.

**Architecture:** Extend the existing auth spine in place. `AuthApi` gains two sibling routes of the OIDC flow (`POST /auth/local`, `GET /auth/settings`) that converge on the same `users` upsert + `issue_token_pair` + 302 JWT-delivery contract. `users` gains `password_hash` + `auth_source` in one additive Alembic revision; `create_app()` runs an idempotent env-driven bootstrap upsert. `K8sClientPool` gains a second input — the admin kubeconfig source (in-cluster or `KUBEDASH_ADMIN_KUBECONFIG` file) — surfaced to admin callers as a synthetic `id: 0` cluster going through the same SAR path. The frontend gains a real Login view (SSO + password form, gated by `/auth/settings`) and a Profile view as the post-login landing. The root Taskfile gains the offline fe loop with a no-CDN assertion as the air-gap proof.

**Tech Stack:** Python 3.12 + Flask-Smorest + SQLAlchemy 2.0 + Alembic + stdlib `hashlib` pbkdf2 (no new Python deps); React 18 (CoreUI template) + Vite 5 + TS strict + Vitest/MSW (no new node deps); go-task Taskfile; plain-ESM node check script.

**Spec:** `.skillgrid/specs/2026-10-17-authentication-vertical/briefing.md` — product why, success criteria, and out-of-scope list. Decisions: `artifacts/04-adr-0021-local-admin-auth.md` (authored by this change), ADR-0001/0002/0004/0006/0020 in force.

**Findings:** none (no research/prototype/sketch run for this change; design source is the validated ARCHITECTURE.md + in-force ADRs + the base-structure spine code).

## Terms

- **Bootstrap admin** — the single local `users` row created idempotently at boot from the bootstrap env vars; role `admin`, `auth_source='local'`. Introduced by this change (briefing § Terms).
- **Admin kubeconfig source** — the pool input resolved from `KUBEDASH_ADMIN_KUBECONFIG` (empty → in-cluster SA; set → file); backs the synthetic `local` cluster (`id: 0`). Introduced by this change.
- **No-CDN check** — the `task fe-check` assertion that no built asset references an external URL; frontend half of ADR-0020's runtime guarantee. Introduced by this change.
- **JWT delivery contract / Cluster / Cluster binding / SubjectAccessReview** — `.skillgrid/artifacts/02-technical-terms.md`.

## Hypothesis

**Claim:** The OIDC-only spine can absorb a local-password sibling route with zero changes to the token, refresh, revocation, and SPA token-parking machinery.
**Right condition:** A no-IdP install (bootstrap env set, `oidc_issuer` empty) reaches `/profile` via password login, `apiFetch` refresh/revocation behave identically to SSO users, and all base-structure auth tests stay green unchanged.
**Wrong condition:** The local path requires changes to `apiFetch`, the refresh hook, or the 302 contract — meaning the "sibling route" is really a second auth mechanism and ADR-0021's reuse claim fails.
**Thinnest MVP:** Task 1 only (local login → same 302 → SPA parks → any authenticated page renders).
**Door check:** Task 1, Step 4 — the login test asserts the 302 Location equals `/?token=<issued_access>&refresh=<issued_refresh>` EXACTLY against the token pair captured from the response (same builder ⇒ same shape, asserted precisely, not regex-approximated), and `frontend/tests/lib/api.test.ts` (existing) passes unmodified against a locally-issued JWT.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- T1: `POST /api/v1/auth/local` with the bootstrap admin's email+password responds **302** with `Location: /?token=<jwt>&refresh=<token>` — the same redirect the OIDC callback produces (same builder, no second contract). *(backstop — only observable by running the app; covered by the container login test + the redirect-shape assertion)*
- T2: Wrong password → 401 `INVALID_CREDENTIALS`; unknown email → 401 `INVALID_CREDENTIALS` (one code, no enumeration); bootstrap env unset → 403 `LOCAL_AUTH_DISABLED` — all in the stable `{ error: { code, message } }` envelope.
- T3: Boot with bootstrap env set creates exactly one `users` row (role `admin`, `auth_source='local'`, `password_hash` non-null); a second boot creates no row and updates the hash only when the env password changed; either env var unset → boot is a no-op.
- T4: The OIDC callback upserts with `auth_source='oidc'` and role `user` (existing tests pass unmodified); a local user's refresh rotation, reuse-detection (401 + row deleted), and jti revocation behave identically to an SSO user's.
- T5: `GET /api/v1/auth/settings` (open, pre-JWT) returns `{ sso_enabled: <oidc_issuer non-empty>, local_enabled: <bootstrap env both set> }`.
- T6: Admin caller's `GET /api/v1/clusters` contains exactly one synthetic entry `{ id: 0, name: "local", source: "admin", ... }`; non-admin response is unchanged (no `id: 0`, existing `source: "registry"` field present on registry rows).
- T7: `GET /api/v1/clusters/0/resources/pods` for an admin lists pods from the admin source (kind, `integration` marker); for a non-admin → 403/404 stable code (not a crash).
- T8: `GET /api/v1/auth/me` returns `auth_source` for all users, `last_login_at`, and `kubeconfig_source` (`"in-cluster" | "kubeconfig-file" | null`) for admins only.
- T9: `KUBEDASH_ADMIN_KUBECONFIG` pointing at a missing file → `/readyz` 503 naming `admin-kubeconfig` (no boot crash); file set → source is `kubeconfig-file`; empty → `in-cluster` (seam-mocked in unit tier).
- T10: Login page: token-in-URL parks `kd_token`/`kd_refresh` and lands on `/profile`; "Sign in with SSO" renders iff `sso_enabled`; the local form renders iff `local_enabled` and posts to `/api/v1/auth/local`, surfacing the error envelope on 401/403.
- T11: Profile page at `/profile` (inside `ProtectedRoute`) renders display name, email, groups, role badge, auth-source badge, last login; logout POSTs `/auth/logout`, clears both storage keys, navigates to `/login`.
- T12: `task fe-install fe-build fe-sync` → `backend/static/index.html` exists and `task backend-run` serves it at `/`; `fe-sync` output mirrors the Dockerfile's `COPY --from=frontend /build/dist ./static` (same `dist/` → `static/` mapping). *(backstop — needs the running app; covered by a static-serving test against the synced dir)*
- T13: `task fe-check` exits 0 on the current bundle and exits 1 printing the offending path when a fixture asset contains `https://cdn.example.com/x.js` or `//cdn.` (allow-list override via `task fe-check ALLOW='…'`). *(backstop — the check script is unit-tested against fixture dirs)*
- T14: No built asset in `frontend/dist/**` references `https?://` or `//cdn.` (the new Login/Profile views included) — the air-gap proof per ADR-0020, scoped exactly as T13 (the I8 precision: protocol-relative non-CDN URLs out of scope).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/core/security.py` — `hash_password` / `verify_password` (pbkdf2:sha256, 600k iters) appended to the existing module.
- `backend/migrations/versions/<new>_local_admin_auth_adr_0021.py` — additive revision (2 columns).
- `backend/app/api/auth.py` — `local`, `settings` routes + `MeOut` growth.
- `backend/app/__init__.py` — `_bootstrap_local_admin(app)` boot hook.
- `backend/app/services/k8s_client.py` — `resolve_admin_source` + `id: 0` routing.
- `backend/app/api/clusters.py` — synthetic admin entry in the list.
- `frontend/src/views/Login/index.tsx` — rewritten (SSO + local form).
- `frontend/src/views/Profile/index.tsx` — new.
- `frontend/src/App.tsx` — `/profile` route (routes live in App.tsx; `routes.tsx` exports only `ProtectedRoute`).
- `scripts/fe-airgap-check.mjs` — the no-CDN walker.
- Root `Taskfile.yaml` — `fe-install`, `fe-build`, `fe-sync`, `fe-dev`, `fe-check`.
- `backend/tests/api/test_local_auth.py`, `backend/tests/test_bootstrap.py`, `backend/tests/test_admin_source.py`, `backend/tests/api/test_clusters_admin.py`, `backend/tests/test_fe_airgap_check.py`, `frontend/tests/views/Login.test.tsx`, `frontend/tests/views/Profile.test.tsx` — passing tests for T1–T14.
- `artifacts/04-adr-0021-local-admin-auth.md` — written (done at plan time, committed by this change).

**Key links** (critical connections that must work together):
- `local` route must call the SAME `issue_token_pair` + redirect builder as the OIDC `callback` (T1's byte-for-byte shape depends on it).
- `_bootstrap_local_admin` must run BEFORE the first request is served — in production, `wsgi.py` calls it after `create_app()` returns (migrations run at image/wsgi boot, so tables exist); in tests, the fixture calls it inside `app.app_context()` AFTER `db.create_all()`. The factory itself stays pure (no DB init — verified `app/__init__.py:13`).
- The pool's `id: 0` routing must consult `g.current_user.role` (set by the existing auth hook) — non-admins never reach the admin source even with a valid JWT.
- Login view's SSO button must 302 to `/api/v1/auth/login` (the existing OIDC entry) — not a new endpoint.
- `fe-sync`'s target dir must be the same path `register_static` reads (`KUBEDASH_STATIC_DIR`, default `backend/static` relative to the backend cwd) — the Dockerfile and Taskfile must agree on the mapping.
- `MeOut` growth must propagate to `frontend/src/lib/types.ts` (`Me` type) — the Profile view compiles against it.

**One-way-door decisions** (hard to reverse — explicit user approval before implementing):
- OD-A: **Migration** — `users.password_hash VARCHAR(255) NULL` + `users.auth_source VARCHAR(16) NOT NULL DEFAULT 'oidc'` (additive; the default is the lock-in: existing rows are declared SSO). Tagged on Task 2.
- OD-B: **New stable error codes** — `INVALID_CREDENTIALS` (401), `LOCAL_AUTH_DISABLED` (403) enter the v1 error contract (base-structure OD-1, the 10-code set grows by 2). Tagged on Task 1.
- OD-C: **`/auth/settings` open route** — a new pre-JWT endpoint (the `/auth/*` opt-out scope widens by one path). Tagged on Task 1.
- OD-D: **Synthetic cluster `id: 0`** — a reserved id in the cluster namespace visible to admins (D1 of the briefing; impossible-by-construction vs PG sequences). Tagged on Task 4.

## Global Constraints

- Python 3.12, `uv`, `ruff`, `mypy --strict`, type hints everywhere (ARCHITECTURE.md §10).
- Error shape `{ error: { code, message, details? } }` with stable string codes; no new code for "cluster not accessible" — reuse the existing stable family (T7 uses the existing 403/404 codes, no invention).
- No new Python dependencies (stdlib pbkdf2 only); no new Node dependencies (plain-ESM check script).
- TS strict + `pnpm` + `eslint` + `prettier`; CoreUI SCSS, no Tailwind.
- Conventional Commits; spec-zone commits separate from code commits (zone guard).
- Air-gap (ADR-0020): zero runtime egress from new code; built bundle free of external URL references (T13/T14).
- Existing base-structure tests must pass unmodified where they assert the OIDC path (T4) — regressions in the spine are build failures.
- Taskfile convention: CWD-independent via `dir:` + `{{.TASKFILE_DIR}}`; any `cmd` string containing `{{...}}` is quoted (the existing header comment is load-bearing).

## File Structure

- `backend/app/models/user.py` — +`password_hash`, +`auth_source` columns.
- `backend/migrations/versions/<rev>_local_admin_auth_adr_0021.py` — additive revision (Create).
- `backend/app/core/security.py` — +`hash_password`, +`verify_password` (append).
- `backend/app/core/config.py` — +`bootstrap_admin_email`, +`bootstrap_admin_password`, +`admin_kubeconfig`.
- `backend/app/core/errors.py` — +`InvalidCredentialsError` (401), +`LocalAuthDisabledError` (403).
- `backend/app/api/auth.py` — +`local`, +`settings` routes; `me` response growth; `_upsert_user` gains `auth_source` default.
- `backend/app/schemas/auth.py` — +`LocalLoginIn`, +`AuthSettingsOut`; `MeOut` growth.
- `backend/app/__init__.py` — +`_bootstrap_local_admin(app)`; `create_app` calls it after DB init.
- `backend/app/services/k8s_client.py` — +`AdminSource` type, +`resolve_admin_source(settings)`, +`id: 0` routing in the pool.
- `backend/app/api/clusters.py` — list handler appends the synthetic admin entry for `role='admin'` callers.
- `backend/tests/test_security_password.py` (Create), `backend/tests/test_bootstrap.py` (Create), `backend/tests/api/test_local_auth.py` (Create), `backend/tests/test_admin_source.py` (Create), `backend/tests/api/test_clusters_admin.py` (Create), `backend/tests/test_fe_airgap_check.py` (Create), `backend/tests/api/test_auth.py` (amend: `auth_source`/`last_login_at` in me-shape), `backend/tests/test_readyz.py` or existing health test (amend: `admin-kubeconfig` 503 path).
- `frontend/src/views/Login/index.tsx` — rewrite (SSO button + local form + token parking).
- `frontend/src/views/Profile/index.tsx` — new.
- `frontend/src/App.tsx` — +`/profile` route (the router tree lives in App.tsx, verified `App.tsx:44-77`).
- `frontend/src/lib/types.ts` — `Me` growth (`auth_source`, `kubeconfig_source`, `last_login_at`).
- `frontend/src/hooks/useCluster.ts` — unchanged (me shape grows compatibly).
- `frontend/tests/views/Login.test.tsx` (Create), `frontend/tests/views/Profile.test.tsx` (Create).
- `scripts/fe-airgap-check.mjs` (Create) — walks a dist dir, flags external URL refs, exits 1 with offenders; `--allow` flag.
- `Taskfile.yaml` — +5 fe tasks (Modify, following the existing `dir:`/quoted-template convention).
- `.gitignore` — +`backend/static/` (synced build output; the Dockerfile bakes its own copy).
- `.skillgrid/ASSUMPTIONS.md`, `README.md`, `.skillgrid/state.yaml` — docs/pointer updates (Task 7).

---

### Task 1: Local password auth core — routes, error codes, settings endpoint

> **Checkpoint:** ⚠ one-way: OD-B (two new stable error codes enter the v1 error contract) + OD-C (`/auth/settings` open route). STOP for user approval before Step 3.

**Files:**
- Create: `backend/tests/api/test_local_auth.py`
- Modify: `backend/app/models/user.py` (the two columns — the model is what `db.create_all()` in tests reads; the Alembic revision lands in Task 2)
- Modify: `backend/app/core/errors.py`
- Modify: `backend/app/schemas/auth.py`
- Modify: `backend/app/api/auth.py`
- Modify: `backend/app/core/config.py`
- Test: `backend/tests/api/test_local_auth.py`, `backend/tests/api/test_auth.py` (amend only the settings-route open-scope test if the authhook scope test asserts an exact path list — verified: `_authhook.py:27` skips the whole `/api/v1/auth/` prefix, so no amendment is expected)

**Interfaces:**
- Consumes: `security.issue_token_pair(user) -> tuple[str, str]` (existing, `security.py:80`); the existing 302 redirect shape from `AuthApi.callback` (`auth.py:89`); `KubeDashHttpError` subclass pattern (`core/errors.py`).
- Produces: `LocalLoginIn` (a **marshmallow** schema — verified: `schemas/auth.py` is `marshmallow` (`ma.Schema`, `ma.fields.String`), and flask-smorest 0.47's `@blp.arguments` requires marshmallow (M-NEW-5): `email = ma.fields.String(required=True)` + a validator asserting it contains `@` and is ≥3 chars — deliberately NOT `EmailStr`, which would pull in the `email-validator` dependency and break the "no new Python deps" constraint), `AuthSettingsOut` (`sso_enabled: bool`, `local_enabled: bool`, also marshmallow); `InvalidCredentialsError` (401, code `INVALID_CREDENTIALS`), `LocalAuthDisabledError` (403, code `LOCAL_AUTH_DISABLED`); `AuthApi.local` handler; `AuthApi.settings` handler. The 302 redirect is produced by a NEW module-level helper `redirect_with_tokens(access: str, refresh: str) -> str` in `api/auth.py` (delivery concern — both callers live there; `security.py` stays token-minting-only) extracted from `callback` so both routes share one builder (the T1 key link). `local` also persists the `RefreshToken` row exactly like `callback` does (issue_token_pair + `db.session.add(RefreshToken(...))` + commit — extracted into a shared `_issue_and_persist(user) -> tuple[str, str]` helper so callback and local cannot diverge).
- Seam: `core/errors.py` is the error-contract seam (OD-1 pattern from base-structure); `redirect_with_tokens` in `api/auth.py` is the delivery-contract seam; `_issue_and_persist` is the token-persistence seam.
- Deletion test: deleting `local` + `settings` removes the only pre-JWT way to enter without an IdP; deleting `redirect_with_tokens` re-inlines the f-string in two places (callback + local) — the duplication is the bug it prevents; deleting `_issue_and_persist` re-couples refresh-row persistence to two call sites (the reuse-detection regression T4 guards is exactly the divergence it prevents).
- Adapters: 2 (OIDC callback + local login both call `redirect_with_tokens` and `_issue_and_persist`); tests use the Flask test client (existing `app`/`client` fixtures).

**SATISFIES:** `local-admin-login-issues-jwt`, `login-page-offers-sso-and-local` (backend half: the settings contract)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/api/test_local_auth.py
"""T1-T2, T5: local login + settings. The api-tier app (sqlite) seeds the
admin row DIRECTLY (db.session.add) — the PG-dialect bootstrap upsert is
exercised in tests/test_bootstrap.py (root PG tier); the local route itself
is dialect-agnostic."""
from urllib.parse import parse_qs, urlparse

@pytest.fixture()
def client_with_admin(client, app):
    with app.app_context():
        from app.models.user import User
        from app.core import security
        db.session.add(User(sub="local:admin@local", email="admin@local",
                            role="admin", auth_source="local",
                            password_hash=security.hash_password("correct-horse")))
        db.session.commit()
    return client

def test_local_login_issues_jwt_same_contract_as_oidc(client_with_admin):
    client = client_with_admin
    res = client.post("/api/v1/auth/local", json={"email": "admin@local", "password": "correct-horse"})
    assert res.status_code == 302
    loc = res.headers["Location"]
    # Door check (Hypothesis): EXACT match against the issued pair — the local
    # route must reuse the OIDC callback's redirect builder (T1 key link).
    q = parse_qs(urlparse(loc).query)
    assert set(q) == {"token", "refresh"} and len(q["token"]) == 1 and len(q["refresh"]) == 1
    access, refresh = q["token"][0], q["refresh"][0]
    # The issued JWT decodes to the admin's claims (the pair is real, not echo):
    from app.core.security import verify_jwt
    claims = verify_jwt(access)
    assert claims["sub"].startswith("local:")  # the bootstrap admin's sub convention
    assert loc == f"/?token={access}&refresh={refresh}"

def test_local_login_wrong_password_401(client):
    res = client.post("/api/v1/auth/local", json={"email": "admin@local", "password": "nope"})
    assert res.status_code == 401
    body = res.get_json()
    assert body["error"]["code"] == "INVALID_CREDENTIALS"

def test_local_login_unknown_email_same_code(client):
    res = client.post("/api/v1/auth/local", json={"email": "ghost@local", "password": "x"})
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"  # no enumeration

def test_local_login_disabled_when_env_unset(client_no_bootstrap):
    res = client.post("/api/v1/auth/local", json={"email": "a@b", "password": "c"})
    assert res.status_code == 403
    assert res.get_json()["error"]["code"] == "LOCAL_AUTH_DISABLED"

def test_auth_settings_open_route_reflects_config(client_no_bootstrap):
    res = client.get("/api/v1/auth/settings")  # pre-JWT: no Authorization header
    assert res.status_code == 200
    assert res.get_json() == {"sso_enabled": False, "local_enabled": False}
```

Plus an amendment to `backend/tests/api/test_auth.py`: if the authhook's path-scope test asserts an exact open-path list, add `/api/v1/auth/settings` to it (the hook already skips the whole `/api/v1/auth/*` prefix — verify, don't assume).

Conftest amendment — **both layers** (`backend/tests/conftest.py` root PG tier AND `backend/tests/api/conftest.py` sqlite tier; the hook's `on_conflict_do_update` is PG-dialect, so the sqlite api-tier app must SKIP the hook — see C-NEW-1): the `Settings` singleton (`app.core.config._settings`) caches from env on first read (and is populated at module import — `k8s_client.py:39` calls `get_settings()` at import), so the amendment must (a) in the primary app fixture: `monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_EMAIL", "admin@local")` + `monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "correct-horse")` + `app.core.config._settings = None` — in that order, BEFORE `create_app()` (reset-after-setenv is the load-bearing order; a wrong order makes `test_auth_settings_open_route_reflects_config` fail because an earlier test's `_settings` leaks in); (b) a `client_no_bootstrap` / `app_no_bootstrap` fixture doing the same with both vars `""`. Note: the `test_apidocs.py` second-app pattern the earlier draft cited builds a second app via `config_overrides` ONLY — it never resets `_settings` (verified); the reset is a NEW pattern this change introduces, stated here, not a citation. `config_overrides` alone is NOT sufficient — `get_settings()` reads env, not `app.config` (verified: the existing conftest's overrides dict reaches `app.config` only). The sqlite api-tier app runs the `local` route with the hook SKIPPED (its tests seed the admin row directly via `db.session.add(User(...))` — the PG-dialect upsert is exercised only in the root PG tier, which is where `test_bootstrap.py` lives).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/api/test_local_auth.py -v`
Expected: 5 FAIL (routes 404/405; settings 404). Door-check assertion: the OIDC callback test in `tests/api/test_auth.py` still PASSES at this step (T4 baseline before touching `auth.py`).

- [ ] **Step 3: Implement**

`core/errors.py` — add the two subclasses following the existing 10-code pattern exactly (name → `code` property → status). `schemas/auth.py` — add `LocalLoginIn` + `AuthSettingsOut`. `config.py` — add:

```python
bootstrap_admin_email: str = ""
bootstrap_admin_password: str = ""
admin_kubeconfig: str = ""  # empty -> in-cluster SA; set -> file path (ADR-0021)
```

`core/security.py` — append the pbkdf2 helpers (Task 1 implements them; Task 2's migration tests don't need them, but `local` does, so they land here first):

```python
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
    return f"pbkdf2:sha256:600000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def verify_password(stored: str, pw: str) -> bool:
    try:
        _, scheme, iters, salt_b64, hash_b64 = stored.split("$")
        assert scheme == "sha256"
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt_b64), int(iters))
    except (ValueError, AssertionError):
        return False
    return hmac.compare_digest(base64.b64encode(dk).decode(), hash_b64)
```

(`hmac.compare_digest` = constant-time; malformed `stored` → False, never an exception.) `api/auth.py` — extract the shared helpers and add the two routes:

```python
def redirect_with_tokens(access: str, refresh: str) -> str:
    return f"/?token={access}&refresh={refresh}"

def _issue_and_persist(user: User) -> tuple[str, str]:
    """issue_token_pair + the hashed RefreshToken row (TTL 30d) + commit —
    the OIDC callback's block, verbatim, so local login cannot diverge."""
    access, refresh = issue_token_pair(user)
    db.session.add(RefreshToken(
        user_id=user.id, token_hash=RefreshToken.hash_token(refresh),
        expires_at=datetime.now(UTC) + timedelta(days=REFRESH_TTL_DAYS)))
    db.session.commit()
    return access, refresh
```

(`callback` now ends with `access, refresh = _issue_and_persist(user); return redirect(redirect_with_tokens(access, refresh))` — the OIDC redirect test passing unmodified is the door check.) `local`: if local auth disabled (both bootstrap env empty) → `raise LocalAuthDisabledError`; look up `User` by email; if no row or `password_hash is None` or `verify_password` fails → `raise InvalidCredentialsError` (one code — no enumeration); else set `last_login_at`, `_issue_and_persist`, 302 via `redirect_with_tokens`. `settings`: return `{"sso_enabled": bool(get_settings().oidc_issuer), "local_enabled": bool(get_settings().bootstrap_admin_email and get_settings().bootstrap_admin_password)}`. NOTE: the local route needs the `password_hash`/`auth_source` columns from Task 2's migration — Task 1's tests therefore run against the conftest app whose `db.create_all()` includes them (the model columns must be added in Task 1 Step 3 too, or Task 1/2 swap order; the plan keeps the order and adds the two model columns to Task 1's file list with the migration itself in Task 2 — `create_all` reads the model, not the migration, so this is coherent).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/api/test_local_auth.py tests/api/test_auth.py -v`
Expected: all PASS. **Door check:** the OIDC callback redirect test passes UNMODIFIED (proving the extraction changed nothing observable).
- [ ] **Step 5: Commit**

```bash
git add backend/app/core/errors.py backend/app/core/config.py backend/app/core/security.py \
        backend/app/schemas/auth.py backend/app/api/auth.py backend/tests/api/test_local_auth.py \
        backend/tests/api/test_auth.py backend/tests/api/conftest.py
git commit -m "feat(auth): local password login + settings route (ADR-0021)"
```

---

### Task 2: Migration + model columns + bootstrap boot hook

> **Checkpoint:** ⚠ one-way: OD-A (additive migration; `auth_source NOT NULL DEFAULT 'oidc'` declares existing rows SSO). STOP for user approval before running the migration locally.

**Files:**
- Create: `backend/migrations/versions/<newrev>_local_admin_auth_adr_0021.py`
- Create: `backend/tests/test_bootstrap.py`
- Modify: `backend/wsgi.py` (call the hook after `create_app` returns — the factory stays pure; verified `app/__init__.py:13` "The factory stays pure")
- Modify: `backend/app/__init__.py` (the hook function itself lives here, next to `register_health`)
- Modify: `backend/app/models/user.py` (the model columns were added in Task 1 for the test `create_all`; Task 2 adds the matching Alembic revision + updates the `sub` comment for the `local:` convention)
- Test: `backend/tests/test_bootstrap.py`, `backend/tests/test_models.py` (amend: new columns present), `backend/tests/api/test_auth.py` (amend: SSO-collision case — the `_upsert_user` `auth_source` assertion)

**Interfaces:**
- Consumes: `security.hash_password` (Task 1); `create_app()` (pure — NO DB init inside it: verified the factory does no `db.create_all()`/migration; tests create tables in `conftest.py:58`, production runs Alembic via wsgi/migrate); the `users` model + `704b7637d05c` current migration head (down-reference).
- Produces: `_bootstrap_local_admin(app: Flask) -> None` — opens its OWN `app.app_context()`, runs a true Postgres upsert (`INSERT … ON CONFLICT (email) DO UPDATE` via `sqlalchemy.dialects.postgresql.insert`), gated on both bootstrap env vars being non-empty; called from `wsgi.py` after `create_app()` (production path) and invoked explicitly inside `app.app_context()` by the test fixtures after `db.create_all()` (test path). The hook updates `password_hash` on env change, sets `role='admin'` + `auth_source='local'` ONLY when the row's current `auth_source` is `'local'` (an SSO-collided row — `auth_source='oidc'` — keeps its SSO identity between boots; the ADR-0021 documented behavior "SSO wins" is pinned by the C2 test, and the hash refresh still applies so the password keeps working for the local identity).
- Seam: the bootstrap hook is the provisioning seam — permission management (ADR-0013) later calls the same upsert shape for UI-created users; the hook's function signature (`app` in, no return, own context) is what it keys off.
- Deletion test: deleting the hook removes the only path by which a local admin row exists (env is data, not logic); deleting the columns re-creates the "is this user SSO or local?" question with no honest answer (T8, T10, T11 all read `auth_source`).
- Adapters: 2 (wsgi boot-time upsert + the test fixture invocation).

**SATISFIES:** `local-admin-login-issues-jwt` (T3 half), `adr-0021-local-mode-in-force` (schema half), `oidc-login-still-issues-jwt` (SSO-collision half — the SSO upsert still wins `auth_source`)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_bootstrap.py  (container tier, Testcontainers PG — the
# conftest app fixture runs create_all + the hook inside an app context)
def test_bootstrap_creates_admin_row(app, db):
    rows = db.session.execute(db.select(User).filter_by(email="admin@local")).scalars().all()
    assert len(rows) == 1
    u = rows[0]
    assert u.role == "admin" and u.auth_source == "local" and u.password_hash is not None
    assert u.sub == "local:admin@local"  # the sub convention (M2: pinned in test)

def test_bootstrap_idempotent_second_boot(app, db):
    n1 = db.session.scalar(db.select(db.func.count()).select_from(User))
    from app import _bootstrap_local_admin
    _bootstrap_local_admin(app)  # second "boot", same env
    n2 = db.session.scalar(db.select(db.func.count()).select_from(User))
    assert n1 == n2  # ON CONFLICT: no duplicate row even under concurrent writers

def test_bootstrap_updates_hash_on_password_change(app, db, monkeypatch):
    h1 = db.session.execute(db.select(User.password_hash).filter_by(email="admin@local")).scalar_one()
    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "rotated-horse")
    import app.core.config as cfg; cfg._settings = None  # reset the Settings cache
    from app import _bootstrap_local_admin
    _bootstrap_local_admin(app)
    h2 = db.session.execute(db.select(User.password_hash).filter_by(email="admin@local")).scalar_one()
    assert h1 != h2  # env password change propagates on next boot

def test_bootstrap_noop_when_env_unset(app_no_bootstrap, db):
    assert db.session.scalar(db.select(db.func.count()).select_from(User)) == 0
```

Plus the SSO-collision case in `tests/api/test_auth.py` (amendment): the mock-OIDC callback running as `admin@local` (the bootstrap email) → after the callback the row has `auth_source='oidc'` (SSO wins); then re-run `_bootstrap_local_admin` → `auth_source` stays `'oidc'` (the hook does not flip an SSO-collided row) but `password_hash` is refreshed (the password keeps working for the local identity). `_upsert_user` gains `auth_source='oidc'` explicitly (not by default) so the collision is an honest write.

`test_security_password.py` — round-trip only (format is an implementation detail):

```python
def test_password_round_trip():
    h = security.hash_password("s3cret!")
    assert security.verify_password(h, "s3cret!") is True
    assert security.verify_password(h, "wrong") is False
    # two hashes of the same password differ (random salt):
    assert security.hash_password("s3cret!") != h
```

`test_models.py` amendment: assert the two new columns exist with the right nullability/default.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_bootstrap.py tests/test_models.py -v`
Expected: bootstrap tests FAIL (hook missing). (The model columns already exist from Task 1 — `db.create_all()` reads the model, so the tests' tables have them; the Alembic revision is Task 2's deliverable for the production DB.)

- [ ] **Step 3: Implement**

New Alembic revision (down-rev = `704b7637d05c`, the current head — the real rev id is generated by `flask db revision -m "local_admin_auth_adr_0021"`; the `<newrev>` filename in the Files list is that generated id): `op.add_column("users", sa.Column("password_hash", sa.String(255), nullable=True))`, `op.add_column("users", sa.Column("auth_source", sa.String(16), nullable=False, server_default="oidc"))`; downgrade drops both. `models/user.py` — update the `sub` column comment: "stable identity — OIDC sub, or `local:<email>` for the bootstrap admin (ADR-0021)". `app/__init__.py` — the hook (next to `register_health`):

```python
def _bootstrap_local_admin(app: Flask) -> None:
    """ADR-0021: idempotent local-admin upsert at boot. Both env vars must be
    set. True Postgres upsert (ON CONFLICT email DO UPDATE) so concurrent
    replicas converge. Own app context: create_app() stays pure (no DB init
    inside the factory — wsgi/tests own the table lifecycle)."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    s = get_settings()
    if not (s.bootstrap_admin_email and s.bootstrap_admin_password):
        return
    new_hash = security.hash_password(s.bootstrap_admin_password)
    with app.app_context():
        stmt = pg_insert(User).values(
            sub=f"local:{s.bootstrap_admin_email}", email=s.bootstrap_admin_email,
            display_name=s.bootstrap_admin_email.split("@")[0],
            role="admin", auth_source="local", password_hash=new_hash)
        stmt = stmt.on_conflict_do_update(
            index_elements=["email"],
            set_={"password_hash": new_hash,
                  "role": "admin",
                  "auth_source": db.case((User.auth_source == "local", "local"), else_="oidc")})
        db.session.execute(stmt)
        db.session.commit()
```

(The `auth_source` CASE is the SSO-collision rule: a row the OIDC callback flipped to `'oidc'` is NOT flipped back on the next boot — "SSO wins" per ADR-0021 — but `password_hash` still refreshes so the password keeps working for the local identity.) `wsgi.py` — call `_bootstrap_local_admin(app)` immediately after `app = create_app(...)` (before Leader/RQ startup) — the production boot path. Conftest: the app fixture invokes `_bootstrap_local_admin(app)` inside its `app.app_context()` AFTER `db.create_all()`; `app_no_bootstrap`/`client_no_bootstrap` (defined in Task 1's conftest amendment, reused here) skip it. `api/auth.py` `_upsert_user` — write `auth_source='oidc'` explicitly on the OIDC path (the collision rule is an honest write, not a default).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_bootstrap.py tests/test_models.py tests/api/test_local_auth.py -v`
Expected: PASS (login now finds the boot-created row).
- [ ] **Step 5: Commit**

```bash
git add backend/migrations/versions/ backend/app/__init__.py backend/wsgi.py \
        backend/app/models/user.py backend/app/api/auth.py \
        backend/tests/test_bootstrap.py backend/tests/test_models.py backend/tests/api/test_auth.py
git commit -m "feat(auth): local admin bootstrap hook + users columns migration (ADR-0021)"
```

---

### Task 3: Admin kubeconfig source in the client pool

> **Checkpoint:** none (pool input, no contract break; the `id: 0` surface is Task 4).

**Files:**
- Create: `backend/tests/test_admin_source.py`
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/__init__.py` (`register_health`'s readyz check dict — verified at `app/__init__.py:107-122`; the "factory/health module" hedge in the earlier draft is resolved: it IS in the factory)
- Modify: `backend/tests/conftest.py` (the `app`/`client` fixtures: after `monkeypatch.setenv`, reset `app.core.config._settings = None` before `create_app` — the Settings singleton caches from env on first read, so a test that changes `KUBEDASH_ADMIN_KUBECONFIG` must reset it, the same pattern `tests/test_apidocs.py:98-101` uses for its second app)
- Test: `backend/tests/test_admin_source.py`

**Interfaces:**
- Consumes: `Settings.admin_kubeconfig` (Task 1), `get_settings()`, the existing `K8sClientPool.get(cluster: Cluster)` (verified: `k8s_client.py:151` — takes a Cluster ROW, not an id; there is no `get_client`), the existing `bound_cluster_or_404(user, cluster_id)` binding gate (verified: `k8s_client.py:65-88` — raises `ClusterNotFoundError` BEFORE any pool lookup when no Cluster row OR no binding exists — the T7 blocker for `id: 0`), `K8sClient.__init__(kubeconfig: bytes)` (verified: `k8s_client.py:98` — bytes-only constructor; no file/in-cluster path exists), the existing `pool.get(cluster)` call sites — verified complete list: `api/clusters.py:125` (`cluster_health`), `api/resources.py:53` (`list_resources`), `services/rbac.py:77` (`can`), `tasks/health.py:28`, `tasks/cluster_sync.py:27` (5 sites, all pass a Cluster row — none change in this task), `kubernetes.config` (`load_kube_config`/`load_incluster_config`).
- Produces: `AdminSource = Literal["in-cluster", "kubeconfig-file"]`; `resolve_admin_source(s: Settings) -> AdminSource` (pure: empty → `"in-cluster"`, non-empty → `"kubeconfig-file"`); a NEW builder `build_admin_client(s: Settings) -> K8sClient` (file: `load_kube_config(path)` → Configuration → the same `K8sClient`-shaped client, constructed via a small `_AdminK8sClient` subclass or a factory kwarg — the exact kubernetes-API shape is an implementation detail pinned by the test seam; in-cluster: `load_incluster_config()`); `K8sClientPool.get_admin_client(user: User) -> K8sClient` — LAZY (resolves `get_settings()` on first call, caches; I4: the pool is constructed at module import, so eager resolution would see pre-env Settings), raises the existing `ClusterNotFoundError` when `user.role != "admin"`; and a `cluster_id == 0` SHORT-CIRCUIT in `api/clusters.py` (`get_cluster`, `cluster_health`) and `api/resources.py` (`list_resources`): admin + `id 0` → `pool.get_admin_client(user)`, non-admin + `id 0` → the existing `ClusterNotFoundError` (stable 404, no new code) — the short-circuit happens BEFORE `bound_cluster_or_404` (which would 404 first, since no Cluster row 0 exists). `K8sClient`/`_AdminK8sClient` gains a `source: str` attribute (`"registry"` | `"admin"`) for test assertions.
- Seam: `resolve_admin_source` is the config→source seam (pure, no k8s); `build_admin_client` is the k8s-client seam (the unit tier injects a fake via the same `factory` kwarg pattern the pool already has — verified: `K8sClientPool(factory=...)` at `k8s_client.py:147`).
- Deletion test: deleting the admin source removes the admin's only way to act on the cluster KubeDash runs in (the whole point of ADR-0021's admin section); the pool reverts to registry-only and `id: 0` 404s for everyone.
- Adapters: 2 (in-cluster path, file path) + 2 test doubles (fake factory in unit, kind in CI) = seam justified.

**SATISFIES:** `admin-sees-local-cluster-from-config` (pool half), T9

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_admin_source.py  (unit tier — no Docker, no kind; the
# fake-factory pattern from tests/api/test_clusters.py applies)
from app.services import k8s_client as kc
from app.core.config import Settings

def test_resolve_admin_source_pure():
    assert kc.resolve_admin_source(Settings(admin_kubeconfig="")) == "in-cluster"
    assert kc.resolve_admin_source(Settings(admin_kubeconfig="/etc/kubeconfig.yaml")) == "kubeconfig-file"

def test_pool_admin_client_role_gate(db):
    admin = _seed_user(db, role="admin")
    normal = _seed_user(db, role="user")
    pool = kc.K8sClientPool()  # fresh instance; get_admin_client is lazy
    c = pool.get_admin_client(admin)
    assert c.source == "admin"
    with pytest.raises(kc.ClusterNotFoundError):
        pool.get_admin_client(normal)  # stable 404 family, not a crash

def test_resources_zero_short_circuit_for_admin(app, client, db, monkeypatch):
    # admin JWT + fake pool admin client (monkeypatch kc.pool like the
    # existing test_resources.py does) -> 200 with the fake's pods
    ...

def test_resources_zero_404_for_non_admin(app, client, db):
    res = client_user.get("/api/v1/clusters/0/resources/pods")
    assert res.status_code == 404
    assert res.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"

def test_readyz_503_when_admin_kubeconfig_file_missing(monkeypatch, tmp_path, client_for_env):
    # client_for_env: a fixture that sets KUBEDASH_ADMIN_KUBECONFIG=<missing>,
    # resets cfg._settings, THEN builds the app (the Settings-cache reset is
    # the fix for the "env set after create_app" trap)
    res = client_for_env.get("/readyz")
    assert res.status_code == 503
    assert "admin-kubeconfig" in res.get_data(as_text=True)

def test_readyz_ok_when_admin_kubeconfig_empty(monkeypatch, client):
    # in-cluster mode (env empty): no admin-kubeconfig dependency at all
    res = client.get("/readyz")
    body = res.get_json()
    assert "admin-kubeconfig" not in body  # I12: absent, not "ok"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_admin_source.py -v`
Expected: 5 FAIL (`resolve_admin_source` not defined; `get_admin_client` missing; no `id:0` short-circuit; readyz has no `admin-kubeconfig` check).
- [ ] **Step 3: Implement**

`k8s_client.py`: add `resolve_admin_source` (2 lines), `build_admin_client(s)` (the k8s construction; wrap file-missing in a `ValueError` with the path), `K8sClientPool.get_admin_client(user)` (lazy + cached + role gate), the `source` attribute (registry clients get `"registry"` in `__init__`; admin client `"admin"`), and a module-level `admin_client_ok(s) -> bool` helper (file set → `os.path.isfile`, else True) for readyz. `api/clusters.py` + `api/resources.py`: the `cluster_id == 0` short-circuit (admin → `pool.get_admin_client(user)`, else raise `ClusterNotFoundError`) placed BEFORE `bound_cluster_or_404`. `app/__init__.py` `readyz`: when `resolve_admin_source(settings) == "kubeconfig-file"`, add `checks["admin-kubeconfig"] = "ok" if admin_client_ok(settings) else "down"`. The 5 existing `pool.get(cluster)` call sites are UNCHANGED (they all hold a real Cluster row — verified; no arity change anywhere).
- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_admin_source.py tests/api/test_clusters.py tests/api/test_resources.py tests/tasks/ -v`
Expected: PASS — the existing cluster/resource/task suites green (the regression guard: the short-circuit must not perturb `id > 0` behavior).
- [ ] **Step 5: Commit**

```bash
git add backend/app/services/k8s_client.py backend/app/api/clusters.py backend/app/api/resources.py \
        backend/app/__init__.py backend/tests/conftest.py backend/tests/test_admin_source.py
git commit -m "feat(clusters): admin kubeconfig source in client pool (ADR-0021)"
```

---

### Task 4: Synthetic `local` cluster in the list + `me` response growth

> **Checkpoint:** ⚠ one-way: OD-D (reserved cluster id 0 in the cluster namespace). STOP for user approval before Step 3.

**Files:**
- Create: `backend/tests/api/test_clusters_admin.py`
- Modify: `backend/app/api/clusters.py` (list handler + the Pydantic list-item schema in `schemas/cluster.py`)
- Modify: `backend/app/schemas/auth.py` (`MeOut` growth)
- Modify: `backend/app/api/auth.py` (`me` handler)
- Test: `backend/tests/api/test_clusters_admin.py`, `backend/tests/api/test_auth.py` (amend me-shape)

**Interfaces:**
- Consumes: Task 3's `resolve_admin_source` (for the synthetic entry's `api_server` display: `"in-cluster"` or the configured path); `g.current_user` (role, `auth_source`); the existing cluster-list Pydantic item schema (`schemas/cluster.py`).
- Produces: cluster list item gains `source: Literal["registry", "admin"]`; admin callers get exactly one extra item `{"id": 0, "name": "local", "source": "admin", "api_server": <"in-cluster" or the file path>}`; `MeOut` gains `auth_source: Literal["local", "oidc"]`, `kubeconfig_source: Literal["in-cluster", "kubeconfig-file"] | None` (None for non-admins), `last_login_at: datetime | None`.
- Seam: the list handler's "append synthetic entry for admins" block is the visibility seam — permission management later extends it (e.g. per-cluster binding status) without touching the pool.
- Deletion test: deleting the synthetic entry removes the admin's visible entry point to their own cluster (T6/T7 die); deleting the `MeOut` fields makes the Profile page (Task 6) unable to render role/auth badges and the Login page (Task 5) unable to know `auth_source`.
- Adapters: 1 caller each (list handler, me handler) — no seam abstraction, direct edits.

**SATISFIES:** `admin-sees-local-cluster-from-config` (T6, T8), `profile-page-shows-identity` (backend half)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/api/test_clusters_admin.py  (container tier)
def test_admin_sees_synthetic_local_cluster_exactly_once(client_admin, db):
    # setup: the admin registers one registry cluster (POST /api/v1/clusters
    # with a valid kubeconfig — the same registration the existing
    # test_clusters.py does; auto-bind makes it visible to the admin)
    client_admin.post("/api/v1/clusters", json={...valid registry cluster...})
    items = client_admin.get("/api/v1/clusters").get_json()
    locals_ = [i for i in items if i.get("source") == "admin"]
    assert len(locals_) == 1 and locals_[0]["id"] == 0 and locals_[0]["name"] == "local"
    # the synthetic api_server reflects the resolved source (I13):
    assert locals_[0]["api_server"] in {"in-cluster", "file:<path-or-empty>"}
    registries = [i for i in items if i.get("source") == "registry"]
    assert len(registries) == 1  # the registered one

def test_non_admin_list_unchanged_shape(client_user, db):
    items = client_user.get("/api/v1/clusters").get_json()
    assert all(i.get("source") == "registry" for i in items)
    assert not any(i["id"] == 0 for i in items)

def test_admin_me_includes_kubeconfig_source(client_admin):
    me = client_admin.get("/api/v1/auth/me").get_json()
    assert me["auth_source"] == "local"
    assert me["kubeconfig_source"] in {"in-cluster", "kubeconfig-file"}
    assert "last_login_at" in me

def test_user_me_kubeconfig_source_null(client_user):
    me = client_user.get("/api/v1/auth/me").get_json()
    assert me["auth_source"] == "local"
    assert me["kubeconfig_source"] is None
```

(The `api_server` assertion above is exact: `"in-cluster"` when `admin_kubeconfig` is empty, else the literal path string from `get_settings().admin_kubeconfig` — NOT the `resolve_admin_source` literal, which only says which of the two it is (I13).)

Plus an `integration`-marked test in the same file: `test_admin_pod_list_via_local_cluster` — with a kind cluster, the admin's `GET /api/v1/clusters/0/resources/pods` returns 200 with the kind pods (the Task 3 short-circuit routes 0 → admin source → SAR as usual); the non-admin gets the stable 404 `CLUSTER_NOT_FOUND`. (kind fixture = the existing session-scoped one from base-structure `tests/conftest.py`; env-blocked locally, CI backstop — same pattern as the base-structure R4 integration tests.)

Fixtures `client_admin` / `client_user`: seed two local users directly (role `admin` / `user`, `auth_source='local'`), mint JWTs via `security.issue_token_pair` and set `Authorization: Bearer` per request (the standard pattern in `tests/api/test_auth.py` — reuse it, don't invent a new one).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/api/test_clusters_admin.py tests/api/test_auth.py -v -m "not integration"`
Expected: 4 FAIL (no `source` field; no `id:0`; `MeOut` rejects unknown fields or omits the new ones).
- [ ] **Step 3: Implement**

`api/clusters.py` `_out()` (verified: the list is a BARE `jsonify([...])` — the Pydantic schema is docs-only in smorest 0.47, so the field must go in the handler dict, not just the schema): add `"source": "registry"` to `_out()`'s returned dict. `list_clusters`: after building the bound-registry list, `if user.role == "admin":` prepend `{"id": 0, "name": "local", "api_server": "in-cluster" if resolve_admin_source(s) == "in-cluster" else s.admin_kubeconfig, "context": None, "status": None, "last_probe_at": None, "source": "admin"}`. `schemas/cluster.py`: item schema +`source: Literal["registry", "admin"] = "registry"` (keeps the OpenAPI doc honest). `schemas/auth.py` `MeOut`: add `auth_source: Literal["local", "oidc"]`, `kubeconfig_source: Literal["in-cluster", "kubeconfig-file"] | None`, `last_login_at: datetime | None`. `api/auth.py` `me`: populate them from `g.current_user` + `resolve_admin_source(get_settings())` (`kubeconfig_source` only when `role == "admin"`, else None). **OpenAPI re-dump (I6/I7):** after `MeOut` grows, re-dump `frontend/openapi.json` from the test client (the same dump the base-structure Task 8 did — the committed `frontend/openapi.json` is the source for `types.ts`) so Task 5's `Me` extension matches the real spec, not a hand-guess.
- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/api/ -v -m "not integration"`
Expected: PASS (full API tier green — the me-shape amendment in test_auth.py included).
- [ ] **Step 5: Commit**

```bash
git add backend/app/api/clusters.py backend/app/schemas/cluster.py backend/app/api/auth.py \
        backend/app/schemas/auth.py backend/tests/api/test_clusters_admin.py backend/tests/api/test_auth.py
git commit -m "feat(auth): synthetic local cluster for admins + me response growth (ADR-0021)"
```

---

### Task 5: Frontend — Login view (SSO + local form) + Profile view + routes

**Files:**
- Create: `frontend/src/views/Profile/index.tsx`, `frontend/tests/views/Login.test.tsx`, `frontend/tests/views/Profile.test.tsx`
- Modify: `frontend/src/views/Login/index.tsx` (rewrite), `frontend/src/routes.tsx`, `frontend/src/App.tsx` (add the `/profile` route — verified: all routes live in `App.tsx:44-77`, `routes.tsx` exports only `ProtectedRoute`; the earlier draft's "routes.tsx gains the route" is corrected), `frontend/src/lib/types.ts`
- Test: `frontend/tests/views/Login.test.tsx`, `frontend/tests/views/Profile.test.tsx`

**Interfaces:**
- Consumes: `apiFetch` (unchanged — T1 door-check proof), the `/api/v1/auth/settings` contract (Task 1), the `/api/v1/auth/local` 302 (Task 1), `useCluster()`'s `me` (grows compatibly via `types.ts`), the re-dumped `frontend/openapi.json` (Task 4) as the source for the `Me` extension, CoreUI form components (the template's existing `views/forms` usage as the pattern reference).
- Produces: Login view with (a) token-in-URL parking effect → `navigate('/profile', { replace: true })` via **react-router** (C6: raw `window.history.replaceState` does not re-render the router — the SPA is BrowserRouter, `App.tsx:43`; the router is the only way to move it), (b) SSO button iff `sso_enabled` → `window.location.assign('/api/v1/auth/login')` (full document navigation to the 302 entry — the browser follows to `/?token=…`, the SPA re-mounts at `/`, and the parking effect on mount consumes it: this is the EXISTING SSO mechanism, kept verbatim), (c) local form iff `local_enabled`: `fetch('/api/v1/auth/local', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({email, password}), redirect: 'follow' })` — **no document navigation**: the fetch follows the 302 in-process, and on success the handler reads the final URL (`res.url` ends `/?token=…&refresh=…`), parses the pair, parks both in localStorage, and calls `navigate('/profile', { replace: true })` (C5: the SPA never leaves `/login`, so no re-mount handoff is needed). The mount auto-bounce (`window.location.assign` on mount, current `Login/index.tsx:26`) is REMOVED (I11: with a no-SSO install it 404s at `/authorize`; the settings-gated SSO button replaces it). On 401/403 the form surfaces the envelope message inline. Profile view: identity card + logout. `App.tsx`: `{ path: '/profile', element: <ProtectedRoute><ProfileView/></ProtectedRoute> }` (lazy, same pattern as the other views).
- Seam: the token-parking effect is the delivery seam — the single place that consumes `?token=&refresh=` from the URL (the SSO document-navigation path); the local form's `res.url` parse is its in-process sibling. Both land on `navigate('/profile')`.
- Deletion test: deleting the Login rewrite re-creates the SSO-only dead-end (no-IdP install unreachable — the whole change's point); deleting Profile removes the post-login landing (users bounce to the clusters view with no identity context).
- Adapters: MSW handlers in the two test files (settings-on/off, local 302/401/403, me admin/user).

**SATISFIES:** `login-page-offers-sso-and-local` (T10), `profile-page-shows-identity` (T11)

- [ ] **Step 1: Write the failing tests**

```tsx
// frontend/tests/views/Login.test.tsx  (Vitest + MSW + RTL, pattern: existing view tests)
describe('Login view', () => {
  it('parks token-in-URL (SSO callback path) and navigates to /profile', async () => {
    // the SSO document navigation lands the SPA at /?token=… — render at that
    // URL inside MemoryRouter (initialEntries=['/?token=AT&refresh=RT'])
    const { container } = render(
      <MemoryRouter initialEntries={['/?token=AT&refresh=RT']}>
        <Routes>
          <Route path="/login" element={<LoginView />} />
          <Route path="/profile" element={<div>PROFILE-LANDING</div>} />
          <Route path="/" element={<Navigate to="/clusters" replace />} />
        </Routes>
      </MemoryRouter>)
    expect(localStorage.getItem('kd_token')).toBe('AT')
    expect(localStorage.getItem('kd_refresh')).toBe('RT')
    expect(container).toHaveTextContent('PROFILE-LANDING')  // the router actually moved
  })

  it('local form success: parses the 302 final URL, parks, navigates to /profile', async () => {
    server.use(settingsHandler({ sso_enabled: false, local_enabled: true }),
              localLoginHandlerRedirecting('/?token=AT2&refresh=RT2'))  // MSW: 302 → Location, followed
    render(<MemoryRouter initialEntries={['/login']}>…routes…</MemoryRouter>)
    await screen.findByLabelText(/email/i)
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'admin@local' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(localStorage.getItem('kd_token')).toBe('AT2')
    expect(localStorage.getItem('kd_refresh')).toBe('RT2')
    expect(screen.getByText('PROFILE-LANDING')).toBeInTheDocument()
  })

  it('shows SSO button only when sso_enabled', async () => {
    server.use(settingsHandler({ sso_enabled: true, local_enabled: true }))
    render(<MemoryRouter><LoginView/></MemoryRouter>)
    expect(await screen.findByRole('button', { name: /sign in with sso/i })).toBeInTheDocument()
  })

  it('hides SSO button and shows local form when sso disabled', async () => {
    server.use(settingsHandler({ sso_enabled: false, local_enabled: true }))
    render(<MemoryRouter><LoginView/></MemoryRouter>)
    expect(screen.queryByRole('button', { name: /sign in with sso/i })).not.toBeInTheDocument()
    expect(await screen.findByLabelText(/email/i)).toBeInTheDocument()
  })

  it('submits local form and surfaces INVALID_CREDENTIALS', async () => {
    server.use(settingsHandler({ sso_enabled: false, local_enabled: true }),
              localLoginHandler(401, { code: 'INVALID_CREDENTIALS', message: 'bad credentials' }))
    render(<MemoryRouter><LoginView/></MemoryRouter>)
    await screen.findByLabelText(/email/i)
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'a@b' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(await screen.findByText(/bad credentials/i)).toBeInTheDocument()
  })
})
```

`Profile.test.tsx` — mirrors: me-admin renders role badge `admin` + auth-source badge + groups chips + last login; me-user renders no kubeconfig source; logout button POSTs `/api/v1/auth/logout`, clears `kd_token` + `kd_refresh`, and navigates to `/login` (assert localStorage empty + the router moved to the login route).

`types.ts` — extend `Me` with `auth_source: 'local' | 'oidc'`, `kubeconfig_source?: 'in-cluster' | 'kubeconfig-file' | null`, `last_login_at?: string | null` — cross-checked against the re-dumped `openapi.json` from Task 4 (I7: the `Me` interface is a hand-maintained extract of the OpenAPI spec, so the dump is the source of truth for the new fields).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && pnpm vitest run tests/views/Login.test.tsx tests/views/Profile.test.tsx`
Expected: FAIL (current Login has no form/settings fetch; Profile route missing).
- [ ] **Step 3: Implement**

`Login/index.tsx` — REWRITE (the current auto-bounce at `useEffect` mount is deleted — I11): (1) parking effect: on mount, if `window.location.search` has `token` + `refresh` → park both in localStorage, `window.history.replaceState({}, '', window.location.pathname)` (drop the query so a refresh doesn't re-park stale tokens), then `navigate('/profile', { replace: true })` (react-router — C6); (2) settings fetch: `useQuery({ queryKey: ['auth/settings'], queryFn: ... apiFetch('/api/v1/auth/settings') })` (object form — M5: matches the `useCluster` style; open route, no token); (3) SSO button (iff `sso_enabled`) → `window.location.assign('/api/v1/auth/login')` (document navigation — the existing SSO entry, unchanged); (4) local form (iff `local_enabled`): `const res = await fetch('/api/v1/auth/local', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ email, password }), redirect: 'follow' })`; if `res.ok && res.redirected` → parse `new URL(res.url).searchParams` for `token`/`refresh`, park both, `navigate('/profile', { replace: true })` (C5: in-process, no document navigation); if `res.ok && !res.redirected` (shouldn't happen) → treat as an error envelope; else → surface `error.message` from the envelope in a `CAlert color="danger"`. `Profile/index.tsx` — identity card from `useCluster().me` (display name, email, groups as `CBadge` chips, role `CBadge`, auth-source `CBadge`, `last_login_at` via `Intl.DateTimeFormat`), logout `CButton` → `apiFetch('/api/v1/auth/logout', { method: 'POST' })` → `localStorage.removeItem('kd_token'); localStorage.removeItem('kd_refresh')` → `navigate('/login', { replace: true })`. `App.tsx` — lazy `ProfileView` import + the `/profile` route inside the `/*` branch, wrapped in `ProtectedRoute` (same pattern as `/clusters/:id`).
- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && pnpm test && pnpm exec tsc --noEmit && pnpm lint && pnpm build`
Expected: all green; `dist/` rebuilt.
- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/Login/index.tsx frontend/src/views/Profile/index.tsx \
        frontend/src/App.tsx frontend/src/lib/types.ts \
        frontend/tests/views/Login.test.tsx frontend/tests/views/Profile.test.tsx
git commit -m "feat(fe): login page (SSO + local) + profile landing (ADR-0021)"
```

---

### Task 6: Taskfile frontend loop + no-CDN air-gap check

**Files:**
- Create: `scripts/fe-airgap-check.mjs`, `backend/tests/test_fe_airgap_check.py`
- Modify: `Taskfile.yaml` (root), `.gitignore`
- Test: `backend/tests/test_fe_airgap_check.py`

**Interfaces:**
- Consumes: `frontend/dist/` (vite output, `outDir: 'dist'` per `vite.config.ts`), the existing Taskfile conventions (header comment: CWD-independent `dir:`, quoted `{{…}}` template strings, `{{.TASKFILE_DIR}}`), `KUBEDASH_STATIC_DIR` (default `backend/static` — the same target the Dockerfile's `COPY --from=frontend /build/dist ./static` maps to).
- Produces: Taskfile tasks `fe-install` (`dir: frontend`, `pnpm install --frozen-lockfile`), `fe-build` (`dir: frontend`, quoted cmd `"pnpm exec tsc --noEmit && pnpm lint && pnpm build"` — I9: the `&&` chain is quoted per the Taskfile header's template-safety convention), `fe-sync` (quoted cmd `"rm -rf {{.TASKFILE_DIR}}/backend/static && cp -r {{.TASKFILE_DIR}}/frontend/dist {{.TASKFILE_DIR}}/backend/static"` + a printed note that index.html is no-cache / assets immutable per ADR-0006 OD-4), `fe-dev` (`dir: frontend`, `VITE_API_BASE=http://localhost:8080 pnpm dev`), `fe-check` (`deps: [fe-build]` + `node {{.TASKFILE_DIR}}/scripts/fe-airgap-check.mjs {{.TASKFILE_DIR}}/frontend/dist {{if .ALLOW}}--allow "{{.ALLOW}}"{{end}}`). The check script: `node scripts/fe-airgap-check.mjs <distDir> [--allow "a,b,c"]` — walks all files, regex `https?://` and `//cdn\.` per line, skips matches whose host is in the allow-list (substring match), exits 1 printing `file:line: url` per offender, exits 0 otherwise. Text files are scanned as UTF-8; binary files are scanned ONLY when their extension is in the URL-capable list `.svg` (the others — fonts, raster images — cannot carry a loadable URL reference; M3). **Claim precision (I8):** the guarantee is "no `https?://` and no `//cdn.` references in the built bundle" — NOT "no external URL references of any kind" (a protocol-relative non-CDN URL like `//internal:8080/api` is out of scope; the briefing's R5 wording is corrected to match this in Task 7's doc pass).
- Seam: the check script is the air-gap verification seam (ADR-0020's frontend half) — CI later calls the same script without the Taskfile; it must stay Taskfile-free.
- Deletion test: deleting `fe-sync` removes the local dev path to a Flask-served SPA (developers need Docker just to see the UI); deleting the check script removes the ONLY machine-readable proof that the bundle is air-gap-clean (T14 becomes a claim, not a check).
- Adapters: 2 (local Taskfile invocation + CI direct `node` invocation — the CI job is Task 7's ci.yaml amendment).

**SATISFIES:** `taskfile-fe-loop-serves-offline-bundle` (T12, T13, T14)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_fe_airgap_check.py  (unit tier — no Docker; subprocess node)
import subprocess, node = "node"  # node is a repo toolchain prereq (frontend build needs it)

def _run(dist: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([node, str(REPO_ROOT / "scripts/fe-airgap-check.mjs"), str(dist), *extra],
                          capture_output=True, text=True)

def test_clean_dist_passes(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text('<script src="./assets/main.js"></script>')
    (tmp_path / "assets/main.js").write_text("console.log('hi')")
    r = _run(tmp_path)
    assert r.returncode == 0

def test_cdn_ref_fails_with_offender(tmp_path):
    (tmp_path / "index.html").write_text('<script src="https://cdn.example.com/lib.js"></script>')
    r = _run(tmp_path)
    assert r.returncode == 1
    assert "index.html" in r.stdout and "https://cdn.example.com/lib.js" in r.stdout

def test_protocol_relative_cdn_fails(tmp_path):
    (tmp_path / "a.js").write_text("x = '//cdn.foo.com/b.js'")
    r = _run(tmp_path)
    assert r.returncode == 1

def test_allow_list_overrides(tmp_path):
    (tmp_path / "index.html").write_text('<script src="https://internal.example.com/lib.js"></script>')
    r = _run(tmp_path, "--allow", "internal.example.com")
    assert r.returncode == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_fe_airgap_check.py -v`
Expected: 4 FAIL (script missing).
- [ ] **Step 3: Implement**

`scripts/fe-airgap-check.mjs` — plain ESM, ~40 lines: `fs.readdirSync` recursive walk, the two regexes, allow-list substring skip, offender lines, exit code. `Taskfile.yaml` — the five tasks per the Interfaces block, following the existing style (each task's `desc:` one-liner; `fe-check` declares `requires: { vars: [] }` — no new required vars; `ALLOW` is optional via `{{if .ALLOW}}`). `.gitignore` — add `backend/static/` with a comment (synced build output; the Dockerfile bakes its own copy from `frontend/dist`).
- [ ] **Step 4: Run tests to verify they pass + the real loop**

Run: `cd backend && uv run pytest tests/test_fe_airgap_check.py -v && cd .. && task fe-install fe-build fe-sync fe-check`
Expected: pytest green; the Taskfile loop ends with `backend/static/index.html` present and `fe-check` exit 0 (T12 + T14 on the real bundle).
- [ ] **Step 5: Commit**

```bash
git add scripts/fe-airgap-check.mjs Taskfile.yaml .gitignore backend/tests/test_fe_airgap_check.py
git commit -m "build: offline fe loop + no-CDN air-gap check in Taskfile (ADR-0020/0021)"
```

---

### Task 7: Docs, ADR bookkeeping, CI wiring, acceptance + full verification

**Files:**
- Modify: `.skillgrid/ASSUMPTIONS.md` (LOCKED index +0021 row, ADR-0020 row annotated, sequence → 0021), `README.md` (quickstart fe-loop + 3 env vars in the env table), `.github/workflows/ci.yaml` (frontend job: add the `node scripts/fe-airgap-check.mjs frontend/dist` step after `pnpm build`; the check script is the same artifact Task 6 built — no new CI dependency), `.skillgrid/state.yaml` (phase update at handoff), `.skillgrid/ARCHITECTURE.md` (§11 one-line superseded-in-part note)
- Create: `.backlog/decisions/decision-021.md` (copy of the ADR per the ticketing convention), `.skillgrid/specs/2026-10-17-authentication-vertical/acceptance.feature` (7 scenarios — the exact names every task's SATISFIES references)
- Test: the full-suite verification below is this task's test step.

**Interfaces:**
- Consumes: everything from Tasks 1–6 (verifies the assembled surface — same role as base-structure TICKET-12).
- Produces: the in-force ADR-0021 bookkeeping (LOCKED index is the source of truth for later changes), the acceptance.feature (scenario names frozen by the SATISFIES lines), green CI.
- Seam: none (docs/verification task).
- Deletion test: deleting the acceptance.feature breaks the SATISFIES cross-reference (grep check in the step below).
- Adapters: none.

**SATISFIES:** `adr-0021-local-mode-in-force`, all scenario-name cross-checks

- [ ] **Step 1: Write `acceptance.feature`** — one Feature (`Authentication vertical: local admin + SSO + offline bundle`), 7 scenarios with the EXACT names: `local-admin-login-issues-jwt`, `admin-sees-local-cluster-from-config`, `login-page-offers-sso-and-local`, `profile-page-shows-identity`, `taskfile-fe-loop-serves-offline-bundle`, `adr-0021-local-mode-in-force`, `oidc-login-still-issues-jwt` (the no-regression guard: the existing OIDC scenario re-asserted in this change's feature file).
- [ ] **Step 2: ADR bookkeeping** — `ASSUMPTIONS.md`: add the 0021 row to the LOCKED table, flip the ADR-0020 row's note to "superseded-in-part by 0021 (local-mode scope; see ADR-0021)", set "Highest sequence in use: 0021"; copy the ADR to `.backlog/decisions/decision-021.md`; `ARCHITECTURE.md` §11: one line — "The bootstrap-admin local mode is now implemented (ADR-0021); the multi-user no-IdP mode remains deferred (ADR-0013)."
- [ ] **Step 3: CI wiring** — `ci.yaml` frontend job: after `pnpm build`, run `node scripts/fe-airgap-check.mjs frontend/dist` (fails the job on any CDN ref — T14 in CI).
- [ ] **Step 4: Full verification (the L3 floor for a high-risk change)**

Run, in order, recording each result:
```bash
cd backend && uv run ruff check . && uv run mypy app && uv run pytest tests/ -v -m "not integration"
cd frontend && pnpm test && pnpm exec tsc --noEmit && pnpm lint && pnpm build
cd ../cli && go vet ./... && go test ./...
helm lint charts/kubedash && helm template t charts/kubedash
grep -c "0021" .skillgrid/ASSUMPTIONS.md   # >= 2 (index row + ADR-0020 annotation)
grep "SATISFIES" .skillgrid/specs/2026-10-17-authentication-vertical/blueprint.md | wc -l  # 7 tasks cite scenarios
```
Expected: all green, or each non-green line explicitly recorded as environment-blocked (Docker-dependent integration tests = CI backstop, the base-structure pattern).
- [ ] **Step 5: Commit (spec-zone + docs, separate from code per the zone guard)**

```bash
git add .skillgrid/ASSUMPTIONS.md .backlog/decisions/decision-021.md README.md .skillgrid/ARCHITECTURE.md \
        .github/workflows/ci.yaml .skillgrid/state.yaml \
        .skillgrid/specs/2026-10-17-authentication-vertical/acceptance.feature
git commit -m "docs(auth): ADR-0021 in force + acceptance scenarios + CI no-CDN gate"
```

---

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Shell commands (Taskfile `fe-sync` `rm -rf`) | Applicable: `rm -rf` on a derived path | The target is `{{.TASKFILE_DIR}}/backend/static` — absolute, derived from the Taskfile's own location, never user-input; `.gitignore`d so a stray dir is regenerable | `test_fe_airgap_check.py`-adjacent Taskfile smoke: `task fe-sync` from a nested cwd (`cd frontend && task fe-sync`) still hits the repo-root path (T12 key link: Dockerfile/Taskfile parity) |
| Subprocess (node check script via pytest + CI) | Applicable: the script's exit code gates the build | Plain ESM, no deps, read-only over `dist/`, deterministic regex; tested against fixtures (clean, cdn, protocol-relative, allow-list) | `test_fe_airgap_check.py` (4 cases, Task 6 Step 1) |
| Version-control automation | N/A: no git hooks or PR automation added (CI runs checks, doesn't mutate) | — | — |
| Executable-file classification | N/A: no new executables (the check script is `node`-invoked, not `chmod +x`) | — | — |
| Process integration (boot hook in `create_app`) | Applicable: the upsert runs in the app's process at import time | Idempotent upsert on the `email` unique key; concurrent replicas converge (same row, last-writer hash wins — the hash is deterministic per env value); failure = boot failure (visible), not a half-state | `test_bootstrap.py` (idempotency + no-op cases, Task 2 Step 1) |
| `_shared/{planning,craft,verification,knowledge}/` files | N/A: none touched | — | — |
| Mnemonic tool contracts | N/A: no MCP contract changes | — | — |

## Open Items Carried Forward (explicit, not placeholders)

- **Non-admin local users** can sign in (once created) but have no cluster access until the permission-management change (ADR-0013) ships CA-based kubeconfig + bindings — a deliberate intermediate state, parked there by the briefing's out-of-scope list.
- **`task fe-dev` proxy depth** (briefing Open Questions): `VITE_API_BASE` is the default (zero vite config change); `server.proxy` is the recorded follow-up if CORS noise appears (`cors_origins` already exists in Settings for it).
- **Vendored node_modules for build-time offline install** — deferred per decision D2; `--frozen-lockfile` against a registry/`file:` store is the supported air-gap install path; T13/T14 cover the runtime guarantee.
- **ADR-0001..0013 file backfill** (base-structure onboarding note) — still open, separate task; this change's ADR-0021 is the next in the sequence and uses madr-full per config.

## Execution Notes

- **Ordering:** Tasks 1→2→3→4 are strictly sequential (each consumes the previous); Task 5 (frontend) can start after Task 1+4 land (it needs the `/auth/settings` + `/auth/local` + grown `me` contracts — exactly the base-structure T08 pattern); Task 6 is independent of 1–5 (pure tooling) and can run in parallel in its own context; Task 7 is last (verifies the assembled surface).
- **Waves:** Wave 1: Task 1 (+ Task 6 in parallel). Wave 2: Task 2. Wave 3: Task 3. Wave 4 (parallel): Task 4, Task 5. Wave 5: Task 7.
- **One-way doors:** OD-A (Task 2), OD-B+OD-C (Task 1), OD-D (Task 4) — each stops for explicit user approval at its checkpoint.
- **Classification:** high-risk (auth + additive migration) → L3+ verification (Task 7 Step 4) and the final review escalates to `parallel-code-review` per the rigor tiers.
- **Slicing:** 7 tasks, 5 waves → `skillgrid:slicing` produces `tasks.md` with the vertical tickets before execution handoff.

