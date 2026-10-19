# Authentication Vertical — Design Briefing (requirements & intent)

> **STATUS:** `draft` (2026-10-17)

> **Role:** this is the *what* — the validated design/spec: problem, intent,
> requirements, success criteria. The companion `blueprint.md` is the *how*
> (implementation plan). Do not rename.

## Problem / Intent

The base-structure spine (change
`2026-10-17-kubedash-base-structure`) gave KubeDash a working OIDC-only
login: the SPA's Login view auto-bounces to `/api/v1/auth/login`, the IdP
callback lands a JWT, and the `users` row is upserted with a
`role` column that nothing can currently set. Three gaps keep the product
unusable on its own:

1. **No way to sign in without an IdP.** ADR-0020 (air-gap) deliberately
   deferred "pure local username/password mode" to ARCHITECTURE.md §11,
   assuming every site has an internal IdP. A site that has *no IdP at
   all* — or the bootstrap moment before SSO is wired — has no way in.
2. **No admin distinction.** `users.role` exists (`user` default,
   `admin` settable) but has no issuer, no enforcement, and no UI.
   Admins need cluster access via their own in-cluster or local
   kubeconfig (not the registry), which nothing today resolves.
3. **No local frontend workflow.** The SPA is only built inside the
   Docker image (stage 1). There is no Taskfile path to build the SPA and
   serve it from `backend/` locally, and nothing proves the built bundle
   is air-gap-clean (no CDN/external references) per ADR-0020.

This vertical closes all three: local password login (bootstrap admin),
admin identity + kubeconfig source, a real login page (SSO + password),
a user profile page as the post-login landing, and the offline
frontend build/sync loop in the root Taskfile.

## Purpose & Success Criteria

- **Purpose:** make authentication self-sufficient — a fresh KubeDash
  install with no IdP configured gets in as a local admin; an IdP-configured
  install offers both SSO and local sign-in; admins act on their own
  kubeconfig (in-cluster or mounted file); and a developer can build +
  serve the SPA offline with a verifiable no-CDN guarantee.
- **Success criteria:**
  - `task fe-install fe-build fe-sync` produces `backend/static/`
    (git-ignored) served by `task backend-run` at `/` with the login page.
  - `task fe-check` fails (non-zero exit) if any built asset references
    `https?://` or `//cdn.` (the exact scope — see Out of scope: No-CDN
    check precision).
  - `POST /api/v1/auth/local` with the bootstrap admin's email/password
    returns the same JWT delivery shape as OIDC; wrong password → 401
    `INVALID_CREDENTIALS` (stable envelope).
  - Bootstrap admin: with `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL` +
    `KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD` set, the app creates exactly one
    idempotent `users` row (role `admin`, `auth_source='local'`) at boot;
    with neither set, boot is unchanged and local login returns 403
    `LOCAL_AUTH_DISABLED`.
  - `GET /api/v1/auth/me` gains `auth_source` (`"local" | "oidc"`) and,
    for admin users, `kubeconfig_source` (`"in-cluster" | "kubeconfig-file" | null`).
  - Admins see registered clusters *plus* a synthetic `local` cluster
    backed by the admin kubeconfig source; normal users see only their
    bound clusters (unchanged behavior).
  - SSO login upserts users with `auth_source='oidc'` and role `user`
    (existing behavior preserved); SSO is still the primary path
    (ADR-0020 boundary intact).
  - Login page: two options — "Sign in with SSO" (302 to
    `/api/v1/auth/login`, only rendered when `oidc_issuer` is configured)
    and a local username/password form. After either path, the app
    redirects to `/profile`.
  - Profile page (`/profile`): identity (display name, email, groups),
    role badge, auth source, last login; logout button. It is the
    post-login landing page.
  - All new/changed behavior has unit tests; the full backend + frontend
    suites stay green (no regressions in the base-structure spine).
- **Out of scope (explicit):**
  - **No-CDN check precision** (locked at the blueprint gate): `task fe-check` guarantees "no `https?://` and no `//cdn.` references in the built bundle" — protocol-relative non-CDN URLs (e.g. `//internal:8080/api`) are not covered (they cannot appear in a same-origin-served bundle, and a wider regex false-positives on non-URL content).
  - **Permission management** (its own later change, ADR-0013):
    self-service CA-based kubeconfig for non-admin local users, role
    templates, bindings UI, drift detection. Non-admin local users in
    THIS vertical can sign in and see their profile, but get no cluster
    access until that change lands.
  - Admin creating additional local users from the UI (bootstrap-admin
    only in this vertical; user CRUD belongs to permission management).
  - SCIM provisioning (ADR-0018), JIT login (ADR-0017), PAM (ADR-0016).
  - Changes to the JWT delivery contract (302 → `/?token=…&refresh=…`)
    or the refresh-token rotation scheme (ADR-0001, OD-1 of base-structure).
  - Ingress auth integration (ADR-0019), kubectl credential plugin flow
    (in-flight `2026-10-17-kubectl-oidc-plugin` change).
  - Vendoring `node_modules` for build-time offline `pnpm install` —
    `pnpm install --frozen-lockfile` from a registry/`file:` store is the
    supported air-gap install path (recorded decision D2); the no-CDN
    guarantee covers *runtime* references in the built bundle.

## Context

- **Fits existing patterns: yes.** Extends the base-structure spine in
  place: `AuthApi` (R2) gains `/auth/local` + a password verifier;
  `users` gains two columns via a new Alembic revision (the OD-3
  pattern: additive, version-byte-free); `create_app()` gains a
  boot-time bootstrap hook; `services/k8s_client.py` gains an
  admin-kubeconfig source alongside the registry pool; the frontend
  gains two views and one hook. No new top-level module.
- **In-force decisions constraining this change** (from
  `.skillgrid/ASSUMPTIONS.md` § LOCKED):
  - **ADR-0001** — Flask + Flask-Smorest, Pydantic schemas, HS256 JWTs,
    refresh-token rotation. The local path reuses `issue_token_pair`
    verbatim.
  - **ADR-0004** — RBAC proxy via SAR. The synthetic `local` cluster
    goes through the same SAR path as registry clusters.
  - **ADR-0002** — multi-cluster via encrypted kubeconfig registry
    (one-way-door). The admin source is a *second* input to the client
    pool, not a replacement; registry rows are untouched.
  - **ADR-0006** — single container serves API + static SPA. The Taskfile
    `fe-sync` step exists so *local dev* mirrors the image's
    `COPY --from=frontend /build/dist ./static` without Docker.
  - **ADR-0020** — air-gap: zero outbound calls at runtime. The no-CDN
    build assertion is the frontend half of its verification story;
    SSO discovery/JWKS caching (0020's OIDC half) is unchanged.
- **Superseding decision:** ADR-0021 (authored by this change,
  `artifacts/04-adr-0021-local-admin-auth.md`) narrows the ADR-0020 §11
  deferral: local password mode is introduced NOW as the bootstrap-admin
  + local-user path; SSO remains the primary path. The LOCKED index
  gains row 0021; ADR-0020's deferral note is annotated (superseded-in-part,
  per the IRON RULE: flip, don't delete).
- **Conventions** (ARCHITECTURE.md §10): Python 3.12 + `uv` + `ruff` +
  `mypy --strict`; TS strict + `pnpm` + `eslint`; CoreUI SCSS (no
  Tailwind); error shape `{ error: { code, message, details? } }` with
  stable string codes; API at `/api/v1/*`; Conventional Commits.
- **Base-structure handoffs this change consumes:**
  - `app/core/security.py` — `issue_token_pair`, `rotate_refresh`,
    `require_auth`, the JWT verify hook with jti revocation.
  - `app/api/_authhook.py` — path-scoped `before_request` for
    `/api/v1/*` minus `/api/v1/auth/*`.
  - `app/services/k8s_client.py` — `K8sClientPool` (the seam where the
    admin source interposes; ADR-0010 informer is still deferred past
    both).
  - `frontend/src/lib/api.ts` — `apiFetch` with single-in-flight 401
    refresh; `ProtectedRoute` gating on `kd_token`.
  - Root `Taskfile.yaml` — CWD-independent, `{{.TASKFILE_DIR}}`-anchored
    `dir:` + quoted-`{{...}}` template convention.

## Approaches Considered

- **Chosen: extend the existing spine, one migration, one new ADR.**
  Local auth is a sibling route of the OIDC route in `AuthApi`; both
  converge on the same `users` upsert + `issue_token_pair` + JWT
  delivery contract, so the SPA's token handling, refresh, and revocation
  are shared. Admin cluster access is a second input to the existing
  client pool, not a parallel registry.
- **Rejected: separate `auth-local` Api class.** Two Api classes for one
  concern (issuing tokens to users) splits the `users` upsert logic and
  the `/auth/*` auth-hook opt-out story. The OIDC and local paths share
  80% of their body; a sibling route is the DRY shape.
- **Rejected: `password` column + plain `users` role for everything.**
  Without `auth_source` the profile page and the admin gate cannot tell a
  local admin from an SSO user, and the SSO upsert would need to
  null-check a password it never writes. Two nullable columns are the
  minimum honest schema.
- **Rejected: admin kubeconfig via registry row named "local".** A
  registry row implies a `cluster_bindings` row and SAR against the
  registry kubeconfig; the admin's in-cluster SA identity is not a
  registry entry and would fight the one-way-door (registry rows are
  user-registered, encrypted, bound). A config-driven source keeps the
  registry pure.

## Requirements

1. **R1 — Local password auth (bootstrap admin).**
   - **Current:** `AuthApi` is OIDC-only; `users` has no password column;
     boot does not create users.
   - **Target:** `users` gains `password_hash` (nullable, `pbkdf2:sha256:
     600000$<salt>$<hash}` — stdlib `hashlib.pbkdf2_hmac`, no new
     dependency) and `auth_source` (`'local' | 'oidc'`, NOT NULL default
     `'oidc'` for existing rows). `POST /api/v1/auth/local`
     (`{ email, password }`) verifies the hash and issues the standard
     token pair. `create_app()` runs a boot hook: when
     `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL` and
     `KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD` are both set, upsert the user
     (role `admin`, `auth_source='local'`, password_hash set) —
     idempotent, runs every boot, updates the hash on password change.
     When either is unset, local login returns 403 `LOCAL_AUTH_DISABLED`
     (stable envelope) and boot is a no-op.
   - **Acceptance:** unit + container tests: boot with env set → row
     exists with role `admin`, re-boot → no duplicate, password changed
     in env → hash updated; login with correct password → 302
     `/?token=…&refresh=…` (same contract as OIDC callback); wrong
     password → 401 `INVALID_CREDENTIALS`; unknown email → 401
     `INVALID_CREDENTIALS` (no user enumeration); env unset → 403
     `LOCAL_AUTH_DISABLED`; SSO callback still upserts with
     `auth_source='oidc'` and role `user`.
   - **Acceptance scenario:** `happy path local-admin-login-issues-jwt` →
     `acceptance.feature`

2. **R2 — Admin identity + kubeconfig source.**
   - **Current:** `users.role` is settable but never set to `admin` by
     the app; `K8sClientPool` only knows registry kubeconfigs.
   - **Target:** `K8sClientPool` gains an admin source resolved once at
     pool construction from config: `KUBEDASH_ADMIN_KUBECONFIG` empty →
     in-cluster service account (seam for the test:
     `resolve_admin_source() -> AdminSource`); set → file path loaded
     via `kubernetes.config.load_kube_config`. `GET /api/v1/clusters`
     for `role='admin'` callers returns the bound-registry clusters plus
     one synthetic entry: `{ "id": 0, "name": "local", "api_server":
     <resolved or "in-cluster">, "source": "admin" }` (registry rows
     carry `source: "registry"`). `id: 0` routes to the admin source in
     the pool; normal users never see it. `GET /api/v1/auth/me` returns
     `auth_source` for everyone and `kubeconfig_source`
     (`"in-cluster" | "kubeconfig-file" | null`) for admins.
   - **Acceptance:** unit tests (pools mocked): admin caller's list
     includes the synthetic entry exactly once; non-admin list is
     unchanged; `get_client(0)` for an admin returns a client from the
     admin source; `get_client(0)` for a non-admin → 404/403 stable
     code; me-response shape assertions for both roles. Integration
     (kind, env-blocked locally): pod list through the admin source on
     the kind cluster.
   - **Acceptance scenario:** `happy path admin-sees-local-cluster-from-config` →
     `acceptance.feature`

3. **R3 — Login page: SSO + local form, post-login → /profile.**
   - **Current:** `views/Login/index.tsx` parks the callback tokens, then
     bounces to `/api/v1/auth/login` (SSO only, no form).
   - **Target:** The Login view (a) still parks `?token=&refresh=` from
     the callback and redirects to `/profile`; (b) shows "Sign in with
     SSO" (302 to `/api/v1/auth/login`) — the button is hidden when
     `GET /api/v1/auth/settings` returns `sso_enabled: false` (new
     trivial endpoint: `{ sso_enabled: bool, local_enabled: bool }`,
     derived from config, open pre-JWT); (c) shows a local
     email/password form posting to `/api/v1/auth/local` on
     `local_enabled: true`, surfacing the error envelope inline
     (`INVALID_CREDENTIALS`, `LOCAL_AUTH_DISABLED`). On success the form
     follows the 302 (same token-parking path as SSO).
   - **Acceptance:** Vitest + MSW: token-in-URL parks and lands on
     `/profile`; SSO button present iff `sso_enabled`; form submits to
     `/auth/local` and 302 → park → `/profile`; error envelope renders
     (401/403). `tsc --noEmit` + `eslint` + `build` green.
   - **Acceptance scenario:** `happy path login-page-offers-sso-and-local` →
     `acceptance.feature`

4. **R4 — Profile page (post-login landing).**
   - **Current:** no profile route; `useCluster()` already fetches
     `/auth/me` (identity + groups + role).
   - **Target:** `views/Profile/index.tsx` at `/profile` (inside
     `ProtectedRoute`): identity card (display name, email, groups
     chips, role badge, auth-source badge, last login from
     `/auth/me` — `last_login_at` added to `MeOut`), logout button
     (POST `/auth/logout` → clear `kd_token`/`kd_refresh` →
     `/login`). `routes.tsx` gains the route; the default post-login
     redirect is `/profile`.
   - **Acceptance:** Vitest + MSW: renders me-fields; role `admin` shows
     the badge; logout clears storage and navigates. `tsc/lint/build`
     green.
   - **Acceptance scenario:** `happy path profile-page-shows-identity` →
     `acceptance.feature`

5. **R5 — Taskfile: offline frontend build + sync loop.**
   - **Current:** `Taskfile.yaml` has no frontend tasks; `frontend/dist`
     and `backend/static` are produced only by the Docker image.
   - **Target:** root `Taskfile.yaml` gains, following the existing
     CWD-independent `dir:` + `{{.TASKFILE_DIR}}` convention:
     - `fe-install` — `pnpm install --frozen-lockfile` (offline-capable:
       works from a registry or `file:` store per the air-gap install
       path).
     - `fe-build` — `pnpm exec tsc --noEmit && pnpm lint && pnpm build`.
     - `fe-sync` — `rm -rf backend/static && cp -r frontend/dist
       backend/static` (mirrors the Dockerfile's
       `COPY --from=frontend /build/dist ./static`); prints a one-line
       note that `index.html` is no-cache and `/assets/*` immutable
       (ADR-0006/OD-4).
     - `fe-dev` — `pnpm dev` with `VITE_API_BASE=http://localhost:8080`
       (vite proxy-free; the API is same-origin in prod, proxied via the
       env in dev — no new vite config: `apiFetch` already honors
       `VITE_API_BASE`).
     - `fe-check` — `fe-build` + a node script
       (`scripts/fe-airgap-check.mjs`) that walks `frontend/dist/**`
       and fails (exit 1, listing offenders) on any `https?://` or
       `//cdn.` reference not in the allow-list (empty by default;
       `task fe-check ALLOW='…'` overrides). This is the air-gap proof:
       the served bundle never points at a CDN.
   - **Acceptance:** from a clean checkout: `task fe-install fe-build
     fe-sync` → `backend/static/index.html` exists; `task backend-run`
     serves it at `/`; `task fe-check` passes on the current bundle and
     fails (with an offender printed) on a deliberately injected CDN
     reference (test: the script is unit-tested against a fixture
     dist/ with a known-bad asset).
   - **Acceptance scenario:** `happy taskfile-fe-loop-serves-offline-bundle` →
     `acceptance.feature`

6. **R6 — Docs + ADR bookkeeping.**
   - `artifacts/04-adr-0021-local-admin-auth.md` (madr-full): local
     password mode as bootstrap-admin path; SSO primary; supersedes-in-part
     the ADR-0020 §11 deferral.
   - `.skillgrid/ASSUMPTIONS.md`: LOCKED index gains row 0021; ADR-0020
     row annotated "superseded-in-part by 0021 (local mode scope)";
     "highest sequence in use" → 0021.
   - `.backlog/decisions/decision-021.md` copy (ticketing convention).
   - `backend/app/__init__.py` / README quickstart: the new Taskfile
     frontend loop + the two bootstrap env vars in the env table.
   - **Acceptance:** `grep 0021 ASSUMPTIONS.md` hits the index row; the
     ADR file parses (frontmatter `status: accepted`); README renders.
   - **Acceptance scenario:** `happy adr-0021-local-mode-in-force` →
     `acceptance.feature`

## Implementation Decisions

- **Modules to build/modify:** `backend/app/models/user.py` (+2
  columns), a new Alembic revision (additive),
  `backend/app/core/security.py` (pbkdf2 helpers),
  `backend/app/api/auth.py` (`/auth/local`, `/auth/settings`,
  `MeOut` growth), `backend/app/core/config.py` (3 new settings),
  `backend/app/__init__.py` (bootstrap boot hook),
  `backend/app/services/k8s_client.py` (admin source),
  `backend/app/api/clusters.py` (synthetic admin entry),
  `frontend/src/views/Login/index.tsx` (rewrite),
  `frontend/src/views/Profile/index.tsx` (new),
  `frontend/src/routes.tsx` (+ route),
  `frontend/src/lib/api.ts` (unchanged), `frontend/src/lib/types.ts`
  (MeOut growth), root `Taskfile.yaml` (+5 tasks),
  `scripts/fe-airgap-check.mjs` (new), `backend/tests/**` (new +
  amended), `frontend/tests/**` (new + amended), docs per R6.
- **Interfaces:**
  - `security.hash_password(pw) -> str`,
    `security.verify_password(stored, pw) -> bool` (pbkdf2:sha256,
    600_000 iters, 16-byte salt; format
    `pbkdf2:sha256:600000$<b64salt>$<b64hash>`).
  - `create_app(bootstrap=…)` — the bootstrap hook is an idempotent
    `_bootstrap_local_admin(app)` called after `db.create_all()` in the
    factory; tests can pass a flag to skip it (isolation).
  - `K8sClientPool.resolve_admin_source(settings) -> AdminSource
    ("in-cluster" | "kubeconfig-file")` — pure, testable seam;
    `get_client(cluster_id=0)` routes to it for admins.
  - `MeOut` (Pydantic): `+ auth_source: Literal["local","oidc"]`,
    `+ kubeconfig_source: Literal["in-cluster","kubeconfig-file"] |
    None`, `+ last_login_at: datetime | None`.
  - Cluster list item: `+ source: Literal["registry","admin"]`,
    synthetic admin row has `id: 0`.
  - `GET /api/v1/auth/settings` → `{ sso_enabled: bool, local_enabled:
    bool }` — open route (pre-JWT), derived from
    `oidc_issuer` non-empty / bootstrap env set.
- **Data flow:** local login: browser → `POST /api/v1/auth/local` →
  verify pbkdf2 → upsert/refresh `last_login_at` → `issue_token_pair`
  → 302 `/?token=&refresh=` → SPA parks → `/profile`. SSO: unchanged.
  Admin cluster: `GET /api/v1/clusters` → admin sees synthetic
  `id:0` → `GET /api/v1/clusters/0/resources/pods` → pool routes 0 →
  admin source → SAR as usual.
- **Error handling:** wrong/unknown local credentials → 401
  `INVALID_CREDENTIALS` (single code, no enumeration); local auth not
  configured → 403 `LOCAL_AUTH_DISABLED`; `id:0` for non-admin → 403
  `CLUSTER_NOT_ACCESSIBLE` (existing stable code family — reuse, do not
  invent a new one for this case); admin kubeconfig file unreadable at
  boot → `/readyz` 503 naming `admin-kubeconfig` (fail visible, don't
  half-start).
- **Dependencies:** none new. Python: stdlib `hashlib`/`base64` for
  pbkdf2 (passlib/argon2 deliberately not added — one fewer supply-chain
  entry, air-gap-friendly). Node: none new (the check script is plain
  ESM node, run by `task fe-check`).
- **Migrations:** one new Alembic revision: `users.password_hash
  VARCHAR(255) NULL`, `users.auth_source VARCHAR(16) NOT NULL DEFAULT
  'oidc'`. Additive; existing rows keep working (SSO users become
  explicit `'oidc'`). No data backfill beyond the default.

## Testing Decisions

- **What makes a good test:** external behavior only — HTTP responses,
  stored rows, task exit codes, rendered views. pbkdf2 is tested via
  the API (login in, wrong password out), never via hash-string
  equality (the format is an implementation detail a reviewer may
  change).
- **Modules to test:** `auth` Api (local + settings + me growth),
  bootstrap hook (idempotency + env matrix), `security` password
  helpers (round-trip only), `k8s_client` admin source (mocked pool),
  `clusters` list (admin vs non-admin shape), frontend Login/Profile
  (MSW), `scripts/fe-airgap-check.mjs` (fixture dist/ good + bad).
- **Edge cases:** concurrent boot (two replicas) → the bootstrap
  upsert is on-`email` unique and idempotent (upsert, not create);
  SSO login as the bootstrap email (IdP sub colliding with local
  email) → the upsert refreshes `auth_source='oidc'` and the password
  is ignored (SSO wins for that identity; documented in the ADR);
  admin with both in-cluster AND file configured → file wins
  (deterministic, logged); `KUBEDASH_ADMIN_KUBECONFIG` pointing at a
  missing file → readyz 503, not a boot crash; local login with
  `role='user'` (if such a row ever exists) → works, sees no
  `id:0`.
- **Docker-free tiers:** all unit tests run without Docker; the
  kind-integration admin-pod-list test carries the `integration`
  marker (CI backstop, same pattern as base-structure).

## Impact on Global Docs

- `.skillgrid/ASSUMPTIONS.md`: LOCKED index +0021, ADR-0020 row
  annotated, sequence counter → 0021.
- `artifacts/04-adr-0021-local-admin-auth.md`: new (madr-full).
- `artifacts/04-adr-0020-air-gap-deployment.md`: §11 deferral note gets
  a superseded-in-part pointer (the row in the index flips per IRON
  RULE; the file keeps a one-line note under its decision outcome).
- `README.md`: quickstart gains the `task fe-install fe-build fe-sync
  backend-run` loop + the bootstrap env vars; env table gains
  `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL`, `KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD`,
  `KUBEDASH_ADMIN_KUBECONFIG`.
- `.skillgrid/ARCHITECTURE.md`: §11 (deferred no-IdP) — one-line note
  that the bootstrap-admin local mode is now implemented (ADR-0021);
  the full no-IdP multi-user mode remains deferred.

## Clarity Report

Compressed interview with the user on 2026-10-17 (4 answer-select
rounds; the design source is the validated ARCHITECTURE.md + 20 in-force
ADRs, so the frontier was the ADR-0020 tension and three scope calls):

| Dimension           | Score | Min  | Status | Notes                              |
|---------------------|-------|------|--------|------------------------------------|
| Goal Clarity        | 0.95  | 0.75 | pass   | "auth vertical" = local+SSO login, profile, admin kcfg, Taskfile loop — user-confirmed |
| Boundary Clarity    | 0.90  | 0.70 | pass   | permission management explicitly out; bootstrap-admin-only provisioning |
| Constraint Clarity  | 0.90  | 0.65 | pass   | ADR-0020 narrowed via new ADR-0021 (user chose new-ADR over annotation) |
| Acceptance Criteria | 0.85  | 0.70 | pass   | every requirement carries a concrete pass/fail check |
| **Clarity**         | 0.08  | ≤0.20| pass   | residual: fe-dev proxy depth (see Open Questions) |

**Interview log:**

| Round | Question summary | Decision locked |
|-------|------------------|-----------------|
| 1 | ADR-0020 defers local password mode — pull it in now? | New **ADR-0021** (madr-full) that narrows the §11 deferral: local mode = bootstrap-admin path, SSO stays primary |
| 2 | Admin cluster identity: how resolved? | **Config-driven**: `KUBEDASH_ADMIN_KUBECONFIG` empty → in-cluster; set → file. Synthetic `local` cluster in the list for admins |
| 3 | How are local users provisioned? | **Bootstrap admin only** this vertical (env-driven, idempotent). Normal local users come with permission management |
| 4 | Taskfile scope for the frontend loop? | **Full local loop**: fe-install / fe-build / fe-sync / fe-dev / fe-check (with the no-CDN assertion as the air-gap proof) |

## Open Questions & Assumptions

- **Decision D1 (locked, round 2):** the synthetic admin cluster has
  `id: 0`. The pool routes `0` to the admin source. If a registry
  cluster ever gets id 0 (it can't — PG sequences start at 1) the
  collision is documented in the ADR as impossible-by-construction.
- **Decision D2 (locked, round 4):** build-time offline `pnpm install`
  uses `--frozen-lockfile` against a registry or `file:` store; the
  air-gap *verification* guarantee is the no-CDN check on the built
  bundle (runtime), not vendored node_modules.
- **Question (non-blocking):** `task fe-dev` sets `VITE_API_BASE` for
  the dev server's origin; the vite `server.proxy` alternative (proxy
  `/api` → `:8080` in dev) is cleaner for cookie-less JWTs but needs a
  vite.config edit. The blueprint defaults to `VITE_API_BASE` (zero
  config change) and records proxy as the follow-up if CORS noise
  appears. `cors_origins` already exists in Settings for exactly this.

## Decisions (ADR)

- **ADR-0021 — Local Admin Auth (bootstrap password mode):** authored
  by this change (`artifacts/04-adr-0021-local-admin-auth.md`),
  supersedes-in-part the ADR-0020 §11 deferral.
- In-force ADRs constraining it: ADR-0001 (JWT/refresh reuse),
  ADR-0002 (registry untouched; admin source is a second pool input),
  ADR-0004 (SAR on the synthetic cluster), ADR-0006 (static serving),
  ADR-0020 (air-gap boundary preserved; SSO primary).

## Terms

- **Bootstrap admin** — the single local `users` row created
  idempotently at boot from
  `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL`/`KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD`;
  role `admin`, `auth_source='local'`. Not in the terms files (introduced
  by this spec).
- **Admin kubeconfig source** — the pool input resolved from
  `KUBEDASH_ADMIN_KUBECONFIG` (empty → in-cluster service account;
  set → mounted/local file); backs the synthetic `local` cluster
  (`id: 0`) visible to admin callers. Not in the terms files.
- **No-CDN check** — the `task fe-check` assertion that no built asset
  in `frontend/dist/` references an external URL (https?://, //cdn) —
  the frontend half of ADR-0020's runtime zero-outbound guarantee.
  Not in the terms files.
- **Cluster / Cluster binding / SubjectAccessReview / JWT delivery
  contract** — see `.skillgrid/artifacts/02-technical-terms.md`.
