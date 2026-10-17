# KubeDash 5.0 Base Structure — Design Briefing (requirements & intent)

> **STATUS:** `draft` (2026-10-17)

> **Role:** this is the *what* — the validated design/spec: problem, intent,
> requirements, success criteria. The companion `blueprint.md` is the *how*
> (implementation plan). Do not rename.

## Problem / Intent

The repo is on the `rebase` branch with a docs/ADR/spec layer only — the
proposed 5.0 stack in `.skillgrid/ARCHITECTURE.md` (Python 3.12 Flask-Smorest
`backend/`, React 18 CoreUI `frontend/`, Go `cli/`, `charts/`) has **no code**.
Every later change (the in-flight `2026-10-17-kubectl-oidc-plugin` included)
has no target to land in. This change builds the **base structure**: a tracer
skeleton where every top-level module from ARCHITECTURE.md §2 exists and the
core spine (config → app factory → OIDC auth → cluster registry → one resource
list → SPA shell) is a real, tested, connected path. Subsystems beyond the
spine exist as thin, ADR-cited stubs so later changes have seams, not blank
files.

## Purpose & Success Criteria

- **Purpose:** give every subsequent KubeDash 5.0 change a working, green,
  convention-conforming monorepo skeleton to build on — no blank repo, no
  "scaffolding task" smuggled into feature work.
- **Success criteria:**
  - `uv sync` + `pytest` pass in `backend/` against Testcontainers (Postgres +
    Redis) with a green CI job (lint + typecheck + test + build).
  - OIDC login → JWT → `/api/v1/auth/me` works end-to-end against a mock OIDC
    provider in tests; unauthenticated requests to any `/api/v1/*` route
    return 401 with the stable error shape.
  - A cluster can be registered (encrypted kubeconfig at rest), appears in
    `GET /api/v1/clusters`, and `GET /api/v1/clusters/<id>/resources/pods`
    lists pods from a `kind` cluster (integration) / fake API server (unit).
  - `pnpm build` in `frontend/` produces a bundle served by Flask at `/`
    (catch-all), with `/api/v1/*` and `/ws/*` taking precedence.
  - `helm lint` + `helm template` pass for `charts/kubedash`.
  - `go build ./...` + `go test ./...` pass for `cli/` (skeleton, `version`
    subcommand real).
- **Out of scope:**
  - Subsystem logic beyond the spine: RBAC templates / permission service
    (ADR-0013), NaaS (ADR-0015), PAM (ADR-0016), JIT provisioning (ADR-0017),
    SCIM gateway (ADR-0018), ingress auth (ADR-0019), aggregated API
    (ADR-0012), observability backends (ADR-0003), SSE/WS streams (ADR-0009),
    the kubectl credential plugin flow (separate in-flight change), Helm
    release operations, audit best-practice checks. These get **stub
    modules with ADR pointers** only.
  - The legacy `main` stack (`src/kubedash`, `src/kdlogin`) is not modified,
    migrated, or deleted by this change.
  - E2E Playwright suite, performance tests, i18n, dark-mode polish, MCP
    server.

## Context

- **Fits existing patterns: yes-with-notes.** `rebase` carries only the
  skillgrid docs layer (`.skillgrid/`, `.backlog/`, `opencode.jsonc`,
  `AGENTS.md`). ARCHITECTURE.md §2 is the canonical layout this change
  materializes; the divergence note: ARCHITECTURE.md §2 lists `frontend/`
  as "scaffolded from coreui-free-react-admin-template" — this change
  performs that scaffolding (template copy + KubeDash extension points),
  it is not assumed pre-existing.
- In-force decisions constraining this change (from
  `.skillgrid/ASSUMPTIONS.md` § LOCKED): ADR-0001 (Flask + Flask-Smorest,
  Pydantic schemas), ADR-0002 (multi-cluster via encrypted kubeconfig
  registry — one-way-door), ADR-0003 (observability query-only), ADR-0004
  (RBAC proxy via SubjectAccessReview), ADR-0005 (CoreUI React + free admin
  template), ADR-0006 (single-container: Gunicorn serves API + static SPA),
  ADR-0007 (RQ over Celery), ADR-0008 (leader election: PG advisory lock +
  `leader_lease`), ADR-0009 (SSE over WebSocket for push; WS only for
  exec). ADR-0010 (informer cache) is **deferred** from this change — the
  spine uses direct per-request API calls; the informer seam is left in
  `services/k8s_client.py` for its own change.
- Conventions per ARCHITECTURE.md §10: Python 3.12 + `uv` + `ruff` +
  `mypy --strict` + type hints everywhere; TypeScript strict + `pnpm` +
  `eslint` + `prettier`; CoreUI SCSS (no Tailwind); Font Awesome icons;
  Conventional Commits; API at `/api/v1/*` from day one; OpenAPI 3.0 via
  Flask-Smorest at `/api/docs` + `/api/openapi.json`; error shape
  `{ error: { code, message, details? } }` with stable string codes.
- Backlog.md tracks this work as TASK-001; spec-zone commits are separate
  from code commits (zone guard per skillgrid:work-unit-commits).

## Approaches Considered

- **Chosen: Tracer thread — spine first, stubs everywhere else.** A thin
  end-to-end path (OIDC login → JWT → register cluster → list pods → SPA
  renders the list) works first; every other module from ARCHITECTURE.md §2
  exists as a thin module with a docstring citing the ADR that owns it.
  Integration risk (the unknown) is tested by the first execution wave;
  later changes thicken their own module in place.
- **Rejected: full structure, all modules thin.** All §2 files exist and
  compile, but ~40 stub modules with no shared spine means the first real
  feature still pays the integration cost alone, and stubs that are never
  wired tend to rot out of sync with ARCHITECTURE.md.
- **Rejected: directory layout + conventions only.** Fast, but leaves no
  falsifiable "it works" — the in-flight kubectl-oidc-plugin blueprint
  targets `backend/app/api/kubectl_auth.py` and needs a working app factory
  + config + extensions to hang its endpoint on.

## Requirements

1. **R1 — Backend app factory + config:** `create_app()` factory builds a
   Flask app with Flask-Smorest, SQLAlchemy, Redis, JWT verify hook, error
   handlers, and `/healthz` + `/readyz`; settings come from
   `app/core/config.py` (Pydantic `BaseSettings`) driven by
   `FLASK_ENV`-selected environment + the env vars in ARCHITECTURE.md §3.8.
   - **Current:** no `backend/` exists.
   - **Target:** `backend/app/__init__.py` exposes `create_app() -> Flask`;
     `create_app()` in a test constructs an isolated app with its own DB
     (Testcontainers Postgres) and passes.
   - **Acceptance:** `pytest backend/tests/test_app.py` green: app
     constructs; `GET /healthz` → 200; `GET /readyz` → 200 with DB + Redis
     reachable, 503 with body listing the failing dependency when Redis is
     down; `/api/openapi.json` returns valid OpenAPI 3.0 JSON.
   - **Acceptance scenario:** `happy path app-boots-and-health-probes-report` → `acceptance.feature`

2. **R2 — OIDC auth spine:** `POST /api/v1/auth/login` initiates the OIDC
   flow (302 to `/authorize`), `/api/v1/auth/callback` exchanges the code,
   upserts the `users` row, and issues an HS256 JWT (15 min) + rotating
   refresh token (30 d, hashed in `refresh_tokens`); `/api/v1/auth/me`
   returns the current user; every other `/api/v1/*` route returns 401
   `{ error: { code: "UNAUTHORIZED" } }` without a valid JWT.
   - **Current:** no auth code exists (legacy `main` auth is Jinja2-session
     based and is not the target).
   - **Target:** `app/api/auth.py` (Smorest Api) + `app/core/security.py`
     (JWT issue/verify, OIDC exchange) + `users` / `refresh_tokens` models;
     the shared `on_before_request` JWT hook is reusable by later Api
     classes.
   - **Acceptance:** test suite with a mock OIDC provider: full
     login→callback→me round trip returns the user's `sub`; expired/missing
     JWT on `/api/v1/clusters` → 401 stable error shape; refresh rotation
     invalidates the previous refresh token.
   - **Acceptance scenario:** `happy path oidc-login-issues-jwt` → `acceptance.feature`

3. **R3 — Cluster registry (multi-cluster spine):** `POST /api/v1/clusters`
   stores a cluster (name, api_server, encrypted kubeconfig via
   AES-256-GCM with `KUBEDASH_SECRET_KEY`), `GET /api/v1/clusters` lists the
   caller's clusters, `GET /api/v1/clusters/<id>/health` hits the cluster's
   `/readyz` through `services/k8s_client.py`.
   - **Current:** no cluster registry; ADR-0002 is in force (one-way-door:
     encrypted kubeconfig registry).
   - **Target:** `clusters` table (SQLAlchemy 2.0), `app/api/clusters.py`,
     `app/services/k8s_client.py` (per-cluster client pool), `cluster_bindings`
     table with user × cluster role (`viewer` | `editor` | `admin`) —
     a user sees only bound clusters.
   - **Acceptance:** registering a cluster with a kubeconfig round-trips:
     stored bytes decrypt back to the original; the row's at-rest form does
     not contain the plaintext kubeconfig; an unbound user's
     `GET /api/v1/clusters` omits the cluster; `/health` returns `up`
     against a `kind` cluster (integration) and a structured 502
     `CLUSTER_UNREACHABLE` when the API server is down.
   - **Acceptance scenario:** `happy path cluster-register-and-health` → `acceptance.feature`

4. **R4 — One resource list (generic reader):**
   `GET /api/v1/clusters/<id>/resources/pods` (with optional `namespace`)
   returns pods from the target cluster through the k8s client pool, in the
   standard list envelope, with RBAC enforced by a SubjectAccessReview
   (ADR-0004) — denied → 403 `RBAC_DENIED`.
   - **Current:** no resource access path.
   - **Target:** `app/api/resources.py` generic per-kind list endpoint
     (pods wired; the `<kind>` routing table is the seam later kinds
     plug into), `app/services/rbac.py` `can(user, verb, resource, …)` with
     30 s SAR cache.
   - **Acceptance:** against a `kind` cluster with a test pod: 200 with the
     pod; a user whose binding lacks `list` on `pods` → 403 stable shape;
     unknown kind → 404 `RESOURCE_KIND_NOT_SUPPORTED` (explicit, not a
     crash).
   - **Acceptance scenario:** `happy path list-pods-for-bound-cluster` → `acceptance.feature`

5. **R5 — SPA shell:** `frontend/` is the CoreUI free React admin template
   extended per ARCHITECTURE.md §4.1–4.2: Vite 5 + React 18 + TS strict +
   TanStack Query v5 + React Router v6 + Zustand; `views/Login/`,
   `views/Clusters/`, `views/Cluster/` (pods list) exist; `lib/api.ts`
   fetch wrapper attaches the JWT, refreshes once on 401; cluster switcher
   in the Header; `_nav.tsx`/`routes.tsx` drive the sidebar.
   - **Current:** no `frontend/`.
   - **Target:** template scaffold + the three views wired to R2/R3/R4
     endpoints; `pnpm build` green; `tsc --noEmit` + `eslint` green.
   - **Acceptance:** `pnpm build` exits 0 producing `dist/`; the Login view
     redirects to `/auth/login`; Clusters view lists clusters from
     `/api/v1/clusters`; Cluster view renders the pod table from R4
     (verified by a component test with MSW mocks + one Playwright smoke
     against the Flask-served bundle).
   - **Acceptance scenario:** `happy path spa-shell-renders-cluster-pods` → `acceptance.feature`

6. **R6 — Single-container build + Helm skeleton:** `backend/Dockerfile`
   is multi-stage (Node 20 builds the SPA → `dist/` copied to
   `backend/static/`; Python 3.12 slim runtime, non-root, `HEALTHCHECK` on
   `/healthz`, `CMD gunicorn` serving API + static catch-all per ADR-0006);
   `charts/kubedash/` has Chart.yaml + values.yaml (subset: image,
   gunicorn, OIDC auth, postgresql/redis toggle) + templates
   (Deployment with `KUBEDASH_REPLICA_ID` via Downward API, Service,
   ConfigMap, Secret) that lint and render.
   - **Current:** no Dockerfile, no `charts/`.
   - **Target:** image builds locally; `helm lint` + `helm template` pass;
     the rendered Deployment carries `KUBEDASH_REPLICA_ID` from
     `metadata.name` and env for DB/Redis/OIDC from values.
   - **Acceptance:** `docker build` exits 0; `helm lint charts/kubedash`
     and `helm template t charts/kubedash` exit 0 with the assertions above
     (template unit test or grep-based CI check).
   - **Acceptance scenario:** `happy path chart-renders-deployment-with-replica-id` → `acceptance.feature`

7. **R7 — CLI skeleton:** `cli/` is a Go module (1.22+) with cobra root +
   `version` subcommand (real: prints module version) and `get-token`
   subcommand stubbed with a docstring pointing at the in-flight
   `2026-10-17-kubectl-oidc-plugin` blueprint (it owns the plugin flow).
   - **Current:** no `cli/` (legacy `src/kdlogin` is not the target).
   - **Target:** `go build ./...` + `go test ./...` green; `version`
     prints the expected shape.
   - **Acceptance:** `go test ./...` green; `./kubedash version` prints
     `kubedash <version>`; `get-token` exits 2 with a "not yet implemented"
     message (no panic).
   - **Acceptance scenario:** `happy path cli-version-prints` → `acceptance.feature`

8. **R8 — CI pipeline:** `.github/workflows/ci.yaml` runs, per PR:
   backend (ruff + mypy --strict + pytest), frontend (tsc + eslint +
   pnpm build), cli (go vet + go test), chart (helm lint + template),
   Trivy scan of the built image. `.github/workflows/e2e.yaml` (main
   only): kind cluster + Helm install + the Playwright smoke from R5.
   - **Current:** no workflows for the 5.0 stack (legacy `_github_workflows/`
     is dormant on this branch).
   - **Target:** both workflow files exist and the PR job is green on this
     change's own merge commit.
   - **Acceptance:** `act`-or-GitHub run of `ci.yaml` on the change branch
     is green; workflow YAMLs pass actionlint.
   - **Acceptance scenario:** `happy path ci-green-on-base-structure` → `acceptance.feature`

9. **R9 — Stub modules with ADR seams:** each deferred subsystem from the
   Out-of-scope list exists as a thin module (docstring + ADR pointer +
   empty-but-valid module surface) so ARCHITECTURE.md §2's file map is
   honest: `app/api/{logs,metrics,traces,audit,permissions,namespaces,
   access,kubeconfig,admin}.py` + `app/api/scim/`, `app/services/{prometheus,
   loki,tempo,grafana,rbac,namespace,access,provisioning,scim}.py`,
   `app/tasks/{cluster_sync,health}.py` (real, minimal: they are the
   leader-gated RQ spine per ADR-0007/0008), `app/sockets/events.py`
   (namespace registered, no handlers yet — SSE is the push channel per
   ADR-0009, WS reserved for exec).
   - **Current:** none of these exist.
   - **Target:** every path listed in ARCHITECTURE.md §2 for `backend/app/`
     exists; stubs are importable, registered (APIs registered on Smorest
     with a documented 501 `NOT_IMPLEMENTED` for unimplemented routes), and
     carry `per .skillgrid/artifacts/04-adr-NNNN-slug.md` docstrings.
   - **Acceptance:** a script (part of the test suite) diffs the §2 file
     map against the tree and fails on missing `backend/app/` paths;
     `GET /api/v1/logs/query` → 501 `NOT_IMPLEMENTED` stable shape.
   - **Acceptance scenario:** `happy path stub-surface-matches-architecture` → `acceptance.feature`

10. **R10 — Test infrastructure:** `backend/tests/conftest.py` provides
    Testcontainers Postgres + Redis fixtures, an app fixture (isolated
    `create_app()`), a mock OIDC provider fixture, and a `kind`-cluster
    fixture (session-scoped, torn down per test file per ARCHITECTURE.md
    §9) used by R3/R4 integration tests.
    - **Current:** no test tree.
    - **Target:** fixtures exist and are consumed by R1–R4 tests; the
      whole backend suite runs in < 10 min locally.
    - **Acceptance:** `pytest backend/tests` green from a clean checkout
      with Docker available; `pytest backend/tests -m "not integration"`
      green without a kind cluster (unit tier isolated from the
      integration tier via a marker).
    - **Acceptance scenario:** `happy path test-fixtures-boot` → `acceptance.feature`

## Implementation Decisions

- **Modules to build/modify:** all new. `backend/app/` per ARCHITECTURE.md
  §2 (factory, extensions, core, api, models, services, tasks, sockets,
  schemas, migrations); `frontend/` (template scaffold + 3 views + lib);
  `cli/` (skeleton); `charts/kubedash/`; `backend/Dockerfile`;
  `.github/workflows/ci.yaml` + `e2e.yaml`; `backend/pyproject.toml` (uv).
  No legacy `src/*` paths touched.
- **Interfaces:**
  - `create_app() -> Flask` (factory; extensions injected so tests get
    isolated apps).
  - Smorest `Api` subclasses per domain, each registering its own
    `on_before_request` JWT hook; handlers read `flask.g.current_user`.
  - `services/k8s_client.py`: `get_client(cluster_id) -> K8sClientPool`
    member returning per-cluster cached `kubernetes` clients; this is the
    seam where the informer cache (ADR-0010) will later interpose.
  - `services/rbac.py`: `can(user, cluster, verb, resource, namespace,
    name) -> bool` (SAR-backed, 30 s cache).
  - Pydantic schemas in `app/schemas/` for every request/response
    (Flask-Smorest native; no marshmallow).
  - Error shape: `{ error: { code, message, details? } }`, codes stable
    strings via Flask-Smorest `HttpError` subclasses in
    `app/core/errors.py` (ARCHITECTURE.md §10).
  - Frontend: `lib/api.ts` `apiFetch(path, init) -> { data, error, meta }`
    with single-in-flight 401 refresh; TanStack Query owns all server state.
- **Data flow:** browser → `/api/v1/*` (Smorest: Pydantic validate → JWT
  hook → handler → `services/` → k8s client pool / SQLAlchemy) → JSON.
  Mutations (register cluster, bind) write to Postgres first, then call the
  cluster; the audit hook (stub, R9) is the single place later changes
  record `audit_log` rows. OIDC: `auth` Api ↔ `core/security.py` ↔ IdP;
  JWT HS256 `KUBEDASH_JWT_SECRET`, refresh tokens hashed in
  `refresh_tokens`.
- **Error handling:** cluster unreachable → 502 `CLUSTER_UNREACHABLE`;
  RBAC deny → 403 `RBAC_DENIED`; not found → 404 `CLUSTER_NOT_FOUND` /
  `RESOURCE_KIND_NOT_SUPPORTED`; unimplemented stub routes → 501
  `NOT_IMPLEMENTED`; validation → 422 with field details (Smorest default
  shaped to the error envelope). `/readyz` returns 503 listing failing
  dependencies.
- **Dependencies:** `uv` (Python deps), `pnpm` (node deps), Go modules
  (`cli/`). Python: `flask`, `flask-smorest`, `pydantic` ≥ 2, `sqlalchemy`
  2.0, `flask-migrate`, `flask-socketio`, `rq`, `redis`, `kubernetes`,
  `httpx`, `authlib` (OIDC), `pyjwt`, `gunicorn`, `pytest`,
  `testcontainers`. Node: the CoreUI template's dep set +
  `@tanstack/react-query`, `react-router-dom`, `zustand`, `socket.io-client`,
  `@fortawesome/fontawesome-free`, `monaco-editor`. Go: `cobra` only (the
  plugin's oauth2/keyring deps belong to the in-flight plugin change).
- **Migrations:** Flask-Migrate/Alembic from day one; the initial migration
  creates `users`, `refresh_tokens`, `clusters`, `cluster_bindings`,
  `leader_lease`. `rbac_templates`, `namespace_requests`,
  `access_requests`, `scim_mappings`, `provisioning_tasks`, `audit_log`
  come with their owning changes (R9 stubs do not create their tables —
  the model files for them are stubs too).

## Testing Decisions

- **What makes a good test:** external behavior only — HTTP responses,
  stored at-rest forms, rendered chart YAML, CLI stdout. No tests assert on
  private attributes; services are tested through their module functions
  with real (container-backed) Postgres/Redis.
- **Modules to test:** every `app/api/*` Api class through the Flask test
  client (≥ 90 % per ARCHITECTURE.md §9); `core/security.py` (JWT
  lifecycle), `services/k8s_client.py` + `services/rbac.py` against a `kind`
  cluster (integration marker); `cli` package via `go test`; chart via
  template assertions; frontend via Vitest + RTL + MSW for the three views.
- **Prior art:** none in-repo for this stack (greenfield); model the API
  test shape on Flask-Smorest's own test examples and the in-flight
  kubectl-oidc-plugin blueprint's mock-server pattern for OIDC.
- **Edge cases:** JWT expired mid-request → 401 (not 500); refresh token
  reuse after rotation → 401 + row deleted; cluster API server down → 502
  with a bounded timeout (no hanging request); duplicate cluster name →
  409 `CLUSTER_ALREADY_EXISTS`; kubeconfig that fails to parse at
  registration → 422 `INVALID_KUBECONFIG` (stored nothing); unbound user on
  a bound cluster → 403.

## Impact on Global Docs

- `.skillgrid/artifacts/00-prd.md`: create it (does not exist) — this is the
  first code change; the PRD records the 5.0 product statement, this
  tracer-skeleton scope as v0.1, and the success criteria above.
- `.skillgrid/ASSUMPTIONS.md`: move "in-flight blueprint targets proposed
  architecture" from INFERRED to VERIFIED (this change makes the target
  real); note the backfill of ADR-0001..0013 files remains open.
- `.skillgrid/ARCHITECTURE.md`: update §2 status from PROPOSED layout to
  "implemented for the spine; stubs as listed in
  `specs/2026-10-17-kubedash-base-structure`" and mark ADR-0010 (informer
  cache) as deferred from the base structure. No structural rewrites.

## Clarity Report

The full `interviewing` design-tree rounds were compressed into three
answer-select rounds with the user on 2026-10-17 (the design source is the
already-validated ARCHITECTURE.md + 20 in-force ADRs, so the interview
frontier was small).

| Dimension           | Score | Min  | Status | Notes                              |
|---------------------|-------|------|--------|------------------------------------|
| Goal Clarity        | 0.95  | 0.75 | pass   | "base structure" = tracer skeleton, user-confirmed |
| Boundary Clarity    | 0.90  | 0.70 | pass   | spine vs stubs boundary explicit in Out-of-scope + R9 |
| Constraint Clarity  | 0.90  | 0.65 | pass   | 20 ADRs + ARCHITECTURE.md §10 conventions in force |
| Acceptance Criteria | 0.85  | 0.70 | pass   | every requirement carries a concrete pass/fail check |
| **Clarity**         | 0.07  | ≤0.20| pass   | residual: Playwright smoke depth (see Open Questions) |

**Interview log:**

| Round | Question summary         | Decision locked                    |
|-------|-------------------------|------------------------------------|
| 1     | Which code world does the base structure target? | Proposed 5.0 stack (`backend/`, `frontend/`, `cli/`, `charts/`) on this branch; legacy `main` stack untouched |
| 2     | How deep should the structure go? | Tracer skeleton: spine (auth → clusters → one resource list → SPA) real + tested; subsystems stubbed with ADR references |
| 3     | Briefing vs blueprint sequencing | Briefing first, approval gate, then blueprint (standard skillgrid flow) |

## Open Questions & Assumptions

- **Assumption:** ADR-0010 (informer cache) is deferred past the base
  structure; the spine uses per-request API calls through the client pool.
  The pool is the seam the informer change interposes at. If the user wants
  the informer in the base structure, R4's implementation changes.
- **Assumption:** the `kind`-cluster integration tier runs in CI on Linux
  with Docker; developers without Docker can run the unit tier
  (`-m "not integration"`).
- **Question:** the Playwright "smoke" in R5/R8 — full login→pods journey
  against a mock OIDC provider + kind, or just bundle-serves-and-renders?
  The blueprint defaults to the full journey (it is the R5 acceptance
  criterion) and the smoke is gated in `e2e.yaml` only.

## Decisions (ADR)

No new ADRs clear the bar for this change — it implements, not decides.
In-force ADRs constraining it: ADR-0001, -0002, -0003, -0004, -0005,
-0006, -0007, -0008, -0009 (paths in `.skillgrid/ASSUMPTIONS.md` § LOCKED).
Note: ADR-0001..0013 files are not yet authored on disk (ASSUMPTIONS.md
onboarding notes) — the base structure is the first code change they will
constrain, and backfilling their files is a separate open task.

## Terms

- **Tracer skeleton / spine** — the thin end-to-end path
  (config → auth → cluster registry → one resource list → SPA) that is real
  and tested in this change; defined by requirements R1–R5. Not in the
  terms files (introduced by this spec).
- **Stub module** — a path from ARCHITECTURE.md §2 that exists, is
  importable, and carries an ADR pointer but implements no subsystem
  behavior (R9). Not in the terms files.
- **Cluster / Cluster binding / Role template / SubjectAccessReview** —
  see `.skillgrid/artifacts/02-technical-terms.md`.
