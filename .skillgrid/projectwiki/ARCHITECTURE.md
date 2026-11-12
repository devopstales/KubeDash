# ARCHITECTURE.md

**Project:** KubeDash
**Version:** 5.0 (rebase branch)
**Last Updated:** 2026-11-12

> This file describes the **live structure** of the codebase and is the source
> of truth for "how the system is built". It does **not** re-argue decisions —
> architectural decisions are recorded in
> `.skillgrid/projectwiki/ASSUMPTIONS.md` (§ LOCKED index → `decisions/04-adr-NNNN-slug.md`)
> and this file points at them.
>
> **Keep it factual and verifiable.** Every diagram, table row, and code snippet
> must correspond to something real in the repo (a package, a file:line, a
> config key).

## Table of Contents

1. Architecture Overview
2. Top-Level Layout
3. Application Layering
4. Entry Points & Command Surface
5. Domain / Core Logic
6. Data & Persistence
7. Storage & State
8. Cross-Cutting Transports (API / MCP / HTTP)
9. Frontend / UI
10. Plugin & Extension Architecture
11. Configuration & Feature Flags
12. Workflow / Pipeline
13. Enforcement & Quality Gates (tests, hooks, lint)
14. Error Handling & Degradation
15. Security
16. Testing Strategy
17. Known Gaps & TODOs

## 1. Architecture Overview

KubeDash is a multi-cluster Kubernetes dashboard: one web console for operators
to view and operate across many Kubernetes clusters, authenticated via OIDC,
with per-user RBAC delegated to the target cluster (SelfSubjectAccessReview),
query-only observability, and a kubectl credential plugin for automation.
It ships as **one container**: Gunicorn (Flask 3 + flask-smorest) serves the REST
API under `/api/v1/*`, the OpenAPI docs at `/api/docs`, and the built React SPA
on the static catch-all route. A leader-gated pgqueue worker thread (in the
Gunicorn master) enqueues interval tasks and every replica claims/claims-runs
them from the Postgres `tasks` table. PostgreSQL is the only stateful
dependency (pgEdge two-node active-active in dev); Redis was removed by
ADR-0029/0030.

```
        browser (React SPA, HttpOnly cookies kd_access/kd_refresh)
        kubectl + Go credential plugin (Bearer only, ADR-0011/0025)
              |
   +----------v-------------------------------------------------+
   | KubeDash container (Gunicorn — ADR-0006)                   |
   |  wsgi.py  (lazy app build, ProxyFix gate, bootstrap admin) |
   |  Smorest domain APIs   /api/v1/*, /api/docs                |
   |  Static SPA handler    /assets/*, /, /<path> (ADR-0040)    |
   |  Leader-gated pgqueue worker thread (scheduler+reaper)     |
   |  app/services: k8s_client pool, rbac.can (SAR), revocation |
   +----------+-----------------------------+------------------+
              |                             |
        +-----v------+                 +----v------------------+
        | PostgreSQL |                 | Kubernetes clusters   |
        | users,     |                 | (registry + local id 0)|
        | clusters,  |                 +----+------------------+
        | bindings,  |                            | SAR / list / get / mutate
        | tokens,    |
        | tasks,     |
        | leader_lease,
        | revoked_jtis
        +------------+
```

## 2. Top-Level Layout

| Path | Purpose |
|---|---|
| `backend/` | Flask 3 + Smorest app factory — `app/{core,api,models,services,tasks,sockets,aggregated,schemas}`, `migrations/` (Alembic), `tests/` (pytest), `wsgi.py` (Gunicorn + pgqueue worker), `Dockerfile` (3-stage), `kubedash.ini` + `kubedash.ini.example` (primary config, ADR-0028), `static/` (served SPA bundle) |
| `frontend/` | React 19 + TS + Vite on the CoreUI template — `src/views/` (one folder per route), `tests/` (Vitest + RTL + MSW), `e2e/` (Playwright), `STYLEGUIDE.md` (UI pieces), `openapi.json` (generated client contract) |
| `cli/` | Go kubectl credential plugin (cobra) — `cmd/{root,get_token,clean,setup,version}.go` |
| `charts/kubedash/` | Helm chart (N replicas, leader election) — the deployment artifact |
| `dev/` | docker-compose dev stack (pgEdge n1/n2, prometheus, pushgateway, grafana, jaeger, nginx, sso), kind config, TLS certs, demo-data scripts |
| `tests/` | `e2e/oidc-mock.py` (mock OIDC IdP), `fe-airgap-check.mjs` (ADR-0020 gate) |
| `scripts/` | ops scripts — Prometheus Pushgateway bridges (`collect-lint.py`, `collect-security.py`, `collect-quality.py`), prometheus-push e2e |
| `Taskfile.yaml` | task runner catalog — the command SoT (`task --list`) |
| `.github/workflows/` | `ci.yaml` (lint/typecheck/test/build/chart/trivy gates), `e2e.yaml` (kind + Helm + mock OIDC + Playwright), `openwiki-update.yml` |
| `.backlog/` | Backlog.md tracker (tasks, decisions, milestones) |
| `.skillgrid/` | Skillgrid — `projectwiki/` (knowledge vault: ASSUMPTIONS, ARCHITECTURE, ADRs, glossary), `change-specs/` (active specs), `meta/state.yaml` (dynamic state) |
| `openwiki/` | generated evidence index (gitignored; 2026-11-06 snapshot — stale on task-runner details, predates ADR-0029) |

## 3. Application Layering

```
backend (Flask app factory, app/__init__.py::create_app):

  wsgi.py          Gunicorn entrypoint: main() -> create_app() + pgqueue worker
     |
  app/api/         one Smorest Api per domain (≤ ~300 lines, Pydantic schemas)
     |              no cross-domain imports; _authhook.py app-scoped JWT gate
     v
  app/services/    pure Python, NO Flask imports — the integration boundary
     |              (k8s_client pool, rbac SAR, revocation, observability, scim, ...)
     v
  app/models/      SQLAlchemy 2.0 domain models (registered on db.Model)
  app/core/        infra: ini_config, config, errors, security, security_headers,
                   leader, pgqueue, kvstore, object_handoff, apidocs
  app/schemas/     Pydantic request/response schemas (Smorest serialization)
  app/tasks/       pgqueue task entrypoints (run() per task module)
  app/aggregated/  kube-aggregator API server (Project/SSOUser/SSOGroup)
  app/sockets/     Socket.IO namespaces (logs, events — stubs)

frontend (Vite build):
  src/views/<Route>/   one folder per route (CoreUI convention)
     -> src/components/, src/api (openapi.json client), TanStack Query (server state),
        Zustand (UI state)

cli (Go):
  main.go -> cmd.Execute()  (cobra tree: version | get-token | clean | setup)
```

**Dependency rules:** `app/api` may import `app/services`, `app/models`,
`app/core`, `app/schemas`. `app/services` must not import Flask (the pure-Python
integration boundary). No cross-domain imports inside `app/api`. Frontend views
must not bypass the API client for server state (TanStack Query owns it).
Enforced by review + mypy strict (`app/services` fully checked; the Smorest
seam modules carry documented `disable_error_code` overrides for the untyped
flask-smorest 0.47 surface).

## 4. Entry Points & Command Surface

- **Backend entry point:** `backend/wsgi.py` — Gunicorn loads `wsgi:wsgi`
  (module-level lazy WSGI callable; `app` is built once on first request via
  `_ensure_app()`, idempotent + thread-safe). `main()` builds the app and starts
  the leader-gated pgqueue worker thread (`_start_worker_if_leader`).
  `INTERVALS` (wsgi.py:67) schedules the due tasks: `app.tasks.health.run`
  every 60 s, `app.tasks.cluster_sync.run` every 300 s; the reaper sweeps stale
  claims / expired jtis / expired kv rows on a 30 s cadence
  (`REAP_INTERVAL_SECONDS`, wsgi.py:77).
- **CLI entry point:** `cli/main.go` → `cmd.Execute()`. Version injected at
  build via `go build -ldflags "-X <VERSIONSYM>=<version>"` (`task build`,
  override `task build VERSION=1.2.3`; `task cross` for 5 OS/arch targets).
- **Frontend:** `frontend/` builds to `dist/` (vite), synced to
  `backend/static/` (`task fe-sync`) and served by the backend static handler.

| Command / Operation | What it does |
|---|---|
| `kubedash version` | print the injected version |
| `kubedash get-token` | print an ExecCredential — **stub** (not implemented; exit 2 per kubectl exec-credential convention; the in-flight kubectl-oidc-plugin change plugs `pkg/oidc` here) |
| `kubedash clean` | kubectl cache-cleanup hook — **stub** (exit 2) |
| `kubedash setup` | interactive credential-plugin setup — **stub** (exit 2) |

## 5. Domain / Core Logic

| Module / Package | Responsibility |
|---|---|
| `app/api/clusters.py` + `app/services/cluster_allocation.py` | cluster registry: CRUD, encrypted kubeconfigs, the synthetic local cluster (id 0, admin-only, ADR-0021) |
| `app/api/resources.py` + `app/services/k8s_client.py` | K8s resource API — `K8sClientPool.get(cluster)` (per-cluster cached client, AES-256-GCM kubeconfig decryption), `bound_cluster_or_404` (missing binding == missing cluster), typed kind catalog (ADR-0041) |
| `app/services/rbac.py` | SAR gate — `rbac.can(user, cluster, verb, resource, namespace, name)` asks the target cluster via SelfSubjectAccessReview (ADR-0004); verdicts cached in the Postgres `kv` table (moved off Redis by ADR-0030) |
| `app/api/auth.py` + `app/core/security.py` + `app/services/revocation.py` | OIDC login/refresh/logout, JWT issuance, `revoked_jtis` deny-list (ADR-0030) |
| `app/core/leader.py` + `app/models/leader_lease.py` | leader election — PG advisory lock + `leader_lease` row with strict fencing token (ADR-0031) |
| `app/core/pgqueue.py` + `app/models/task.py` | Postgres queue — `SELECT ... FOR UPDATE SKIP LOCKED` claim + reaper (ADR-0029) |
| `app/tasks/` | task entrypoints: `health` (60 s), `cluster_sync` (300 s), plus leader-gated `alerts`, `access_expiry`, `rbac_drift`, `ns_request_expiry` |
| `app/services/{prometheus,loki,tempo,grafana}.py` | query-only observability clients (ADR-0003) |
| `app/aggregated/` + `app/api/aggregated/` | kube-aggregator server: Project + SSOUser + SSOGroup (ADR-0012) — **501 stubs** |
| `app/api/gateway_api.py` + `app/services/gateway_convert.py` | ingress-auth `/auth/verify` for NGINX/Traefik/Istio/Gateway API (ADR-0019) |
| `app/api/scim/` + `app/services/scim.py` | SCIM 2.0 gateway (IdP/HR push; identity decoupled from bindings, ADR-0018) — **501 stubs** |
| `app/core/object_handoff.py` | ADR-0040 object ref handoff (session-scoped, form-POST deep link) |

**Key invariants:** the read path is **direct K8s API calls** today —
`K8sClientPool` is the documented seam where ADR-0010's informer cache
interposes (deferred). Mutations always go through the API.

## 6. Data & Persistence

```
OIDC IdP --login--> users (JWT, kd_access/kd_refresh cookies)
                        |
cluster registry (encrypted kubeconfig, AES-256-GCM, KUBEDASH_SECRET_KEY)
      |
bindings (user <-> cluster) --gate--> bound_cluster_or_404
      |
SAR (SelfSubjectAccessReview per verb/resource/ns/name) --> 403 RBAC_DENIED
      |
K8sClientPool --> list / get / mutate
      |
tokens (self-service kubeconfig), revoked_jtis (deny-list), kv (SAR verdict cache)
      |
tasks (pgqueue claims), leader_lease (fenced election)
```

Primary models (`backend/app/models/`): `user`, `cluster`, `binding`, `group`,
`token`, `revocation` (revoked_jtis), `kv`, `leader_lease`, `task`, `audit`,
`access_request`, `namespace_request`, `rbac_template`, `kubectl_config`,
`scim_map`.

## 7. Storage & State

- **Primary store:** PostgreSQL (`kubedash` DB) — the only stateful dependency.
  Dev runs a pgEdge two-node **active-active** pair (Spock sync; n1 `:5432`,
  n2 `:16433`) with a strict fencing token on `leader_lease` (ADR-0031).
  Redis is gone (ADR-0029/0030 removed its last two consumers: the RQ queue and
  the revocation set; the SAR cache now lives in the `kv` table).
- **Migrations:** Alembic — `backend/migrations/` (10 revisions; the schema
  source of truth; never hand-edit the dev DB; `task dev-stack` applies the same
  head path prod uses).
- **State zones:** durable state = Postgres. Browser state = tab-private
  `sessionStorage` object refs (ADR-0040) + HttpOnly cookies. No file-based app
  state; `.skillgrid/` holds the dev workflow state, not runtime state.

## 8. Cross-Cutting Transports (API / MCP / HTTP)

| Transport | Port / Protocol | Shares handlers with |
|---|---|---|
| REST API (Smorest, OpenAPI at `/api/docs`) | `:8080` dev (plain HTTP, ADR-0027) / `:8443` TLS backend / `:443` nginx edge | one app: `create_app` registers all domain APIs |
| Static SPA | same port, catch-all route (`/assets/*`, `/`, `/<path>`) | same app (`register_static`) |
| kubectl credential plugin endpoints (`/api/v1/kubectl/*`, `GET /kubeconfig`) | same port, Bearer-only (ADR-0025) | same app |
| Ingress-auth verification (`/auth/verify`, ADR-0019) | same port, called by NGINX/Traefik/Istio/Gateway API | same app |
| Aggregated API (kube-aggregator: Project/SSOUser/SSOGroup) | same app, **501 stubs** | same app |
| Socket.IO namespaces (`/logs`, `/events`) | same port — **stubs** pending the observability/exec changes (ADR-0009 reserves WS for bidirectional exec) | `app/sockets/` |

No MCP server surface in the product (MCP exists only in the dev tooling).

## 9. Frontend / UI

- **Stack:** React 19.3 + TypeScript 5.8 + Vite 7 on the CoreUI free admin
  template (vendored SCSS — **no Tailwind**; UI pieces follow
  `frontend/STYLEGUIDE.md`); TanStack Query 5 (server state), Zustand 5 (UI
  state), react-router-dom 7, DataTables React (Bootstrap 5 skin, ADR-0023),
  monaco-editor (YAML), react-syntax-highlighter (secrets, ADR-0024).
- **Routing:** one folder per route in `src/views/` (16 views: Clusters,
  Cluster, ClusterStatus, ClusterPermission, Storage, Security, Network,
  OtherResource, Permissions, AdminPermissions, Groups, Users, Kubeconfig,
  Profile, Login, Stub). Object navigation: no object identity in the URL —
  tab-private `sessionStorage` object ref + same-origin form-POST deep link
  (ADR-0040); one route per kind, no `/data` suffix (ADR-0041).
- **Dev vs prod:** dev = `task fe-dev` (vite dev server, API proxied to
  `:8080` — never bare `pnpm dev`); prod = `task fe-build` (tsc + eslint +
  vite → `frontend/dist/`) → `task fe-sync` (copy to `backend/static/`) →
  served by Gunicorn in the container. **Air-gap:** `task fe-check`
  (`tests/fe-airgap-check.mjs`) fails on any `https?://` / `//cdn.` reference in
  the built bundle (ADR-0020).
- **Client contract:** `frontend/openapi.json` — generated from the backend
  OpenAPI spec (openapi-typescript).

## 10. Plugin & Extension Architecture

No in-app plugin system. Extension points are protocol-level:

- **kubectl credential plugin** (ADR-0011): server-managed SSO config — the Go
  CLI (`cli/`) is the client half; `GET /kubeconfig` emits the `--server`
  wiring; `get-token` plugs in the ExecCredential flow (in-flight).
- **kube-aggregator** (ADR-0012): KubeDash registers as an APIService for
  Project/SSOUser/SSOGroup.
- **Ingress auth** (ADR-0019): `/auth/verify` for NGINX/Traefik/Istio/Gateway
  API external auth.
- **SCIM 2.0** (ADR-0018): IdP/HR push endpoints for identity sync.

## 11. Configuration & Feature Flags

- **Precedence:** `backend/kubedash.ini` (primary source) → `KUBEDASH_*` env
  override → fail-fast at boot (`ConfigError` on missing identity/credential
  keys; no hard-coded defaults — ADR-0028). `create_app` is pure; config
  resolves in `app/core/ini_config.py` + `app/core/config.py`.
- **Main config:** `backend/kubedash.ini` (dev values; gitignored — seeded from
  `kubedash.ini.example`). Sections: `[security]` (`jwt_secret`,
  `secret_key`, `admin_password`), `[database]`, `[sso_settings]`
  (`issuer_url`, `client_id`, `bootstrap_users`), `[monitoring]` (jaeger OTLP),
  `[deployment]` (`admin_kubeconfig`, `kubedash_role`, `kubedash_replica_id`,
  `cookie_secure`, `tls_edge`, `ssl_cert/key`, `plugin_server`, timeouts),
  `[bootstrap]` (`bootstrap_admin_email`), `[ha]` (`node_dsn_overrides`).
- **Feature flags:** none as a separate system — config keys carry the toggles
  (`jaeger_enabled`, `tls_edge`, `cookie_secure`, `kubedash_role`).

## 12. Workflow / Pipeline

Dev-workflow pipeline (Skillgrid SDD — see AGENTS.md `### Workflow`):
`brainstorming → writing-blueprints → slicing → ticketing → execution → qa →
code-review → receiving-code-review → ship → reflect`; specs in
`.skillgrid/change-specs/<YYYY-MM-DD-topic>/`, closed changes in
`.skillgrid/change-archive/`, tickets in `.backlog/` (Backlog.md).

CI pipeline (`.github/workflows/ci.yaml`):

```
pushgateway (ephemeral :9091)
   |
   +-- backend:  uv sync -> ruff check + mypy app -> pytest -m "not integration"
   +-- frontend: pnpm install --frozen-lockfile -> tsc --noEmit + eslint + vite build -> air-gap check
   +-- cli:      go vet + go test
   +-- chart:    helm lint + helm template -> pytest tests/test_chart.py
   +-- image:    docker build (backend/Dockerfile) -> Trivy CRITICAL (exit-code 1)
   +-- lint-workflows: actionlint
```

E2E (`.github/workflows/e2e.yaml`, main): kind + Helm install + mock OIDC
(`tests/e2e/oidc-mock.py`) + Playwright smoke.

## 13. Enforcement & Quality Gates (tests, hooks, lint)

| Gate | Enforced by | Fails on |
|---|---|---|
| backend lint + typecheck | `ci.yaml` (ruff check + `mypy app` strict) | any ruff finding / mypy error |
| backend unit tests | `ci.yaml` (`pytest -m "not integration"`) | any failure |
| frontend typecheck + lint + build | `ci.yaml` (tsc --noEmit + eslint + vite build) | any failure |
| air-gap | `ci.yaml` + `task fe-check` (`tests/fe-airgap-check.mjs`) | any external URL/CDN ref in the bundle |
| CLI | `ci.yaml` (go vet + go test) | any failure |
| chart | `ci.yaml` (helm lint + helm template + `tests/test_chart.py`) | any failure |
| image CVEs | `ci.yaml` (Trivy `severity: CRITICAL, exit-code: 1`) | any CRITICAL vuln |
| workflow YAML | `ci.yaml` (actionlint) | any finding |
| git hooks | machine-level `pre-commit` + `commit-msg` (dotfiles template); skillgrid work-unit commit shims per `checkpoint.enabled` | conventional-commit format, cwd-drift/protected-ref guards |

Local dev loops: `task dev-stack` (compose + schema + backend, plain HTTP
:8080), `task e2e` / `task e2e-ssl`, `task multi-up` + `task failover`
(leader failover ~10 s), `task test-security` (Trivy, advisory),
`task test-dast` (Wapiti, needs the stack).

## 14. Error Handling & Degradation

- **Error convention:** stable code envelope from `app/core/errors.py` — every
  API response (success, 404, 403, 5xx) carries a machine-readable error code;
  the exception repr never leaks. Domain errors: `CLUSTER_NOT_FOUND` (missing
  cluster **or** missing binding — same 404), `RBAC_DENIED` (403),
  `NOT_IMPLEMENTED` (501 stubs), `ConfigError` (boot).
- **Degradation floors:** config fails **closed** at boot (missing
  identity/credential keys raise; no fallback defaults — ADR-0028). SAR verdict
  cache miss → direct SAR to the cluster (fail-closed authorization). No
  informer cache today — reads are direct K8s API calls (ADR-0010 deferred).
  pgqueue reaper re-queues stale claims (120 s stale window) and expires
  jtis/kv rows; leader failover re-elects on the next poll (~10 s, fenced by
  the `leader_lease` token — ADR-0031). Static SPA + API share one process — a
  dead backend means the SPA is unreachable too (single-container tradeoff,
  ADR-0006).

## 15. Security

```
OIDC IdP (sole external authN)
   |  code -> JWT -> HttpOnly cookies kd_access / kd_refresh (Secure per edge, ADR-0025/0027)
   v
KubeDash API
   |  1. JWT verify (app-scoped before_request, /api/v1/*; Bearer only for kubectl/*)
   |  2. binding check (bound_cluster_or_404)
   |  3. SAR gate (rbac.can -> SelfSubjectAccessReview, verdict cached in kv)
   |  4. K8sClientPool (kubeconfig decrypted AES-256-GCM, KUBEDASH_SECRET_KEY)
   v
target cluster (RBAC answered by the cluster itself — ADR-0004)
```

| Control | Where | Notes |
|---|---|---|
| OIDC authN + session revocation | `app/api/auth.py`, `app/services/revocation.py` | `revoked_jtis` deny-list on Postgres (ADR-0030); logout propagates to kubectl sessions |
| HttpOnly session cookies | `app/core/security.py` | no credentials in URLs/localStorage (ADR-0025) |
| Kubeconfig encryption | `KUBEDASH_SECRET_KEY`, AES-256-GCM | one-way door; distinct from the HS256 JWT key |
| Security-header layer | `app/core/security_headers.py` | CSP (per-request nonce), HSTS, XFO, XCTO, RP, COOP/COEP (ADR-0026/0027) |
| Air-gap | `task fe-check`, `backend/app/core/apidocs.py` | zero outbound calls at runtime; Swagger UI vendored (ADR-0020) |
| TLS edge (opt-in dev) | `task dev-stack-ssl`, nginx in `dev/` | Plain-HTTP is the dev default (ADR-0027); ProxyFix gated on the edge (ADR-0026) |
| Image CVE scan | `ci.yaml` (Trivy CRITICAL, exit 1) | local `task test-security` is advisory |
| Secret scan | gitleaks (`.gitleaks-report.json`, gitignored) | advisory locally |
| One-way doors | AGENTS.md § Security | cluster registry schema + `KUBEDASH_SECRET_KEY` — ADR-gated + migration-gated |

## 16. Testing Strategy

- **Runner:** `uv run pytest -m "not integration"` (backend unit floor) ·
  `corepack pnpm test` in `frontend/` (Vitest) · `go test ./...` in `cli/` ·
  `task e2e` / `task e2e-ssl` (Playwright) · `uv run pytest tests/test_chart.py`
  (chart).
- **Layers:** unit — `backend/tests/` (app factory, config, auth, rbac, pgqueue,
  leader), `frontend/tests/` (RTL + MSW), `cli/cmd/*_test.go`. Integration —
  `pytest -m integration` (kind-gated + Testcontainers Postgres; `task kind-up`).
  E2E — `frontend/e2e/` (auth-smoke + ui-smoke against the live stack; mock
  OIDC via `tests/e2e/oidc-mock.py` for CI).
- **Coverage:** test-result metrics (pass/fail/total/duration) pushed to the
  Prometheus Pushgateway in dev + CI (`pytest-prometheus-pushgateway`); **no
  local coverage threshold or mutation gate** (config `quality.coverage_min: 0`,
  `mutation_min: 0`).

## 17. Known Gaps & TODOs

- **16 API modules are 501 stubs** (base-structure surface, staged for later
  milestones): `logs`, `metrics`, `traces`, `audit`, `permissions`,
  `namespaces`, `access`, `kubeconfig`, `admin`, `kubectl_auth`, `groups`,
  `aggregated/{projects,sso_users,sso_groups}`, `scim/{users,groups}` — the
  decisions (ADR-0003/0012/0013/0018) are in force; the endpoints are not.
- **kubectl credential plugin is a stub** — `get-token`/`clean`/`setup` exit 2;
  the in-flight kubectl-oidc-plugin change plugs `pkg/oidc` in
  (`cli/cmd/get_token.go`). Its spec zone was lost in the 2026-11-12
  `.skillgrid/` wipe — re-baseline before resuming (see
  `ASSUMPTIONS.md` § Open Questions).
- **Socket.IO `logs`/`events` namespaces are stubs**; no SSE endpoint is served
  yet — the SPA refreshes via TanStack Query on demand (ADR-0009 target
  unmet).
- **Read path is direct K8s API calls** — the ADR-0010 informer cache is
  deferred; `K8sClientPool` is the documented interposition seam.
- **`openwiki/` evidence index is stale** on task-runner details (predates
  ADR-0029 — still says RQ/Redis).
- **Taskfile descriptions lag the code** in two places (`backend-run` /
  `multi-up` still say "RQ worker" — the worker is pgqueue since ADR-0029).
