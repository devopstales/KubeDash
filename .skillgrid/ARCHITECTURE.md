# KubeDash — Live Architecture

> **Status:** PROPOSED
> **Date:** 2026-10-17
> **Scope:** Multi-cluster Kubernetes dashboard with observability integration.
> **Stack:** Python 3.12 + Flask (Gunicorn) backend · React 18 + TypeScript + Vite frontend (CoreUI UI).

This file is the **live** description of KubeDash's program structure. It is updated
as the codebase changes. It is *not* a blueprint, *not* a spec, and *not* a decision
record. Load-bearing decisions live in `.skillgrid/knowledge/decisions/04-adr-*.md`; the
glossary lives in `.skillgrid/knowledge/glossary/01-business-terms.md` and
`02-technical-terms.md`; the ADR index lives in `.skillgrid/ASSUMPTIONS.md`.

---

## 1. System Overview

KubeDash is an open-source, enterprise-grade web dashboard for managing one or
many Kubernetes clusters, with first-class observability (logs, metrics,
traces).

```
                        ┌────────────────────────────────┐
                        │        OIDC Identity           │
                        │   (Keycloak / Okta / Azure)    │
                        └───────────────▲────────────────┘
                                        │ OIDC + JWT
┌──────────────────────────────────────────────────────────────┐
│                    KubeDash (single container)               │
│                                                              │
│  ┌────────────────────┐        ┌──────────────────────────┐  │
│  │  Gunicorn (WSGI)   │        │  RQ Worker (in-process)  │  │
│  │  Flask + Smorest   │        │  gated by KUBEDASH_ROLE  │  │
│  │  serves:           │        │  =leader (one replica)   │  │
│  │  • /api/v1/*       │        │  • cluster_sync          │  │
│  │  • /ws/* (SocketIO)│        │  • health_probe          │  │
│  │  • /static/* (SPA) │        │  • alerts.evaluate       │  │
│  └─────────┬──────────┘        └────────────┬─────────────┘  │
│            │                                │                │
│            ▼                                ▼                │
│  ┌─────────────────┐              ┌─────────────────┐        │
│  │  PostgreSQL     │              │  Redis          │        │
│  │  (SQLAlchemy)   │              │  (cache + RQ    │        │
│  └─────────────────┘              │   broker)       │        │
│                                   └─────────────────┘        │
└──────────────────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────┐    ┌──────────────────────────┐
│  Kubernetes API      │    │  Observability backends  │
│  (N clusters)        │    │  Prometheus · Loki ·     │
└──────────────────────┘    │  Tempo · Grafana         │
                            └──────────────────────────┘
```

**One deployable:** `kubedash` — a single container that runs:

1. **Gunicorn** (WSGI) — the Flask + Flask-Smorest API **and** the static
   file server for the built React SPA. No separate frontend container.
   The SPA is built at image-build time (multi-stage Dockerfile) and
   mounted read-only at `/app/static`.
2. **RQ worker** — in-process async task handling (Redis Queue),
   **enabled only on the leader replica** (gated by `KUBEDASH_ROLE=leader`).
   Followers skip the worker to avoid duplicate background jobs.

**External dependencies:** PostgreSQL (metadata, audit, users) and Redis
(cache, rate-limit counters, RQ broker). Both are separate StatefulSets /
managed services — they are *not* bundled in the KubeDash container.

**Replicas + leader election:** the Helm chart deploys N replicas of the
`kubedash` Deployment. A leader election module (PostgreSQL advisory lock
+ a `leader_lease` table with heartbeat) elects exactly one replica as
**leader**; only the leader runs the RQ worker + periodic tasks. All
replicas serve HTTP + WebSocket identically. If the leader dies, a follower
acquires the lease within the heartbeat interval (default 10 s). The
election is re-checked on every request via a lightweight in-memory
flag refreshed by a background thread.

---

## 2. Repository Layout

```
KubeDash/
├── .skillgrid/
│   ├── ARCHITECTURE.md          ← this file
│   ├── ASSUMPTIONS.md           ← VERIFIED / INFERRED / LOCKED (ADR index)
│   ├── WINDOWS.md               ← cross-change defect register (open warnings/suggestions)
│   ├── config.yaml
│   ├── state.yaml
│   ├── knowledge/               ← knowledge base (OKF v0.2 bundle)
│   │   ├── index.md / log.md / reverse-index.md  ← catalog, journal, path→concept map
│   │   ├── decisions/           ← ADRs: 04-adr-NNNN-slug.md, one locked decision per file
│   │   ├── glossary/            ← 01-business-terms.md, 02-technical-terms.md
│   │   ├── invariants/          ← must-hold contracts (claims + anchors)
│   │   ├── workflows/           ← thin cross-package business flows
│   │   └── reference/           ← PRDs, research, roadmaps
│   ├── specs/                   ← per-change folders (briefing, blueprint, tasks, adr)
│   ├── sdd/                     ← per-change SDD execution folders (progress.md, review diffs)
│   ├── prototypes/              ← retained feasibility probes
│   └── archive/                 ← shipped per-change folders (YYYY-MM-DD-slug)
├── backend/
│   ├── app/
│   │   ├── __init__.py          ← create_app factory
│   │   ├── extensions.py        ← Smorest, SQLAlchemy, JWT, SocketIO, RQ, limiter, migrate
│   │   ├── core/
│   │   │   ├── config.py        ← env-driven settings (dev/stage/prod)
│   │   │   ├── security.py      ← OIDC, JWT issue/verify, RBAC proxy
│   │   │   ├── leader.py        ← leader election (PG advisory lock + lease)
│   │   │   └── errors.py        ← Smorest HttpError subclasses + handlers
│   │   ├── api/                 ← one Api (flask_smorest) per domain
│   │   │   ├── auth.py
│   │   │   ├── clusters.py
│   │   │   ├── resources.py
│   │   │   ├── logs.py
│   │   │   ├── metrics.py
│   │   │   ├── traces.py
│   │   │   ├── audit.py
│   │   │   ├── permissions.py   ← /admin/permissions/* (bind, unbind, templates)
│   │   │   ├── namespaces.py    ← /namespaces/* (NaaS request/approve, § 5C)
│   │   │   ├── access.py        ← /access/* (PAM elevation requests, § 5D)
│   │   │   ├── scim/            ← /scim/v2/* (SCIM 2.0 gateway, § 5F)
│   │   │   │   ├── users.py
│   │   │   │   └── groups.py
│   │   │   ├── kubectl_auth.py  ← /kubectl/auth/v1/config (plugin bootstrap)
│   │   │   ├── kubeconfig.py    ← /kubeconfig (self-service download)
│   │   │   ├── admin.py
│   │   │   └── aggregated/      ← K8s aggregated API server (port 8443)
│   │   │       ├── __init__.py  ← second Flask app, mTLS, read-only
│   │   │       ├── projects.py  ← GET /apis/projects.kubedash.io/v1/projects
│   │   │       ├── sso_users.py ← GET /apis/auth.kubedash.io/v1/sso-users
│   │   │       └── sso_groups.py← GET /apis/auth.kubedash.io/v1/sso-groups
│   │   ├── models/              ← SQLAlchemy 2.0 models
│   │   │   ├── user.py
│   │   │   ├── cluster.py
│   │   │   ├── audit.py
│   │   │   ├── token.py
│   │   │   ├── leader_lease.py
│   │   │   ├── rbac_template.py ← role templates (Postgres, not ClusterRoles)
│   │   │   ├── binding.py       ← user × cluster × namespace × template
│   │   │   ├── namespace_request.py  ← NaaS onboarding requests (§ 5C)
│   │   │   ├── access_request.py ← PAM elevation requests (§ 5D)
│   │   │   └── scim_map.py      ← SCIM externalId ↔ KubeDash id mapping (§ 5F)
│   │   ├── services/            ← plain Python, no Flask imports
│   │   │   ├── k8s_client.py    ← per-cluster kubernetes client pool
│   │   │   ├── rbac.py          ← SubjectAccessReview proxy + effective perms
│   │   │   ├── permission.py    ← bind/unbind, template apply, kubeconfig gen
│   │   │   ├── namespace.py     ← NaaS provisioning pipeline (§ 5C)
│   │   │   ├── access.py        ← PAM elevation lifecycle, auto-expiry (§ 5D)
│   │   │   ├── provisioning.py  ← JIT login provisioning task engine (§ 5E)
│   │   │   ├── scim.py          ← SCIM 2.0 resource CRUD + filtering (§ 5F)
│   │   │   ├── prometheus.py
│   │   │   ├── loki.py
│   │   │   ├── tempo.py
│   │   │   └── grafana.py
│   │   ├── tasks/               ← RQ tasks (run on leader only)
│   │   │   ├── cluster_sync.py
│   │   │   ├── health.py
│   │   │   ├── alerts.py
│   │   │   ├── rbac_drift.py    ← RBAC drift detection (10 min)
│   │   │   ├── access_expiry.py ← PAM auto-revoke at TTL (§ 5D)
│   │   │   └── ns_request_expiry.py ← NaaS TTL'd grants auto-revoke (§ 5C)
│   │   ├── sockets/             ← Flask-SocketIO namespaces
│   │   │   ├── logs.py
│   │   │   └── events.py
│   │   ├── aggregated/          ← aggregated API service layer
│   │   │   ├── project.py       ← Namespace → Project projection + RBAC filter
│   │   │   ├── sso_user.py      ← SSOUser computation (RBAC walk)
│   │   │   └── sso_group.py     ← SSOGroup computation (RBAC walk)
│   │   ├── schemas/             ← Pydantic request+response (flask_smorest)
│   │   │   └── kubectl_auth.py  ← AuthConfig model (plugin↔server contract)
│   ├── migrations/              ← Flask-Migrate / Alembic
│   ├── static/                  ← built SPA (copied here at image-build time)
│   ├── tests/
│   │   ├── conftest.py          ← Testcontainers, app fixture, cluster fixture
│   │   ├── api/
│   │   ├── services/
│   │   └── tasks/
│   ├── wsgi.py                  ← Gunicorn entrypoint (Flask + RQ worker)
│   ├── pyproject.toml           ← uv-managed deps
│   └── Dockerfile               ← multi-stage: build SPA → runtime
├── frontend/                    ← scaffolded from coreui-free-react-admin-template
│   ├── public/
│   │   ├── favicon.ico
│   │   └── manifest.json
│   ├── src/
│   │   ├── assets/              ← images, icons (from template)
│   │   ├── components/          ← Header, Sidebar, Footer, common widgets
│   │   │   ├── Header.jsx       ← from template, extended with cluster switcher
│   │   │   ├── Sidebar.jsx      ← from template, nav driven by _nav
│   │   │   ├── Footer.jsx       ← from template
│   │   │   └── ...              ← KubeDash-specific widgets (PodTable, LogTail, etc.)
│   │   ├── layouts/             ← layout containers (from template)
│   │   ├── scss/                ← CoreUI SCSS theme overrides
│   │   ├── views/               ← application views (one folder per route)
│   │   │   ├── Login/
│   │   │   ├── Clusters/
│   │   │   ├── Cluster/         ← /clusters/:id dashboard
│   │   │   ├── Resources/       ← /clusters/:id/<kind> generic list + YAML
│   │   │   ├── Logs/
│   │   │   ├── Metrics/
│   │   │   ├── Traces/
│   │   │   └── Permissions/     ← /permissions + /admin/permissions
│   │   ├── _nav.tsx             ← sidebar navigation config (from template)
│   │   ├── routes.tsx           ← route config (from template, extended)
│   │   ├── store/               ← Zustand stores (selectedCluster, theme)
│   │   ├── hooks/               ← useCluster, useResources, useWebSocket
│   │   ├── lib/                 ← api client, socket client, types, utils
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── tests/                   ← Vitest + RTL
│   ├── e2e/                     ← Playwright
│   ├── index.html
│   ├── package.json
│   ├── vite.config.mjs
│   ├── tsconfig.json
│   └── eslint.config.mjs
├── cli/                         ← Go kubectl credential plugin
│   ├── main.go                  ← cobra root, subcommands
│   ├── go.mod                   ← module: github.com/org/kubedash-cli
│   ├── cmd/
│   │   ├── get_token.go         ← "kubedash get-token"
│   │   ├── clean.go             ← "kubedash clean"
│   │   ├── setup.go             ← "kubedash setup" (debug: dump claims)
│   │   └── version.go           ← "kubedash version"
│   ├── pkg/
│   │   ├── config/              ← FetchAuthConfig, AuthConfig types
│   │   ├── oidc/                ← PKCE flow, refresh, code_verifier
│   │   ├── cache/               ← keyring + file fallback
│   │   ├── output/              ← ExecCredential JSON marshal
│   │   └── httpclient/          ← TLS-configured HTTP client
│   ├── internal/testutil/       ← in-process mock OIDC provider
│   ├── testdata/                ← sample kubeconfig for integration tests
│   ├── Taskfile.yaml            ← go-task: build + cross (5 combos)
│   └── .krew.yaml               ← Krew manifest
├── charts/kubedash/             ← Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
├── tests/
│   ├── e2e/oidc-mock.py         ← CI mock IdP (port 9096)
│   └── fe-airgap-check.mjs      ← ADR-0020 no-CDN walker
├── docs/                        ← MkDocs Material
├── .github/workflows/
│   ├── ci.yaml                  ← lint + typecheck + test + build
│   ├── cli-release.yaml         ← tag cli/v* → cross-compile → GitHub Release
│   ├── release.yaml             ← tag → image → GHCR → Helm package
│   └── e2e.yaml                 ← kind cluster + full UI flow
└── README.md
```

---

## 3. Backend (Flask + Gunicorn)

### 3.1 App factory + Smorest

Every module is imported through `create_app()` in `app/__init__.py`.
Extensions are initialised in `app/extensions.py` and injected into the
factory, so tests can construct isolated apps with different configs.

The `flask_smorest.Api` instance is created **inside** the factory (not as a
module global) so each test app gets its own spec. Domain `Api` subclasses
(`auth`, `clusters`, `resources`, …) are registered on it via
`api.register(ClusterApi())` etc. The OpenAPI spec is rebuilt on every
`create_app()` call, so adding/removing an `Api` is reflected in
`/api/openapi.json` immediately.

**Static file serving:** Flask serves the built SPA from `backend/static/`
via a catch-all route (`/<path:p>` → `send_from_directory`) registered
*after* all API routes, so `/api/v1/*` and `/ws/*` take precedence. The
`index.html` is returned for any non-API, non-asset path (SPA fallback),
enabling client-side routing without server-side route definitions.

### 3.2 REST API (Flask-Smorest)

All REST endpoints are built on **Flask-Smorest** (`flask_smorest.Api`).
Each domain is a `flask_smorest.Api` subclass registered on the Flask app.
Schemas are **Pydantic** models (Flask-Smorest supports Pydantic natively;
we do *not* use marshmallow). Every endpoint declares `arguments` and
`response` schemas, which Flask-Smorest uses for:

- **Request validation** — Pydantic parses + validates the body/query/params
  before the handler runs. Invalid input → `422` with field-level errors.
- **Response validation** — the handler's return value is validated against
  the declared response schema before serialization.
- **OpenAPI 3.0 auto-generation** — served at `/api/docs` (Swagger UI) and
  `/api/openapi.json` (machine-readable spec, used for TS codegen in the
  frontend).

Each `api/<domain>.py` is ≤ ~300 lines, declares its own Pydantic schemas in
`schemas/`, and does **not** import from sibling domains — they share
services in `services/`.

**Auth on Smorest endpoints:** a shared `on_before_request` hook on each
`Api` verifies the JWT, loads the `users` row, and stashes it in
`flask.g.current_user`. Handlers access it via `flask.g`. Per-cluster RBAC
is enforced inside the handler via `services.rbac.can(...)` (see § 3.5).

| Api (Smorest) | Responsibility                                  | Key endpoints                                    |
|---------------|-------------------------------------------------|--------------------------------------------------|
| `auth`        | OIDC login/callback, JWT issue/refresh/revoke   | `/auth/login`, `/auth/callback`, `/auth/me`       |
| `clusters`    | Cluster registry CRUD, health, RBAC check       | `/clusters`, `/clusters/<id>/health`             |
| `resources`   | Generic K8s CRUD + YAML apply + dry-run         | `/clusters/<id>/resources/<kind>`                |
| `logs`        | Loki / OpenSearch log query (WS is separate)    | `/logs/query`                                    |
| `metrics`     | Prometheus query + range + recording rules      | `/metrics/query`, `/metrics/query_range`         |
| `traces`      | Tempo / Jaeger trace search + detail            | `/traces`, `/traces/<id>`                        |
| `audit`       | Read audit log, export                          | `/audit`, `/audit/export`                        |
| `admin`       | Users, roles, cluster bindings, settings        | `/admin/users`, `/admin/clusters`                |

**Note:** WebSocket endpoints (`/ws/logs`, `/ws/events`) are **not** Smorest
routes — they are registered on Flask-SocketIO directly (see § 3.6). Smorest
handles all synchronous HTTP/JSON only.

### 3.2.1 Example endpoint shape

```python
# app/api/clusters.py
from flask_smorest import Api, fields
from pydantic import BaseModel
from app.schemas.cluster import ClusterOut, ClusterCreate

class ClusterApi(Api):
    resources_namespace = "clusters"
    tags = ["Clusters"]

    def on_init(self, app):
        # shared JWT verify hook
        self.on_before_request(self._verify_jwt, blueprint=False)

    @blp.route("/clusters", methods=["GET"])
    @blp.arguments(None)
    @blp.response(CustomHttpError.HTTP_403, "RBAC_DENIED")
    @blp.response(CustomHttpError.HTTP_404, "CLUSTER_NOT_FOUND")
    @blp.response(CustomHttpError.HTTP_502, "CLUSTER_UNREACHABLE")
    @blp.response(HTTPStatus.OK, ClusterOut)
    def list_clusters(self):
        ...
```

### 3.3 Services (no Flask)

`services/` contains **pure Python** modules with no Flask imports. They are
the integration boundary:

- **`k8s_client.py`** — maintains a pool of `kubernetes` client instances,
  one per registered cluster. Caches `CoreV1Api`, `AppsV1Api`, etc. Handles
  kubeconfig + service-account token auth.
  - **Informer-based cache** (the key scalability pattern, borrowed from
    Radar): each registered cluster runs a long-lived watch per resource
    kind (Pods, Deployments, Services, Events, CRDs, …), cached in an
    in-memory dict keyed by `(cluster, kind, namespace, name)`. The UI and
    all read-path services read from this cache, **not** from per-request
    API calls. Mutations go through the API and the cache is updated on the
    watch event. Reconnect + backoff on watch disconnect.
  - **Namespace scoping**: `cluster.namespace_scope: true` pins the cache
    to a single namespace (for 10k+ namespace clusters).
  - **First-paint backstop**: if the initial cache sync exceeds
    `KUBEDASH_FIRST_PAINT_BACKSTOP` (default 5 m), the UI renders partial
    data with a "syncing…" indicator rather than hanging.
- **`rbac.py`** — `SubjectAccessReview` proxy. Every mutating request runs
  through `rbac.can(user, verb, resource, name, namespace)` before the call.
  Result is cached per (user, cluster, verb, resource) for 30 s.
  - **RBAC visibility** (read-only): `rbac.effective_permissions(sa)`
    returns the deduplicated, group-expanded permission set for a
    ServiceAccount, with blast-radius flags (wildcards, cluster-admin,
    cluster-wide `create pods`). `rbac.my_permissions(user)` wraps
    `SelfSubjectRulesReview` for the "My Permissions" panel.
- **`prometheus.py` / `loki.py` / `tempo.py` / `grafana.py`** — thin
  `httpx` clients with per-backend timeouts, retries, and a shared
  `observability` config (base URL, auth, tenant).
- **`topology.py`** — builds the resource-relationship graph (Service →
  Deployment → Pod, Ingress → Service, PVC → Pod) from the informer cache.
  Pure function; no extra API calls.
- **`timeline.py`** — watches K8s `Event` objects + diffs resource changes
  (informer compare). Stores in `audit_log` (Postgres) with a 24 h ring
  buffer in Redis.
- **`helm.py`** — shells out to `helm` (bundled in the image) for release
  list / get / upgrade / rollback / uninstall. Write ops gated by RBAC +
  `features.helmWrite`.
- **`gitops.py`** — reads ArgoCD + FluxCD CRDs via the dynamic client.
  Drift detection, diagnosis pipeline, lifecycle awareness.
- **`audit.py`** — 44+ best-practices checks as pure functions over the
  informer cache. Runs as RQ task (leader, 5 min) + on-demand.
- **`tls.py`** — parses TLS secrets, computes expiry. RQ task (leader,
  daily) + on-demand.
- **`cost.py`** — PromQL queries for OpenCost / Kubecost metrics.
  Auto-detects the metric family.
- **`network_path.py`** — hop-ordered reachability diagnosis over the
  informer cache + optional live probe (DNS/TCP/TLS/HTTP).
- **`mcp/`** — MCP tool definitions + handlers. Reuses the same
  `services/` layer. Read-only by default; writes require client
  confirmation + RBAC.
- **`kubectl_auth.py`** — resolves SSO config per cluster (issuer,
  client_id, token_url, auth_url, scopes, expiry) for the kubectl
  credential plugin. Reads from the `clusters` table (`oidc_config`
  JSONB column) or the Helm ConfigMap. Unauthenticated endpoint
  (bootstrapping auth); TLS + rate-limited.

### 3.4 Data model (PostgreSQL via SQLAlchemy 2.0)

Core tables:

| Table         | Purpose                                            |
|---------------|----------------------------------------------------|
| `users`       | OIDC subject, display name, role, status          |
| `clusters`    | name, kubeconfig ref (encrypted), api server, status |
| `cluster_bindings` | user × cluster → allowed RBAC role (viewer/editor/admin) |
| `audit_log`   | who / what / when / cluster / resource / diff / result |
| `refresh_tokens` | JWT refresh token store (hashed), expiry         |
| `alerts`      | active alert state, dedup key, last-firing        |
| `leader_lease` | replica_id, acquired_at, heartbeat_at, token (UUID) |
| `rbac_templates` | name, scope (namespace/cluster), rules (JSONB), builtin |
| `cluster_bindings` | user, cluster, namespace, template, role (computed) |
| `namespace_requests` | user, cluster, namespace, template, status (pending/approved/denied/active/expired), requested_at, decided_by, decided_at, expires_at, reason (§ 5C) |
| `access_requests` | user, cluster, baseline template, elevation template, status (pending/approved/denied/active/expired), requested_at, decided_by, decided_at, expires_at (TTL), reason (§ 5D) |
| `provisioning_tasks` | user, trigger (login/elevation/naas), task type, params (JSONB), status, result (JSONB), created_at, run_at (§ 5E) |
| `scim_mappings` | external_id, provider, kind (user/group), kubedash_id, attributes (JSONB) (§ 5F) |

**One-way-door:** kubeconfig secrets are stored AES-256-GCM encrypted with a
key from `KUBEDASH_SECRET_KEY` (env). The key is not the JWT signing key.

### 3.5 AuthN / AuthZ flow

KubeDash uses **OIDC** as its sole auth mode. There is no proxy mode —
the KubeDash server is the auth authority and issues its own JWTs.

```
Browser ──/auth/login──► Flask ──302──► OIDC /authorize
                              ◄──code──
Flask: code→token→userinfo, upsert `users`, issue short-lived JWT (15 min)
        + refresh token (30 d, stored hashed in `refresh_tokens`)
Flask answers `302 /` with HttpOnly cookies (ADR-0025): `kd_access` (JWT,
Path=/, SameSite=Lax) and `kd_refresh` (opaque, Path=/api/v1/auth,
SameSite=Strict). No credential in the URL.
Browser sends the cookies automatically; API clients and the kubectl plugin
send `Authorization: Bearer <jwt>` instead.
Smorest on_before_request hook: read Bearer first, then `kd_access`; verify
       JWT → load `users` row → stash in flask.g.current_user → allow/deny.
Handler: resolve cluster binding → `rbac.can(...)` (cached
       SubjectAccessReview) → allow/deny.
```

- JWT: HS256, 15 min TTL, `sub` = OIDC subject, `cluster` claim optional.
  The access cookie and the JWT share one lifetime constant
  (`ACCESS_TTL_SECONDS`), so they cannot drift.
- Session delivery (ADR-0025): login answers `302 /` with `kd_access` +
  `kd_refresh` HttpOnly cookies plus a non-HttpOnly `kd_session` navigation
  hint (spoofable, grants nothing). `KUBEDASH_COOKIE_SECURE` defaults True;
  the local HTTP dev stack sets it false.
- Refresh: `/auth/refresh` reads `kd_refresh` (JSON body fallback for
  scripts) and rotates the token, re-setting both cookies.
- Logout: `/auth/logout` revokes the refresh rows (ADR-0014), clears all
  three cookies; OIDC RP-initiated logout if the provider supports it.
- **Smorest integration:** the JWT verify runs in each `Api`'s
  `on_before_request` hook (see § 3.2). Handlers access the user via
  `flask.g.current_user`. Per-cluster RBAC is enforced inside the handler
  via `services.rbac.can(...)` — Smorest is not used for RBAC, only for
  request validation + docs.
- **UI adaptation:** the frontend calls `/auth/me/permissions` on mount to
  get the user's effective RBAC verbs per resource. Buttons (Delete,
  Scale, Rollback, …) are **hidden** if the user lacks the verb.

### 3.6 Real-time (SSE + WebSocket)

**SSE is the primary push channel** for all server→client streams. It is
simpler, stateless, HTTP-native, and load-balancer-friendly. WebSocket is
reserved for **bidirectional** cases only (exec / terminal).

| Stream | Transport | Endpoint | Notes |
|---|---|---|---|
| Events / timeline | **SSE** | `/events/timeline?cluster=&ns=&since=` | K8s Event watch + resource diffs |
| Topology updates | **SSE** | `/events/topology?cluster=&ns=` | Informer cache changes |
| Log tail | **SSE** | `/events/logs?cluster=&ns=&pod=&container=&since=` | K8s `read_namespaced_pod_log` with `follow=True`, chunks ≤ 8 KB |
| Cluster health | **SSE** | `/events/health?cluster=` | Status changes from health probes |
| Exec / terminal | **WebSocket** | `/ws/exec?cluster=&ns=&pod=&container=` | Bidirectional (stdin/stdout). Gated by `features.exec` |

- SSE endpoints are plain Flask routes (not Smorest) that return
  `text/event-stream` with `Cache-Control: no-cache`. The client uses
  `EventSource` (native browser API, auto-reconnect built-in).
- WebSocket (exec) uses Flask-SocketIO over Gunicorn `eventlet`/`gevent`
  workers. Fallback to long-polling is **not** enabled.
- **Backpressure**: each SSE stream is buffered (max 100 events). If the
  client falls behind, the server sends a `reconnect` event and the client
  re-issues with a fresh `since` cursor.

### 3.7 Async tasks (Postgres queue + leader election)

**Queue on Postgres** (ADR-0029, supersedes the RQ/Redis design). Tasks are
defined in `app/tasks/`. The leader-gated scheduler in `wsgi.py` enqueues a due
task as an `INSERT` into a Postgres `tasks` table; a worker loop claims rows
with `SELECT ... FOR UPDATE SKIP LOCKED`, runs them, and marks them done.
**Gated by leader election**: only the replica holding the `leader_lease`
enqueues; any replica runs the claim loop, but `SKIP LOCKED` guarantees a job
is claimed by exactly one worker. Redis is **no longer in the task path** —
Postgres is the only stateful dependency (ADR-0029 + ADR-0030 remove its last
two consumers).

| Task                  | Schedule       | Purpose                                    | Wired |
|-----------------------|----------------|--------------------------------------------|-------|
| `health.run`          | every 1 min    | Hit each cluster's `/readyz`, update status| yes   |
| `cluster_sync.run`    | every 5 min    | Reconcile `clusters` table with live state | yes   |
| `alerts.evaluate`     | every 1 min    | Evaluate Prometheus alert rules, upsert `alerts` | stub |
| `access_expiry.run`   | every 1 min    | Revoke PAM elevations + TTL'd grants whose `expires_at` has passed (§ 5C, § 5D); also reaps `revoked_jtis` (ADR-0030) | stub |
| `rbac_drift.run`      | every 10 min   | Detect RBAC drift vs. role templates (§ 5B) | stub  |

Claim / recovery semantics (ADR-0029): the claim is `FOR UPDATE SKIP LOCKED`
(atomic, non-blocking, cluster-wide under the active-active topology); a
**reaper** re-queues a `processing` row whose `locked_at` is stale (crash
recovery, replaces RQ's death penalty); a task that raises is retried up to 3×
with exponential backoff (`available_at`), then dead-lettered (`status=
'failed'`). The worker **polls** (5 s) rather than using `LISTEN`/`NOTIFY` —
a `NOTIFY` does not replicate across active-active nodes and the tasks are
periodic, so poll latency is immaterial.

**Leader election** (`app/core/leader.py`, ADR-0031, supersedes the
single-writable assumption of ADR-0008):

- A `leader_lease` table with `replica_id`, `acquired_at`, `heartbeat_at`,
  `token` (UUID), and a monotonic **`fence`** column (ADR-0031).
- The **advisory lock** (`pg_try_advisory_lock(hashtext(:rid))`) is the mutex;
  it is **session-local** and not guaranteed to replicate across active-active
  nodes — the `leader_lease` row (which *does* replicate) + the staleness check
  + the fence are the source of truth.
- The leader heartbeats every 5 s (`UPDATE heartbeat_at = now() WHERE id=1 AND
  fence = :my_fence`).
- A background thread on every replica checks: if `heartbeat_at` is stale
  (> 10 s) and I'm not the leader, attempt acquisition (`... SET fence=fence+1
  ... RETURNING fence`).
- **Strict fencing (ADR-0031):** *every* leader-gated task DB-write carries the
  leader's in-memory `fence` and is conditioned on `WHERE fence = :my_fence`.
  Under the active-active last-write-wins conflict resolution, a leader that
  loses the lease row to another node finds its `fence` stale → its writes
  affect 0 rows → it demotes. No two leaders commit task state.
- The in-memory `is_leader` flag is updated by this thread; the scheduler
  checks it per task, per poll and idles when `False`.
- **Failover:** leader dies → followers detect stale heartbeat within 10 s →
  one acquires the lease (fresh advisory lock + `fence+1`) → resumes enqueue.
  No data loss; a dead worker's in-flight job is re-claimed by the reaper and
  retried (3×, exponential backoff).

**Why Postgres over RQ/Redis (ADR-0029) and active-active pgEdge (ADR-0031):**
the queue's payload (a task path + timestamps) has no need to live in a
different engine than the data the tasks mutate, and Postgres is already a hard
requirement — moving the queue (and, per ADR-0030, the session-revocation
deny-list) onto it removes Redis as a stateful dependency entirely. The
task volume is tiny and periodic (no fan-out), so a hand-rolled
`SKIP LOCKED` claim + reaper is simpler than a queue library, and plain
Postgres core (no `CREATE EXTENSION`). The database is run **active-active**
via pgEdge/Spock (`ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal`, a thin
operator-less Helm chart with a run-once init `Job`, `dev/` docker-compose) so
a node loss opens no read-only promotion gap; `autoddl` replicates Alembic DDL
so migrations run once.

### 3.8 Config

Env-driven via `app/core/config.py` (Pydantic `BaseSettings`).
Environments: `development`, `staging`, `production` selected by
`FLASK_ENV`. Secrets come from env or a mounted secret file
(`KUBEDASH_SECRET_FILE` in k8s).

Key env vars:

| Var | Purpose |
|---|---|
| `KUBEDASH_ROLE` | `leader` (runs RQ worker) or `follower` (HTTP only) |
| `KUBEDASH_REPLICA_ID` | unique id for this replica (set by K8s Downward API) |
| `KUBEDASH_SECRET_KEY` | AES-256-GCM key for kubeconfig encryption |
| `KUBEDASH_JWT_SECRET` | HS256 signing key for JWTs |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string (cache + RQ broker) |
| `CORS_ORIGINS` | comma-separated allowed origins (UI) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_ISSUER` | OIDC SSO config |

### 3.9 Observability of KubeDash itself

- **OTel** — Flask + SQLAlchemy + httpx instrumented, OTLP → Tempo/Jaeger.
- **Prometheus** — `/metrics` on the API (request duration, in-flight,
  cluster-watch lag, RQ task duration, leader-election status).
- **Structured logs** — JSON to stdout (Loki ingests).
- **Health endpoints** — `/healthz` (liveness), `/readyz` (DB + Redis + one
  cluster reachable + leader status).

---

## 4. Frontend (React + TypeScript)

### 4.1 Stack

- **Vite 5** — dev server + build. `@vitejs/plugin-react`.
- **React 18** + **TypeScript** (strict, `noUncheckedIndexedAccess`).
- **TanStack Query v5** — all async data. Caching, retries, optimistic
  updates for CRUD.
- **React Router v6** — data router, nested layouts.
- **Zustand** — lightweight global state (selected cluster, theme, sidebar).
- **@coreui/react** + **@coreui/coreui** — component library (Bootstrap 5
  based, true React hook components, no jQuery). The **free React admin
  template** (`coreui/coreui-free-react-admin-template`) is the starting
  scaffold: its `src/` layout (Header, Sidebar, Footer, routes, `_nav`) is
  adopted verbatim as the KubeDash shell, then extended with KubeDash
  feature views.
- **Chart.js** (`react-chartjs-2`) — line/bar/area/doughnut charts for
  metrics, pod scheduling, resource usage. Chart.js is lightweight,
  canvas-based, and pairs well with CoreUI `Card` bodies.
- **DataTables** (`react-datatable`) — client-side + server-side sorting,
  filtering, pagination, column search for resource lists (pods, deployments,
  services, etc.). Server-side mode proxies to the API's `?page=&sort=&q=`
  params.
- **@fortawesome/fontawesome-free** — icon set (replaces CoreUI's default
  icon set for broader glyph coverage: K8s resource icons, status indicators,
  brand icons).
- **highlight.js** — syntax highlighting for YAML, JSON, logs, and code
  snippets (used in the YAML editor, log viewer, and API response panels).
- **Monaco Editor** — YAML/JSON editing with schema validation (kube-openapi
  schemas fetched at runtime).
- **socket.io-client** — WebSocket for logs + events.
- **react-i18next** — i18n (en default; zh, de, ja planned).

> **Note on Tailwind:** the free CoreUI template is Bootstrap/SCSS-based, not
> Tailwind. KubeDash follows the template's native CoreUI styling (SCSS
> variables + `@coreui/coreui` classes). Tailwind is **not** used; custom
> styles go in `src/scss/` per the template's convention.

### 4.2 View folders (CoreUI template convention)

The free CoreUI template organises the app by **view** (one folder per
route), not by feature. KubeDash follows that convention: each
`src/views/<Name>/` is a self-contained vertical containing the page
component, its child components, its hooks, and its TanStack Query
definitions. Views do not import from each other except through `lib/`
(shared API client + types) and `components/` (shared widgets).

```
src/views/
├── Login/        ← /login, /callback (OIDC)
├── Clusters/     ← /clusters (registry list, DataTables)
├── Cluster/      ← /clusters/:id (per-cluster dashboard: pods, nodes, events,
│                   │   Chart.js resource usage, FontAwesome resource icons)
├── Resources/    ← /clusters/:id/<kind> (DataTables list + detail + Monaco YAML)
├── Logs/         ← /clusters/:id/logs (search + live tail + highlight.js)
├── Metrics/      ← /clusters/:id/metrics (Grafana embed + Chart.js panels)
├── Traces/       ← /clusters/:id/traces (search + waterfall)
└── Permissions/  ← /permissions (user) + /admin/permissions (admin)
```

**Shared shell** (from the template, extended):

- `components/Header.jsx` — top bar, cluster switcher dropdown, user menu,
  theme toggle.
- `components/Sidebar.jsx` — collapsible nav, driven by `_nav.tsx`.
- `components/Footer.jsx` — version + status indicators.
- `_nav.tsx` — sidebar config. Each entry maps to a `views/<Name>/` folder.
  Icons come from **Font Awesome** (`<FontAwesomeIcon icon={faKube} />`).
- `routes.tsx` — route table. Protected routes are wrapped in
  `<ProtectedRoute>` (`kd_session` hint check + cluster binding check;
  the hint is not a credential — ADR-0025).

**KubeDash-specific widgets** live in `components/` (not in views):
`PodTable` (DataTables), `LogTail` (socket.io + highlight.js),
`YamlEditor` (Monaco wrapper), `ClusterHealthBadge`, `ResourceYamlModal`,
`MetricChart` (Chart.js wrapper).

### 4.3 API client

`lib/api.ts` — a single typed `fetch` wrapper:

- Sends the session as same-origin HttpOnly cookies (ADR-0025); JS never
  holds a token.
- On 401, triggers a single in-flight refresh (the `kd_refresh` cookie is
  the source), then retries; a 401 that survives the retry clears the
  `kd_session` hint and redirects to `/login`.
- On 403, surfaces a "no permission" toast.
- Session helpers (cookie name, hint read/clear, dead-session redirect) live
  in `lib/session.ts` — the only place that knows the `kd_session` name.
- Returns `{ data, error, meta }` shapes that map 1:1 to TanStack Query
  queryFn results.

WebSocket client in `lib/socket.ts` — auto-reconnect with exponential
backoff, namespaces `/logs` and `/events`.

### 4.4 State strategy

- **Server state** → TanStack Query (never in Redux/Zustand).
- **UI state** (selected cluster, sidebar, theme, filters) → Zustand.
- **Form state** → React hooks / react-hook-form per screen.
- **Route state** → React Router `useSearchParams` (e.g., log time range,
  DataTables page/sort).

### 4.5 Build → static serving

The SPA is built with `vite build` into `frontend/dist/`. The Dockerfile
copies `frontend/dist/` → `backend/static/` in the final image. Gunicorn
serves it via Flask's catch-all route (see § 3.1). **No nginx, no separate
UI container.** Asset files (`/assets/*.js`, `/assets/*.css`) are served
with `Cache-Control: immutable` (hashed filenames). `index.html` is served
with `Cache-Control: no-cache` (always fresh, SPA fallback).

### 4.6 Testing

- **Unit / component** — Vitest + React Testing Library + MSW (mock API).
- **E2E** — Playwright. Spins up a `kind` cluster + KubeDash via Helm,
  runs the full flow: login → view cluster → open pod logs → tail → kill
  pod → verify 404.
- **Visual** — Playwright screenshot diffs on key routes (CI gate).

---

## 5. Multi-cluster design

A **Cluster** is a first-class entity in KubeDash:

- Stored in `clusters` table with name, endpoint, encrypted kubeconfig,
  context, and health status.
- Bound to **users** via `cluster_bindings` (role: `viewer` | `editor` |
  `admin`). A user sees only clusters they are bound to.
- Each cluster has an independent K8s client in the pool. Cross-cluster
  operations (e.g., "search pods across all my clusters") fan out with
  `concurrent.futures` and merge results with per-cluster status.
- **Cross-cluster search** is a single API (`/search?q=...`) that queries
  all bound clusters in parallel, with a 10 s per-cluster timeout and
  partial-result semantics (`200` + `warnings[]` for timed-out clusters).

**One-way-door:** the cluster registry schema (encrypted kubeconfig,
bindings, health) is the backbone of multi-tenancy. Changes to it require
a migration and are ADR-gated.

---

## 5B. Permission Management

KubeDash provides a **self-service permission management** layer inspired
by [sighupio/permission-manager](https://github.com/sighupio/permission-manager)
(1.4k stars, "brings sanity to Kubernetes RBAC") and
[vmware-archive/gangway](https://github.com/vmware-archive/gangway)
(408 stars, "easily enable OIDC auth flows for kubectl").

### What these tools do (and their gaps)

| Tool | What it does | Gap KubeDash fills |
|---|---|---|
| **permission-manager** | Web UI to create users, assign **role templates** (ClusterRole + RoleBinding abstractions) to namespaces, and **distribute kubeconfig YAML** per user. Templates are ClusterRoles with a `template-namespaced-resources___` prefix. Users are a CRD (`permissionmanagerusers`). | Single-cluster only. No SSO — users are manual entries. No multi-cluster. Templates pollute the ClusterRole namespace. No RBAC visibility (can't see what a user *effectively* can do). No self-service kubeconfig download tied to SSO identity. |
| **gangway** | Web app that runs the OIDC flow and hands the user a **preconfigured kubeconfig** (with the ID token embedded). The user pastes it into `~/.kube/config` and `kubectl` works. | Archived (2021). Single-cluster. One-shot kubeconfig (token expires, user must re-run the flow). No RBAC management. No multi-cluster. No role assignment. |

**KubeDash combines and extends both:**
- **Role templates** (from permission-manager) — but stored in KubeDash's
  Postgres (not as prefixed ClusterRoles), so they don't pollute the
  cluster's RBAC namespace.
- **Self-service kubeconfig** (from gangway) — but the kubeconfig
  references the **KubeDash credential plugin** (`kubectl kubedash
  get-token`), not an embedded token. The token is always fresh (PKCE
  flow + keyring cache). No paste-and-pray.
- **Multi-cluster** — a user can have bindings on N clusters. One
  kubeconfig covers all of them.
- **RBAC visibility** — the SSOUser/SSOGroup objects (§ 5A) show what a
  user *effectively* can do, computed from the actual RBAC objects.
- **SSO-native** — users are created automatically on first OIDC login
  (no manual user creation). Groups come from the IdP.

### Role templates

A **role template** is a named, reusable set of RBAC rules. It is the
abstraction over "who can do what." KubeDash ships with four built-in
templates (stored in Postgres, not as ClusterRoles):

| Template | Scope | Rules | Use case |
|---|---|---|---|
| `viewer` | namespace | `get`, `list`, `watch` on all namespaced resources | Read-only access to a namespace |
| `developer` | namespace | `viewer` + `create`, `update`, `patch`, `delete` on pods, deployments, services, configmaps, secrets; `create` on jobs | Day-to-day development |
| `admin` | namespace | `*` on all namespaced resources | Namespace admin |
| `cluster-admin` | cluster | `*` on `*` at cluster scope | Full cluster access |

**Custom templates:** cluster admins can create additional templates via
the UI or API. A template is:

```python
# backend/app/models/rbac_template.py
class RBACTemplate(db.Model):
    __tablename__ = "rbac_templates"
    id: int
    name: str              # unique, e.g. "developer", "sre-oncall"
    description: str
    scope: str             # "namespace" | "cluster"
    rules: JSONB           # [{resources: [...], verbs: [...], api_groups: [...]}]
    created_by: str
    created_at: datetime
    builtin: bool          # True for the 4 built-ins (cannot be deleted)
```

```json
// Example: "developer" template rules
[
  {"api_groups": [""],            "resources": ["pods", "pods/log", "pods/exec"],
   "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
  {"api_groups": ["apps"],        "resources": ["deployments", "statefulsets", "daemonsets"],
   "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
  {"api_groups": [""],            "resources": ["services", "configmaps", "secrets"],
   "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
  {"api_groups": ["batch"],       "resources": ["jobs", "cronjobs"],
   "verbs": ["get", "list", "watch", "create"]}
]
```

**Applying a template** creates the actual K8s RBAC objects:

```
User requests: "bind template 'developer' to user 'jdoe' in namespace 'production'"
    │
    ▼
KubeDash controller (RQ task, leader-only)
    │
    ├── 1. Create/patch a Role "kubedash-developer" in namespace "production"
    │      (rules = template.rules, labels: kubedash.io/template=developer)
    │
    ├── 2. Create/patch a RoleBinding "kubedash-jdoe-production"
    │      (roleRef = kubedash-developer, subjects = [User jdoe])
    │      (labels: kubedash.io/user=jdoe, kubedash.io/template=developer)
    │
    └── 3. Record the binding in KubeDash's cluster_bindings table
           (user=jdoe, cluster=production, role=developer,
            namespace=production, template_id=2)
```

**Key design choices (vs. permission-manager):**

- Templates are stored in **Postgres**, not as ClusterRoles with a prefix.
  The actual Role/RoleBinding objects created in the cluster carry a
  `kubedash.io/template` label so they can be discovered and cleaned up.
  This avoids polluting the cluster's ClusterRole namespace.
- **Idempotent:** re-applying the same template to the same user + namespace
  is a no-op (the Role/RoleBinding already exist with the right rules).
- **Drift detection:** if someone edits a `kubedash.io/template` Role
  directly (via kubectl), the next RQ sync detects the drift and either
  re-applies the template (if `rbac.driftPolicy: enforce`) or flags it
  (if `rbac.driftPolicy: warn`).
- **Deletion:** removing a binding deletes the RoleBinding. The Role is
  deleted only when no other binding references it.

### Self-service kubeconfig

When a user logs in (OIDC) and has ≥ 1 cluster binding, KubeDash offers
a **"Download kubeconfig"** button in the UI. This is the gangway pattern,
extended:

```yaml
# Generated kubeconfig (what the user downloads)
apiVersion: v1
kind: Config
clusters:
  - name: kubedash-production
    cluster:
      server: https://api.production.example.com:6443
      certificate-authority-data: <base64 CA>
  - name: kubedash-staging
    cluster:
      server: https://api.staging.example.com:6443
      certificate-authority-data: <base64 CA>
contexts:
  - name: kubedash-production
    context:
      cluster: kubedash-production
      user: kubedash
      namespace: production        # default namespace (from binding)
  - name: kubedash-staging
    context:
      cluster: kubedash-staging
      user: kubedash
      namespace: staging
users:
  - name: kubedash
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - kubedash
          - get-token
          - --server=https://kubedash.example.com
          # NOTE: no --cluster-name here; the plugin reads it from the
          #       kubeconfig context's cluster.server (auto-detect)
current-context: kubedash-production
```

**Differences from gangway:**
- The kubeconfig references the **KubeDash credential plugin** (§ 7.6),
  not an embedded ID token. The token is always fresh (PKCE + keyring).
- **Multi-cluster:** one kubeconfig covers all bound clusters. Each
  context maps to a cluster + namespace.
- **Auto-detect cluster:** the plugin reads the cluster from the
  kubeconfig context's `cluster.server` URL (matched against the
  KubeDash cluster registry) instead of a `--cluster-name` flag. This
  means the same user entry works for all clusters.
- **Default namespace:** each context sets `namespace` to the user's
  bound namespace, so `kubectl get pods` works without `-n`.

**API endpoint:**

```
GET /api/v1/kubeconfig
  → Content-Disposition: attachment; filename="kubedash-kubeconfig.yaml"
  → Content-Type: application/yaml
  (requires a valid session; returns 404 if no bindings)
```

### Permission management UI

A new view in the KubeDash frontend: `src/views/Permissions/`.

**For cluster admins** (`/admin/permissions`):

| Tab | Content |
|---|---|
| **Users** | DataTables list of all users (from `users` table). Columns: username, email, groups, last login, cluster count. Click → user detail. |
| **User Detail** | User's cluster bindings (cluster, namespace, template, role). "Bind" button → pick cluster + namespace + template. "Unbind" button. "Download kubeconfig" button. SSOUser effective permissions (from § 5A). |
| **Templates** | DataTables list of RBAC templates (built-in + custom). Columns: name, scope, rule count, description. Click → template detail (rules editor). "Create template" button. |
| **Template Detail** | Rule editor (add/remove resource + verb rows). Scope selector (namespace/cluster). "Preview" shows the rendered Role YAML. |
| **Audit** | Permission change history (who bound/unbound what, when). From `audit_log`. |

**For regular users** (`/permissions`):

| Tab | Content |
|---|---|
| **My Access** | List of the user's cluster bindings (cluster, namespace, role). "Download kubeconfig" button. |
| **My Projects** | List of Projects the user can see (from § 5A aggregated API). |

### Backend service

```python
# backend/app/services/permission.py — module functions, pure Python (no Flask).
# Dependencies are passed in: db_session is a SQLAlchemy session, k8s is a
# K8sClient for the target cluster, settings carries plugin_server.

def bind(*, user_sub: str, cluster_id: int, namespace: str | None,
         template_name: str, actor_sub: str, db_session, k8s) -> ClusterBinding:
    """Apply a role template to a user (synchronous, ADR-0008).

    Resolve template/user/cluster -> scope guard -> idempotency check (an
    existing user+cluster+namespace+template row is returned as a 200 no-op,
    no re-apply, no audit row) -> apply Role + RoleBinding (or ClusterRole +
    ClusterRoleBinding) labelled kubedash.io/template + kubedash.io/user ->
    commit the cluster_bindings row and the audit_log row in one transaction.
    """

def unbind(*, user_sub: str, cluster_id: int, namespace: str | None,
           actor_sub: str, db_session, k8s) -> None:
    """Remove a user's binding. No template argument: the row is looked up by
    user + cluster + namespace. Deletes the RoleBinding, GCs the Role only
    when no other binding on that scope references the same template, then
    deletes the row + writes the audit row."""

def generate_kubeconfig(*, user_sub: str, db_session, settings) -> str:
    """Render the caller's self-service kubeconfig: one cluster entry per
    distinct bound cluster (server + CA from the decrypted registry
    kubeconfig, ADR-0002), one context per binding named kubedash-<cluster>
    (cluster-scoped bindings omit namespace), exec-plugin user pointing at
    settings.plugin_server (KUBEDASH_PLUGIN_SERVER)."""

# Errors (stable codes): missing cluster CLUSTER_NOT_FOUND 404; missing
# template/user RESOURCE_KIND_NOT_SUPPORTED 404; scope mismatch
# INVALID_KUBECONFIG 422; cluster failure CLUSTER_UNREACHABLE 502; no
# bindings NO_BINDINGS 404; unset plugin_server INTERNAL_ERROR 500.
#
# Not implemented: effective-permission (SSOUser, § 5A) lookup — the admin
# user detail shows bindings only.
```

### Drift detection (RQ task) — not implemented

> Design only. The user-management change (ADR-0013 core) ships templates,
> bind/unbind and self-service kubeconfig; the `rbac_drift_check` task below
> is not part of it.

The `rbac_drift_check` task runs every 10 min (leader-only):

1. List all Roles/RoleBindings in each cluster with the
   `kubedash.io/template` label.
2. Compare their rules against the template in Postgres.
3. If a Role's rules differ from the template → **drift**.
4. If `rbac.driftPolicy: enforce` → re-apply the template (fix the drift).
5. If `rbac.driftPolicy: warn` → log a warning + create an alert.
6. If a RoleBinding references a template that no longer exists →
   **orphan** → flag for cleanup.

### Helm values

```yaml
# values.yaml
rbac:
  templates:
    enabled: true
    driftPolicy: enforce       # enforce | warn
    driftCheckInterval: 10m
  kubeconfig:
    enabled: true              # allow self-service kubeconfig download
    # The generated kubeconfig references the credential plugin.
    # The plugin's --server must match the KubeDash ingress URL.
    pluginServer: https://kubedash.example.com
```

### Security

| Concern | Control |
|---|---|
| Who can bind/unbind | Only users with `cluster-admin` or `kubedash.io/admin` group can create/modify bindings. Regular users see "My Access" (read-only). |
| Template creation | Only `cluster-admin` can create/edit custom templates. Built-in templates are read-only. |
| Role/RoleBinding naming | `kubedash-` prefix + `kubedash.io/*` labels. Prevents collision with user-managed RBAC. |
| Drift enforcement | `driftPolicy: enforce` re-applies templates. `warn` only logs. Configurable. |
| Kubeconfig generation | Requires a valid session. No token embedded (plugin-based). CA data is public. |
| Audit | Every bind/unbind/template change → `audit_log`. |

### ADR

- **ADR-0013** — Permission management: role templates (Postgres, not
  ClusterRoles) + self-service kubeconfig (plugin-based, multi-cluster) +
  drift detection. Combines permission-manager (templates) + gangway
  (kubeconfig) patterns, extended for multi-cluster + SSO.

### 5B.1 Session revocation propagation (learned from OpenUnison)

OpenUnison's distinguishing guarantee: *logging out of the web session
invalidates the kubectl session.* KubeDash adopts the same property.

**The property:** when a user's KubeDash session ends (logout, refresh-token
revocation, or IdP-side logout), every credential derived from that session
becomes unusable **immediately**, not at its natural expiry.

**How it works:**

| Credential path | Revocation mechanism |
|---|---|
| Web session (JWT) | Logout deletes the row from `refresh_tokens`, adds the `jti` to a Redis revocation set checked by the JWT verify hook, and clears the session cookies. The 15-min JWT is short enough that the revocation set only needs to live `TTL(JWT)` (15 min). |
| kubectl plugin (OIDC ID token) | Logout triggers **OIDC RP-initiated logout** (`end_session_endpoint`, `post_logout_redirect_uri`), so the IdP revokes the refresh token. The plugin's next `get-token` refresh fails → browser re-auth. For clusters where the K8s API server accepts a *KubeDash-issued* token (not the raw IdP token), the same `jti` revocation set is checked on the `/kubectl/auth/v1/token` endpoint. |
| Cert-based access (CSR) | Logout calls `revoke_user_csr(user)` — the KubeDash-serving certificate (signer `kubernetes.io/kubedash-apiserver-client`) is revoked in the cluster's certificate authority. The cert remains valid in TLS terms but is rejected by the K8s API server's client CA check once revoked (CRL / OCSP, or the cert is removed from the CA bundle KubeDash publishes). |

**Key design choice:** revocation is **additive** (a deny-list), not
stateful per-token. The deny-list is Redis (fast, shared across replicas)
with a TTL equal to the JWT lifetime, so it self-cleans. No DB migration
beyond the existing `refresh_tokens` table.

**Endpoints:**

```
POST /auth/logout
  1. Delete the user's refresh_token row
  2. Add jti to the Redis revocation set (TTL = JWT expiry)
  3. Call OIDC end_session (if the IdP advertises one)
  4. Revoke the user's KubeDash-serving CSR (cert path)
  5. Audit: action="logout", cluster=all-bound
```

**ADR:** ADR-0014.

---

## 5C. Namespace as a Service (NaaS)

Self-service namespace onboarding, learned from OpenUnison's NaaS portal.
Instead of an admin binding every user by hand, a user **requests** access
to a namespace (or a new namespace), an approver **approves** it, and KubeDash
**provisions** it automatically.

### The flow

```
User (UI: "Request access")
    │  cluster, namespace (existing or new), template, reason, optional TTL
    ▼
POST /api/v1/namespaces/requests
    │
    ▼
Row in `namespace_requests` (status=pending)
    │
    ├──► Notification to approvers (group-based: the cluster's
    │    `naas.approverGroups`, or any `cluster-admin`)
    │
    ▼
Approver (UI: /admin/namespaces/requests → Approve / Deny)
    │
    ▼
POST /api/v1/namespaces/requests/<id>/approve
    │
    ├── 1. (if new namespace) create the Namespace + labels
    │       kubedash.io/naas=true, kubedash.io/request=<id>
    ├── 2. Apply the role template (reuse § 5B permission service:
    │       Role + RoleBinding, labelled kubedash.io/template=…)
    ├── 3. Run the JIT provisioning pipeline (§ 5E) — optional
    │       per-cluster tasks: create default ServiceAccount,
    │       apply a ResourceQuota/LimitRange from a cluster default,
    │       create a default Secret, etc.
    ├── 4. Record in `cluster_bindings`
    ├── 5. If a TTL was requested → set `expires_at` on the request
    │       and the binding
    └── 6. Audit: action="naas.approve"
```

**Deny** records the reason and notifies the requester. No cluster-side
objects are created.

### Data model

```python
# backend/app/models/namespace_request.py
class NamespaceRequest(db.Model):
    __tablename__ = "namespace_requests"
    id: int
    user_id: int               # requester
    cluster: str
    namespace: str             # existing or to-be-created
    namespace_is_new: bool
    template: str              # role template name (§ 5B)
    reason: str                # free text, required
    ttl_hours: int | None      # optional time-boxed grant
    status: str                # pending | approved | denied | active | expired
    requested_at: datetime
    decided_by: int | None     # approver user_id
    decided_at: datetime | None
    deny_reason: str | None
    expires_at: datetime | None
```

### API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/namespaces/requests` | any authenticated user | Submit a request |
| `GET` | `/api/v1/namespaces/requests?status=pending` | requester (own) / approver (all) | List requests |
| `GET` | `/api/v1/namespaces/requests/<id>` | requester / approver | One request |
| `POST` | `/api/v1/namespaces/requests/<id>/approve` | approver | Approve + provision |
| `POST` | `/api/v1/namespaces/requests/<id>/deny` | approver | Deny |
| `DELETE` | `/api/v1/namespaces/requests/<id>` | approver / requester (pending only) | Cancel |

### Auto-expiry (TTL'd grants)

The `access_expiry` RQ task (leader-only, every 1 min, § 3.7) scans
`namespace_requests` and `access_requests` for `status=active` rows whose
`expires_at <= now()`, then:

1. Unbinds the user (deletes the RoleBinding; deletes the Role if unreferenced).
2. Marks the request `expired`.
3. Optionally deletes the namespace if `namespace_is_new` and
   `naas.deleteOnExpire: true` (default `false` — data safety).
4. Audits: `action="naas.expire"`.

### Helm values

```yaml
# values.yaml
naas:
  enabled: true
  approverGroups: ["platform-team"]   # groups that can approve
  allowNewNamespaces: true            # false → only pre-existing namespaces
  defaultTTLHours: 0                  # 0 = no TTL (permanent grant)
  maxTTLHours: 720                    # cap on requested TTL (30 d)
  deleteOnExpire: false               # delete new namespaces when their grant expires
```

### Security

| Concern | Control |
|---|---|
| Who can request | Any authenticated user with ≥ 1 cluster binding (or `naas.enabled` and no bindings → request creates the first). |
| Who can approve | Users in `naas.approverGroups` or `cluster-admin`. Not self-approve. |
| Namespace creation | Only if `allowNewNamespaces: true`; namespace is labelled `kubedash.io/naas=true`. |
| Template selection | Requester picks from **non-`cluster-admin`** templates only; `cluster-admin` requires a PAM elevation (§ 5D). |
| TTL | Bounded by `maxTTLHours`; auto-revoked by `access_expiry`. |
| Audit | Every request/approval/denial/expiry → `audit_log`. |
| Drift | Provisioned RBAC objects carry `kubedash.io/template` labels → covered by the existing `rbac_drift_check` task. |

**ADR:** ADR-0015.

---

## 5D. Privileged Access Management (PAM)

Time-boxed, approved **elevation** of a user's baseline role, learned from
OpenUnison's PAM. The core idea: a user has a *baseline* binding (e.g.
`viewer` on production). When they need more (e.g. `developer` for a
hotfix), they **request an elevation** with a reason and a TTL. An approver
approves. KubeDash applies the *delta* of RBAC. When the TTL elapses, the
elevation is **automatically reverted** to the baseline.

### Baseline vs. elevation

```
Baseline (permanent):  user × cluster × namespace × template "viewer"
Elevation (time-boxed): user × cluster × namespace × template "developer"
                          for 4 hours, with reason "hotfix payment-api"
```

KubeDash does **not** replace the baseline binding. It applies the
elevation template **on top** (a second RoleBinding, labelled
`kubedash.io/elevation=<access_request_id>`). On expiry, only the
elevation binding is removed; the baseline is untouched. This means:

- Reverting an elevation can never break the user's baseline access.
- Multiple concurrent elevations on the same user × namespace are allowed
  (each is an independent binding).
- The effective permission is the **union** of baseline + all active
  elevations (standard K8s RBAC semantics).

### The flow

```
User (UI: /permissions → "Request elevated access")
    │  cluster, namespace, baseline (auto-detected), elevation template,
    │  TTL (bounded), reason (required)
    ▼
POST /api/v1/access/requests
    │
    ▼
Row in `access_requests` (status=pending)
    │
    ├──► Notification to approvers (same group model as NaaS,
    │    or a dedicated `pam.approverGroups`)
    ▼
Approver approves
    │
    ▼
POST /api/v1/access/requests/<id>/approve
    │
    ├── 1. Compute the RBAC delta: elevation_template.rules − baseline_template.rules
    │      (KubeDash records which rules are *added* for the audit trail)
    ├── 2. Create the elevation RoleBinding (label kubedash.io/elevation=<id>)
    │      pointing at the elevation Role (created once per template, shared)
    ├── 3. Set `expires_at = now() + TTL`
    ├── 4. Status → active
    └── 5. Audit: action="pam.approve", with the RBAC delta
```

### Auto-revert

The same `access_expiry` RQ task (leader-only, every 1 min) handles PAM
expiries:

1. Find `access_requests` with `status=active` and `expires_at <= now()`.
2. Delete the elevation RoleBinding (label `kubedash.io/elevation=<id>`).
3. If no other elevation references the elevation Role, delete it.
4. Status → `expired`.
5. Audit: `action="pam.expire"`.
6. **No** alert if the elevation was already manually revoked (idempotent).

### Break-glass

A `cluster-admin` can elevate *themselves* (self-approve) when no approver
is reachable — the break-glass path. This is:
- Limited to a short TTL (default 1 h, `pam.breakGlassTTLHours`).
- Always audited with `decided_by == requested_by` flagged.
- Visible in a `/admin/access/break-glass` report for review.

### Data model

```python
# backend/app/models/access_request.py
class AccessRequest(db.Model):
    __tablename__ = "access_requests"
    id: int
    user_id: int
    cluster: str
    namespace: str | None       # None = cluster-scoped elevation
    baseline_template: str      # the user's existing binding
    elevation_template: str     # the requested elevated template
    status: str                 # pending | approved | denied | active | expired | revoked
    reason: str                 # required
    ttl_hours: int              # bounded by pam.maxTTLHours
    is_break_glass: bool        # True if self-approved
    requested_at: datetime
    decided_by: int | None
    decided_at: datetime | None
    rbac_delta: JSONB | None    # rules added (for audit)
    expires_at: datetime | None
    revoked_at: datetime | None # manual early revoke
```

### API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/access/requests` | any authenticated user | Submit elevation |
| `GET` | `/api/v1/access/requests?status=active` | requester (own) / approver (all) | List |
| `POST` | `/api/v1/access/requests/<id>/approve` | approver (or self, break-glass) | Approve + apply |
| `POST` | `/api/v1/access/requests/<id>/deny` | approver | Deny |
| `POST` | `/api/v1/access/requests/<id>/revoke` | approver / requester | Manual early revoke |

### Helm values

```yaml
# values.yaml
pam:
  enabled: true
  approverGroups: ["sre-leads"]
  maxTTLHours: 12               # cap on elevation TTL
  breakGlassEnabled: true
  breakGlassTTLHours: 1         # self-approve TTL cap
  allowClusterScoped: true      # false → namespace-scoped elevations only
```

### Security

| Concern | Control |
|---|---|
| Elevation is additive | Baseline binding is never modified; revert only removes the elevation binding. |
| RBAC delta recorded | The exact rules added are stored in `rbac_delta` for audit. |
| TTL bounded | `ttl_hours ≤ pam.maxTTLHours`; break-glass ≤ `pam.breakGlassTTLHours`. |
| Self-approve limited | Only via break-glass, short TTL, flagged in audit + report. |
| Elevation RBAC objects | Labelled `kubedash.io/elevation=<id>` → discoverable, cleanable, drift-checked. |
| Audit | Request/approve/deny/expire/revoke → `audit_log`, with the RBAC delta on approve. |

**ADR:** ADR-0016.

---

## 5E. Just-In-Time (JIT) Login Provisioning

Custom provisioning that runs **at login** (or at elevation approval, or at
NaaS approval), learned from OpenUnison's customizable JIT login workflow.
KubeDash's existing behaviour — auto-create the `users` row on first OIDC
login — is the trivial case. The JIT engine generalises it into a
**declarative, per-cluster provisioning pipeline**.

### What it is

A **provisioning task** is a named, parameterised action that mutates the
cluster on behalf of the user. Tasks are **declared** in Helm
(`provisioning.tasks`), **triggered** by a lifecycle event (login,
elevation, NaaS approval), and **executed** by the `provisioning.py`
service in order. Each task is idempotent and individually retryable.

### Trigger points

| Trigger | When | Example |
|---|---|---|
| `login` | Every successful OIDC login (and first login) | Ensure the user's default namespace exists; create a per-user ServiceAccount; apply a default `viewer` binding if none exists. |
| `elevation` | PAM elevation approved (§ 5D) | Grant access to a break-glass `kubectl` context; write a short-lived Secret the user's workload can mount. |
| `naas` | NaaS request approved (§ 5C) | Apply a cluster-default `ResourceQuota`/`LimitRange` to the new namespace; create a default `Secret` with a registry credential. |

### Declaration (Helm)

```yaml
# values.yaml
provisioning:
  enabled: true
  tasks:
    - name: ensure-default-namespace
      trigger: login
      type: namespace.ensure          # builtin
      params:
        name: "{{ username }}-default"
    - name: default-viewer-binding
      trigger: login
      type: rbac.bind_template        # builtin
      params:
        template: viewer
        namespace: "{{ username }}-default"
      onlyIf: noExistingBinding
    - name: per-user-serviceaccount
      trigger: login
      type: serviceaccount.create     # builtin
      params:
        name: "{{ username }}"
        namespace: "{{ username }}-default"
    - name: registry-secret
      trigger: naas
      type: secret.copy               # builtin
      params:
        fromSecret: registry-creds    # source Secret in kubedash ns
        toName: registry-creds
        template: "{{ namespace }}"
```

Task types are **builtin** (implemented in `services/provisioning.py`):
`namespace.ensure`, `rbac.bind_template`, `serviceaccount.create`,
`secret.copy`, `label.apply`, `annotation.apply`, `quota.apply`,
`limitrange.apply`. Custom (arbitrary) task types are a deferred extension
(§ 11).

### Execution

```python
# backend/app/services/provisioning.py
def run_pipeline(user, cluster, trigger: str, context: dict):
    """Run all tasks whose trigger matches, in declared order."""
    tasks = config.provisioning.tasks_for(trigger, cluster)
    for task in tasks:
        # idempotency: each task checks its own preconditions
        result = BUILTIN_TYPES[task.type](user, cluster, task.params, context)
        ProvisioningTask(
            user=user, trigger=trigger, task=task.name,
            params=task.params, status=result.status,
            result=result.detail
        ).save()  # one row per task run, for audit
        if result.status == "failed" and task.required:
            raise ProvisioningError(task.name)  # halt the pipeline
```

- **Login-time tasks run inline** (synchronously) during the OIDC callback,
  but **after** the JWT is issued — a provisioning failure does **not**
  block login. The user is logged in; the failure is recorded in
  `provisioning_tasks` and surfaced in the UI ("your workspace failed to
  provision: …"). This keeps login availability decoupled from provisioning
  correctness.
- **Elevation / NaaS tasks run synchronously** inside the approve handler
  (they must succeed for the access to be granted).
- **Retry:** failed tasks are re-run on the next login of the same user
  (login-triggered) or via an admin "Re-run provisioning" button.
- **Template variables:** `{{ username }}`, `{{ namespace }}`,
  `{{ cluster }}`, `{{ request_id }}` are substituted (Jinja2, `undefined`
  is an error, no sandboxed globals).

### Data model

```python
# backend/app/models/provisioning_task.py
class ProvisioningTask(db.Model):
    __tablename__ = "provisioning_tasks"
    id: int
    user_id: int
    cluster: str
    trigger: str          # login | elevation | naas
    task_name: str
    params: JSONB
    status: str           # success | failed | skipped
    result: JSONB
    created_at: datetime
    run_at: datetime
```

### Security

| Concern | Control |
|---|---|
| Tasks are declared, not code | Only `provisioning.tasks` from Helm run. No user-supplied task types (custom types deferred). |
| Idempotent | Each builtin task is safe to re-run (create-if-absent, patch-to-desired). |
| Login not blocked | Login-time provisioning failure → logged-in user + recorded failure, not a failed login. |
| Audit | One `provisioning_tasks` row per run (params + result). |
| Least privilege | The KubeDash ServiceAccount needs write on the resources the tasks touch (namespaces, serviceaccounts, secrets, quotas) — scoped per the tasks actually declared. |

**ADR:** ADR-0017.

---

## 5F. SCIM 2.0 Gateway

A **SCIM 2.0** server (RFC 7644) that lets an external identity source — an
IdP, an HR system, or an upstream identity hub — **push** user and group
lifecycle to KubeDash, instead of KubeDash discovering users only at SSO
login. Learned from OpenUnison's SCIM 2.0 Gateway.

### Why

KubeDash's user/group discovery is currently **login-driven**: a user exists
in `users` only after their first OIDC login, and groups only from the
`groups` claim at login. This has two gaps:

1. **De-provisioning is invisible.** When an employee leaves, the IdP
   disables their account, but KubeDash keeps the `users` row and any
   bindings until someone notices. SCIM `deactivate` closes this.
2. **Group membership is not authoritative.** The IdP is the source of truth
   for groups; KubeDash should *receive* that, not infer it from a single
   login's `groups` claim.

The SCIM gateway makes the IdP (or an identity hub like Okta/EntraID/Keycloak
that speaks SCIM) the **push** authority: it calls KubeDash's `/scim/v2/*`
endpoints on user/group create/update/deactivate.

### Scope

KubeDash implements the **SCIM 2.0 resource + filter subset** that identity
hubs actually use:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/scim/v2/Users` | List (with `?filter=`, `?startIndex=`, `?count=`) |
| `POST` | `/scim/v2/Users` | Create |
| `GET` | `/scim/v2/Users/<id>` | Read one |
| `PUT` | `/scim/v2/Users/<id>` | Full replace |
| `PATCH` | `/scim/v2/Users/<id>` | Partial (replace/add/remove ops) |
| `DELETE` | `/scim/v2/Users/<id>` | Delete |
| `POST` | `/scim/v2/Users/<id>/ deactivate` *(via `active=false` PATCH)* | Deactivate |
| `GET/POST/GET/PUT/PATCH/DELETE` | `/scim/v2/Groups[...]` | Same for groups |

- **`active` flag:** SCIM `active: false` → KubeDash `users.status = disabled`
  (login rejected, bindings retained for audit). `active: true` → re-enabled.
- **SCIM id ↔ KubeDash id:** SCIM's opaque `id` is mapped to the KubeDash
  `users.id` / `sso_groups.id` via `scim_mappings`. The SCIM `externalId`
  is stored and used for idempotent upserts (same `externalId` → same row).
- **Filter subset:** `userName eq "…"`, `externalId eq "…"`,
  `active eq true/false`, `groups.value eq "…"`, and `and`/`or` composition.
  (The full SCIM filter grammar is a deferred extension; the subset covers
  Okta/EntraID/Keycloak provisioning.)
- **Auth:** the SCIM endpoints are authenticated with a **dedicated SCIM
  client** (a KubeDash-issued service bearer token, or a shared secret in
  `Authorization: Bearer <scim_token>`). It is **not** user SSO — SCIM is a
  machine-to-machine channel. The token is scoped to `scim:users` +
  `scim:groups` (no cluster access).

### Mapping to KubeDash

```
SCIM User                        KubeDash
─────────────────────────────────────────────────────
id            (opaque)      ↔    scim_mappings.kubedash_id → users.id
externalId                    →   users.oidc_subject (or users.external_id)
userName                      →   users.username
name.givenName/familyName     →   users.display_name
emails[0].value               →   users.email
active                        →   users.status (active|disabled)
groups[].value                →   SSOGroup rows + user↔group membership
meta.created/lastModified     →   users.created_at / updated_at (read-only)
```

### Side effects

A SCIM **create/update** of a user does **not** auto-create cluster
bindings — bindings are still an explicit admin/NaaS/PAM action (§ 5B–5D).
SCIM manages the *identity* (who the user is, their groups, active state);
KubeDash's permission model manages *access* (bindings). This keeps the two
concerns decoupled.

A SCIM **deactivate** sets `users.status=disabled`. The next login is
rejected. Existing bindings are **retained** (not deleted) so re-activation
restores access; a separate admin action or a `scim.deleteBindings: true`
Helm flag can cascade-delete bindings on deactivate.

### Helm values

```yaml
# values.yaml
scim:
  enabled: true
  tokenSecret: kubedash-scim-token   # the Bearer token for SCIM calls
  deleteBindingsOnDeactivate: false  # true → deactivate also removes bindings
  allowedOrigins: []                 # if using IP/origin allow-list (defence in depth)
```

### Security

| Concern | Control |
|---|---|
| Auth | Dedicated SCIM Bearer token (machine-to-machine), scoped to SCIM resources only. Not user SSO. |
| Idempotency | Upsert keyed on `externalId`; re-POSTing the same user is a no-op. |
| Deactivate ≠ delete | `active: false` disables (reversible); `DELETE` removes the row (bindings retained by default). |
| Filter injection | Filters are parsed by a SCIM filter parser (not string-interpolated into SQL); parameterised. |
| Audit | Every SCIM mutation → `audit_log` (source="scim", actor=scim-token). |
| Ordering | SCIM calls are idempotent and out-of-order safe (last-write-wins per `externalId`). |

**ADR:** ADR-0018.

---

## 5A. Kubernetes API Aggregation Layer

KubeDash registers itself as an **aggregated API server** with the
Kubernetes API server, following the pattern from
[kube-aggregator](https://github.com/kubernetes/kube-aggregator) (and its
[OpenShift fork](https://github.com/openshift/kubernetes-kube-aggregator)).
This exposes KubeDash-specific objects directly in the Kubernetes API —
`kubectl get projects`, `kubectl get sso-users` — without a separate
KubeDash API call.

### What kube-aggregator does

The stock `kube-aggregator` provides three capabilities:

1. **API Service registration** — a `v1beta1.APIService` CRD that
   registers a new API group (e.g. `projects.kubedash.io/v1`) with the
   K8s API server. The API server discovers the aggregated server via the
   `APIService`'s `spec.service` reference and proxies requests.
2. **Discovery summarization** — the K8s API server merges the
   aggregated server's `/api` and `/apis` discovery docs into its own, so
   `kubectl api-resources` shows the new group.
3. **Secure proxy** — the API server proxies requests to the aggregated
   server over mTLS (the aggregated server presents a client certificate
   signed by the same CA as the API server's serving cert).

KubeDash uses this mechanism to expose **three new API groups**:

| Group | Version | Objects | Purpose |
|---|---|---|---|
| `projects.kubedash.io` | `v1` | `Project` | 1:1 mapping of a K8s Namespace, filtered by user RBAC |
| `auth.kubedash.io` | `v1` | `SSOUser` | Per-user effective permissions (cluster-admin view) |
| `auth.kubedash.io` | `v1` | `SSOGroup` | Per-group effective permissions (cluster-admin view) |

### Architecture

```
kubectl get projects -o wide
    │
    ▼
K8s API Server
    │  (discovers APIService projects.kubedash.io/v1)
    │  (proxies over mTLS to the aggregated server)
    ▼
KubeDash Aggregated API (Flask, same container as the main API)
    │
    ├── 1. Authenticate the user (K8s client cert / bearer token)
    ├── 2. List all Namespaces in the cluster
    ├── 3. For each namespace, run SubjectAccessReview
    │      (can this user "get" pods in this namespace?)
    ├── 4. Filter: keep only namespaces where the user has ≥ read access
    ├── 5. Wrap each in a Project object
    └── 6. Return the list
```

**Key property:** the aggregated server is **stateless** and **read-only**.
It does not store any data of its own — it derives `Project`, `SSOUser`,
and `SSOGroup` objects on-the-fly from the K8s API (Namespaces, RBAC
objects) + the KubeDash `cluster_bindings` table. The informer cache
(§ 3.3) serves the Namespace + RBAC reads; `SubjectAccessReview` serves
the permission checks.

### The `Project` object

`Project` is a **1:1 read-only projection** of a K8s `Namespace`, filtered
by the requesting user's RBAC. A user sees only the Projects (Namespaces)
where they have at least read permission.

```yaml
# kubectl get project production -o yaml
apiVersion: projects.kubedash.io/v1
kind: Project
metadata:
  name: production              # same name as the Namespace
  namespace: ""                 # cluster-scoped (like Namespace)
  labels:
    kubedash.io/namespace: production
  annotations:
    kubedash.io/description: "Production workloads"
spec:
  displayName: Production       # human-friendly name (from label or annotation)
  description: Production workloads
  conditions:
    - type: Active              # derived from Namespace.status.phase
      status: "True"
status:
  phase: Active                 # Active | Closing
  resourceQuota:                # if a ResourceQuota exists in the namespace
    cpu: {used: "12", hard: "32"}
    memory: {used: "48Gi", hard: "128Gi"}
  podCount: 142
  deploymentCount: 23
  serviceCount: 31
```

**API surface:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/apis/projects.kubedash.io/v1/projects` | List Projects the user can read |
| `GET` | `/apis/projects.kubedash.io/v1/projects/{name}` | Get one Project |
| `WATCH` | `/apis/projects.kubedash.io/v1/projects` | Watch for changes (delegated to Namespace watch) |

**RBAC filter logic:**

```python
def list_projects(user: str, cluster: Cluster) -> list[Project]:
    projects = []
    for ns in informer_cache[cluster]["namespaces"].values():
        # Does the user have ≥ read access to this namespace?
        can = rbac.can(user, verb="get", resource="pods",
                       namespace=ns.metadata.name, cluster=cluster)
        if can:
            projects.append(_namespace_to_project(ns))
    return projects
```

- **Cluster-admin** sees all Namespaces as Projects.
- **Namespace-scoped user** sees only the Namespaces in their bindings.
- **No binding** → empty list (no error).
- The check is cached per (user, namespace) for 30 s (reuses the existing
  `rbac.can` cache).

### The `SSOUser` object (optional, cluster-admin only)

`SSOUser` is a **synthetic, read-only** object that shows what a specific
user can do across the cluster. It does not exist in etcd — it is computed
on-the-fly from RBAC objects + the KubeDash `users` table.

**Only visible to cluster-admin** (RBAC: `get` on `sso-users` requires
the `cluster-admin` role or the `kubedash.io/admin` group).

```yaml
# kubectl get ssouser jdoe -o yaml
apiVersion: auth.kubedash.io/v1
kind: SSOUser
metadata:
  name: jdoe
  namespace: ""
spec:
  username: jdoe
  email: jdoe@example.com
  displayName: John Doe
  groups: [developers, platform-team]
  oidcSubject: google-oauth2|1234567890
  lastLogin: "2026-10-17T08:30:00Z"
  clusterBindings:
    - cluster: production
      role: editor
    - cluster: staging
      role: admin
status:
  effectivePermissions:
    clusterScoped:
      - resource: nodes
        verbs: [get, list]
      - resource: namespaces
        verbs: [get, list]
    namespaceScoped:
      - namespace: production
        rules:
          - resource: pods
            verbs: [get, list, watch]
          - resource: deployments
            verbs: [get, list, watch, patch]
          - resource: secrets
            verbs: [get]
      - namespace: staging
        rules:
          - resource: "*"
            verbs: [get, list, watch, create, update, patch, delete]
  blastRadius:
    hasWildcards: false
    hasClusterAdmin: false
    canCreatePodsClusterWide: false
    summary: "Namespace-scoped editor on production, admin on staging"
```

**API surface:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/apis/auth.kubedash.io/v1/sso-users` | List SSOUsers (cluster-admin only) |
| `GET` | `/apis/auth.kubedash.io/v1/sso-users/{username}` | Get one SSOUser |

**Computation:**

```python
def get_sso_user(username: str, cluster: Cluster) -> SSOUser:
    user = db.users.get_by_username(username)
    bindings = db.cluster_bindings.get_by_user(user.id)
    
    # Effective permissions: walk all RoleBindings + ClusterRoleBindings
    # that reference this user (directly or via groups)
    cluster_rules = []
    ns_rules = defaultdict(list)
    for crb in informer_cache[cluster]["clusterrolebindings"].values():
        if _matches_user(crb, username, user.groups):
            role = informer_cache[cluster]["clusterroles"][crb.roleRef.name]
            cluster_rules.extend(role.rules)
    for rb in informer_cache[cluster]["rolebindings"].values():
        if _matches_user(rb, username, user.groups):
            role = informer_cache[cluster]["roles"][rb.roleRef.name]
            ns_rules[rb.metadata.namespace].extend(role.rules)
    
    return SSOUser(
        spec=...,
        status=EffectivePermissions(
            clusterScoped=dedupe(cluster_rules),
            namespaceScoped={ns: dedupe(rules) for ns, rules in ns_rules.items()},
            blastRadius=compute_blast_radius(cluster_rules, ns_rules),
        )
    )
```

### The `SSOGroup` object (optional, cluster-admin only)

`SSOGroup` is the group-level equivalent. Shows what a specific group can
do across the cluster.

```yaml
# kubectl get ssogroup developers -o yaml
apiVersion: auth.kubedash.io/v1
kind: SSOGroup
metadata:
  name: developers
  namespace: ""
spec:
  groupName: developers
  members: [jdoe, asmith, bjones]   # from OIDC groups + cluster_bindings
  clusterBindings:
    - cluster: production
      role: editor
status:
  effectivePermissions:
    # same shape as SSOUser.status.effectivePermissions
    ...
  memberCount: 3
```

**API surface:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/apis/auth.kubedash.io/v1/sso-groups` | List SSOGroups (cluster-admin only) |
| `GET` | `/apis/auth.kubedash.io/v1/sso-groups/{name}` | Get one SSOGroup |

### Registration (APIService)

The Helm chart creates three `APIService` objects that register the
KubeDash aggregated server with the K8s API server:

```yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1.projects.kubedash.io
spec:
  group: projects.kubedash.io
  version: v1
  service:
    namespace: kubedash
    name: kubedash-aggregated-api
    port: 8443
  groupPriorityMinimum: 100
  versionPriority: 15
  caBundle: <base64 CA cert>       # same CA as the API server
  insecureSkipTLSVerify: false     # mTLS, not insecure
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1.auth.kubedash.io
spec:
  group: auth.kubedash.io
  version: v1
  service:
    namespace: kubedash
    name: kubedash-aggregated-api
    port: 8443
  groupPriorityMinimum: 100
  versionPriority: 15
  caBundle: <base64 CA cert>
  insecureSkipTLSVerify: false
```

The KubeDash container runs a **second listener** on port `8443` (the
aggregated API) in addition to the main API on `8080`. The aggregated
listener:
- Requires a **client certificate** (mTLS) signed by the K8s CA.
- Serves `/apis/projects.kubedash.io/v1/*` and `/apis/auth.kubedash.io/v1/*`.
- Serves `/apis/projects.kubedash.io/v1` (discovery) for the API server
  to merge into its own `/apis` doc.
- Is **read-only** (no POST/PUT/DELETE).

### Helm chart additions

```yaml
# values.yaml
aggregatedAPI:
  enabled: true
  port: 8443
  tls:
    # The aggregated API uses the K8s serving CA for mTLS.
    # The Helm chart generates a keypair + CSR at install time
    # (via a Job) or accepts a pre-generated cert.
    caSecret: kubedash-aggregated-api-ca
    tlsSecret: kubedash-aggregated-api-tls
  # Feature flags
  projects: true        # register projects.kubedash.io
  ssoUsers: true        # register auth.kubedash.io/sso-users
  ssoGroups: true       # register auth.kubedash.io/sso-groups
```

```yaml
# charts/kubedash/templates/aggregated-api-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: kubedash-aggregated-api
  namespace: kubedash
spec:
  ports:
    - port: 8443
      targetPort: 8443
  selector:
    app: kubedash
---
# APIService objects (see above)
```

### Security

| Concern | Control |
|---|---|
| Transport (API server → aggregated) | mTLS. The aggregated server presents a client cert signed by the K8s CA. The API server validates it. |
| Auth (user → aggregated) | The API server proxies the request with the user's credentials (client cert or bearer token). The aggregated server validates via `SelfSubjectAccessReview`. |
| Project list is RBAC-filtered | Each Namespace is checked via `SubjectAccessReview` before inclusion. No leakage. |
| SSOUser/SSOGroup are admin-only | RBAC: `get`/`list` on `sso-users`/`sso-groups` requires `cluster-admin` or `kubedash.io/admin` group. |
| No writes | The aggregated API is read-only. No POST/PUT/DELETE handlers. |
| No data stored | Projects, SSOUsers, SSOGroups are computed on-the-fly. Nothing in etcd. |

### Relationship to the KubeDash main API

The aggregated API is a **thin read-only proxy** that reuses the same
`services/` layer as the main API:

- `services/rbac.py` — `SubjectAccessReview` for Project filtering +
  SSOUser/SSOGroup permission computation.
- `services/k8s_client.py` — informer cache for Namespaces, RBAC objects.
- `db.cluster_bindings` — user↔cluster bindings for SSOUser.

It does **not** duplicate logic. The main API's `/clusters/<id>/resources/
namespaces` endpoint and the aggregated API's `/projects` endpoint call
the same `informer_cache` + `rbac.can()` functions.

### Why an aggregated API (and not just a KubeDash REST endpoint)?

1. **`kubectl get projects`** — users can list their visible namespaces
   without a separate `curl` to the KubeDash API. It shows up in
   `kubectl api-resources`, tab-completion, and every kubectl plugin.
2. **Discovery** — `kubectl get apiservice v1.projects.kubedash.io` shows
   the registration status (Available / NotAvailable).
3. **Standard RBAC** — cluster admins can grant `get projects` via a
   RoleBinding, just like any other K8s resource.
4. **SSOUser/SSOGroup in kubectl** — `kubectl get ssouser jdoe` is a
   one-liner for "what can this user do?" No separate API call.
5. **Ecosystem integration** — any tool that speaks the K8s API
   (kubectl, Lens, Helm, Argo CD) can consume these objects natively.

### ADR

- **ADR-0012** — Aggregated API server for Project + SSOUser + SSOGroup
  (kube-aggregator pattern; read-only, mTLS, RBAC-filtered Projects,
  admin-only SSO objects; no data in etcd)

---

## 6. Observability integration

KubeDash **does not** scrape metrics or ingest logs itself. It is a
**query + display** layer over existing observability backends:

| Signal   | Backend (user-supplied)      | KubeDash role                              |
|----------|------------------------------|--------------------------------------------|
| Metrics  | Prometheus / Thanos / Mimir  | Query + range + embed Grafana dashboards   |
| Logs     | Loki / Elastic / OpenSearch  | Search + tail + pod-level filter           |
| Traces   | Tempo / Jaeger / Zipkin      | Search + waterfall + span detail           |
| Alerts   | Prometheus Alertmanager      | Evaluate + display + dedup (in `alerts`)   |

Backend base URLs + auth come from `observability.<signal>` in config.
A cluster can override the global observability config (useful when each
cluster has its own Prometheus).

---

## 7. Deployment

### 7.1 Container (single image)

- **Base:** Python 3.12 slim, non-root.
- **Multi-stage Dockerfile:**
  1. **Stage 1 (frontend):** Node 20 → `pnpm install` → `vite build` → `dist/`.
  2. **Stage 2 (backend):** Python 3.12 slim → `uv sync` → install deps.
  3. **Stage 3 (runtime):** copy backend + `dist/` → `static/` → non-root
     user → `HEALTHCHECK` on `/healthz` → `CMD gunicorn -w 4 -b 0.0.0.0:8080 wsgi:app`.
- **Gunicorn:** 4 workers × 2 threads (tunable via `GUNICORN_WORKERS` /
  `GUNICORN_THREADS` env). `eventlet` or `gevent` worker class for
  WebSocket support.
- **RQ worker:** spawned as a background thread in `wsgi.py` at startup,
  gated by `KUBEDASH_ROLE=leader`. No separate worker container.

### 7.2 Helm chart

`charts/kubedash/` — one chart, **one Deployment** (N replicas) +
Service + Ingress + ConfigMap + Secret. Optional subcharts:
`postgresql` (bitnami), `redis` (bitnami) for all-in-one dev; in prod,
external PG + Redis via `values.yaml`.

Key `values.yaml`:

```yaml
replicaCount: 3            # N replicas; leader election picks 1
image:
  repository: ghcr.io/org/kubedash
  tag: v1.0.0
gunicorn:
  workers: 4
  threads: 2
leaderElection:
  heartbeatInterval: 10s   # how often leader renews lease
  staleThreshold: 30s      # how long before a follower takes over
auth:
  oidc:
    issuer: https://login.example.com
    clientId: kubedash
    clientSecret: from-secret
features:
  exec: true                 # terminal / debug shell
  helmWrite: true            # helm upgrade / rollback / uninstall
  terminal: true             # local host terminal (in-cluster mode)
  mcp: true                  # MCP server for AI agents
cluster:
  contextSwitchTimeout: 30s
  firstPaintBackstop: 5m
  namespaceListTimeout: 5s
  maxScopeCandidates: 20
  listPageSize: 0
  namespaceScope: false
timeline:
  storage: postgres          # memory | postgres
  retention: 90d
mcp:
  enabled: true
  trustedOrigins: []         # extra origins allowed to call /mcp
postgresql:
  enabled: true            # set false in prod (external PG)
redis:
  enabled: true            # set false in prod (external Redis)
```

### 7.3 CI/CD (GitHub Actions)

- **PR** — lint (ruff, eslint), typecheck (mypy, tsc), unit tests, build
  (frontend + backend), Trivy scan.
- **main** — + E2E on `kind`, publish dev image to GHCR.
- **tag `v*`** — + Helm package, publish release image to GHCR.

### 7.4 K8s install (target cluster)

The Helm chart deploys KubeDash into the user's cluster. Ingress (or
`LoadBalancer` Service) exposes the UI + API on a single port. OIDC is
configured via `values.yaml` (`auth.oidc.issuer`, `auth.oidc.clientId`,
`auth.oidc.clientSecret`). The chart creates a dedicated namespace +
`ServiceAccount` with a **minimal** RBAC (read-only on `pods`, `events`,
`namespaces`, `services`; write only on resources the user has bound).

Each replica gets a unique `KUBEDASH_REPLICA_ID` via the K8s Downward API
(`metadata.name` of the Pod). All replicas are `KUBEDASH_ROLE=leader`
(candidates); the leader election module decides which one actually runs
the RQ worker.

### 7.5 Tuning for slow / high-latency clusters

Enterprise clusters reached over SSH tunnels, distant regions, or throttled
API servers need wider deadlines. These are Helm `values.yaml` keys (mapped
to env vars on the Deployment):

| values.yaml key | Env var | Default | Purpose |
|---|---|---|---|
| `cluster.contextSwitchTimeout` | `KUBEDASH_CONTEXT_SWITCH_TIMEOUT` | `30s` | Max time a kubeconfig context switch may take |
| `cluster.firstPaintBackstop` | `KUBEDASH_FIRST_PAINT_BACKSTOP` | `5m` | Hard cap on initial informer-cache sync before partial render |
| `cluster.namespaceListTimeout` | `KUBEDASH_NAMESPACE_LIST_TIMEOUT` | `5s` | Timeout for cluster-wide namespace LIST (RBAC scope detection) |
| `cluster.maxScopeCandidates` | `KUBEDASH_MAX_SCOPE_CANDIDATES` | `20` | Cap on namespace-fallback probe fan-out |
| `cluster.listPageSize` | `KUBEDASH_LIST_PAGE_SIZE` | `0` (off) | Paginate initial LIST of high-cardinality kinds (Pods, RS) for very large clusters |
| `cluster.namespaceScope` | `KUBEDASH_NAMESPACE_SCOPE` | `false` | Pin informer cache to a single namespace (large clusters) |

The UI renders **partial data with a "syncing…" indicator** when the
first-paint backstop elapses, rather than hanging on a spinner.

### 7.5.1 Ingress Auth Integration

OpenUnison is an ingress-native SSO solution: it ships integrations for
NGINX, Traefik, F5, Istio, and the Gateway API, where the **ingress
controller** authenticates the request and forwards the user's identity to
the backend. KubeDash adopts the same pattern so that (a) KubeDash-protected
*other* applications (Headlamp, Argo CD, Grafana, Vault) can be secured by the
ingress using KubeDash as the auth authority, and (b) KubeDash's own UI can
optionally have the ingress terminate auth and forward identity headers.

**The mechanism:** KubeDash exposes a **subrequest verification endpoint**
that ingress controllers call via `auth_request` (NGINX), `forwardauth`
(Traefik), or `ext_authz` (Istio / Envoy Gateway). The endpoint validates the
request's credential and returns `200` + identity headers on success, `401`
on failure. The ingress then forwards the identity headers to the backend,
which trusts them (they are set by the ingress, not the client).

**The verify endpoint:**

```
GET /auth/verify?cluster=<name>      # called by the ingress (subrequest)
  # Accepts: Authorization: Bearer <kubedash-jwt>   (KubeDash-issued JWT)
  #          OR a KubeDash session cookie
  # Returns 200 on success with headers:
  #   X-Remote-User:   <username>
  #   X-Remote-Groups: <group1,group2,...>
  #   X-Remote-Cluster:<cluster>        (if cluster-scoped)
  # Returns 401 on failure (no header)
```

The endpoint is **not** a full API call — it performs only JWT/cookie
verification + a `users` lookup. It is rate-limited and unauthenticated in
the sense that it is called by the ingress (mTLS or a shared
`X-Auth-Request-Auth` token between ingress and KubeDash, configurable).

**Per-ingress-controller integration:**

| Controller | Mechanism | Config (Helm annotation / value) |
|---|---|---|
| **NGINX Ingress** | `auth_url` / `auth_request` subrequest | `nginx.ingress.kubernetes.io/auth-url: https://kubedash.example.com/auth/verify`, `auth-signin: /auth/login`, `auth-response-headers: X-Remote-User,X-Remote-Groups` |
| **Traefik** | `forwardauth` middleware | `traefik.ingress.kubernetes.io.middleware: kubedash-auth@kubernetescrd` → a `Middleware` of type `forwardAuth` pointing at `/auth/verify`, `authResponseHeaders: X-Remote-User,X-Remote-Groups` |
| **Istio** | `ext_authz` (Envoy external authorization) | An `EnvoyFilter`/`ExtensionProvider` pointing the `ext_authz` gRPC/HTTP service at KubeDash's `/auth/verify`; allowed headers `X-Remote-User`, `X-Remote-Groups` |
| **Gateway API** | `HTTPRoute` + `BackendRef` to an `ext_authz`-capable gateway class (Envoy Gateway) | Envoy Gateway `HTTPRoute` with `backendRefs` to the auth service; or an `APIRoute` filter |

**Identity propagation to backends:** once the ingress has validated and
set `X-Remote-User` / `X-Remote-Groups`, the protected backend (KubeDash UI,
Headlamp, Argo CD, etc.) reads those headers and acts on that identity. For
KubeDash's own UI, the backend re-verifies the JWT directly (the headers are
a convenience, not the sole trust anchor — the UI's own JWT is still
checked). For *external* backends that cannot verify KubeDash JWTs
themselves, the ingress-forwarded headers are the identity, and KubeDash
optionally signs them (an `X-Auth-Signature` header, HMAC with a shared
secret) so a compromised ingress cannot forge them.

**Which applications to secure:** the same list OpenUnison covers —
Headlamp, Argo CD, Kiali, Grafana, Vault, plus any OIDC-capable app. KubeDash
does **not** re-implement each app's auth; it is the **auth authority** the
ingress asks, and the apps receive the forwarded identity.

**Security:**

| Concern | Control |
|---|---|
| Ingress → KubeDash (verify call) | mTLS, or a shared `X-Auth-Request-Auth` token (Helm secret). Not open to clients. |
| Client → ingress | TLS (cert-manager / external). The client presents a KubeDash JWT or session cookie. |
| Header forgery | Backends re-verify the JWT where possible; `X-Auth-Signature` (HMAC) for backends that rely on headers only. The ingress is the only party that may set `X-Remote-*`. |
| Revocation | The verify endpoint checks the same Redis `jti` revocation set as the main API (§ 5B.1), so logout is honoured at the ingress too. |
| Rate limiting | The verify endpoint is rate-limited (it is on the hot path of every request to protected apps). |

**Helm values:**

```yaml
# values.yaml
authIntegration:
  enabled: true
  verifyEndpoint: /auth/verify
  # Shared token the ingress presents on the verify call (mTLS alternative)
  requestAuthSecret: kubedash-auth-request-token
  # Sign forwarded headers with HMAC (for header-trusting backends)
  signHeaders: true
  headerSigningSecret: kubedash-header-signing-secret
  # Example ingress annotations rendered as a ConfigMap / docs
  ingress:
    controller: nginx        # nginx | traefik | istio | gateway
```

**ADR:** ADR-0019.

### 7.6 kubectl credential plugin (`kubectl kubedash`)

KubeDash ships a **Go-based kubectl credential plugin** that lets users
authenticate to Kubernetes clusters via the KubeDash OIDC SSO — without
putting any SSO config in their kubeconfig. This is the CLI counterpart
to the web UI's login flow.

**Blueprint:** `.skillgrid/specs/2026-10-17-kubectl-oidc-plugin/blueprint.md`

#### The security problem it solves

`kubelogin` (the dominant OSS kubectl OIDC plugin) puts **all SSO config
in the kubeconfig**:

```yaml
# kubelogin-style kubeconfig (the problem)
users:
  - name: oidc
    user:
      exec:
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://accounts.google.com   # ← visible
          - --oidc-client-id=123456789.apps.googleusercontent.com  # ← visible
```

Since `~/.kube/config` is 0644 by default, anyone who reads it learns the
IdP + OAuth app (reconnaissance). Rotating the `client_id` or migrating
IdPs requires editing every user's kubeconfig.

**KubeDash's answer:** the kubeconfig contains **only** the KubeDash
server URL and the cluster name. The plugin fetches SSO config from the
server at auth time. The user never sees the issuer, client_id, or scopes.

```yaml
# KubeDash kubeconfig (what the user sees)
users:
  - name: kubedash
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - kubedash
          - get-token
          - --server=https://kubedash.example.com   # ← only the server
          - --cluster-name=production               # ← only the cluster
```

#### How it works

```
kubectl get pods
    │
    ▼ (exec credential plugin)
kubectl-kubedash get-token --server=... --cluster-name=...
    │
    ├── 1. GET /kubectl/auth/v1/config?cluster=production
    │      → {issuer, client_id, token_url, auth_url, scopes, expiry}
    │      (unauthenticated endpoint; TLS + rate-limited; config is
    │       not secret in a PKCE flow)
    │
    ├── 2. Check token cache (OS keyring → 0600 file fallback)
    │      ├── valid → return ExecCredential (no browser)
    │      ├── expired + refresh_token → silent refresh (no browser)
    │      └── expired + no refresh / refresh failed → browser flow
    │
    ├── 3. OIDC Authorization Code + PKCE (S256)
    │      ├── Generate code_verifier + code_challenge
    │      ├── Bind HTTP listener to 127.0.0.1:0 (ephemeral port)
    │      ├── Open browser to auth_url + PKCE params + state
    │      ├── User logs in at the IdP
    │      ├── IdP redirects to http://127.0.0.1:PORT/cb?code=&state=
    │      ├── Validate state, extract code
    │      └── POST token_url with code + code_verifier
    │           → {id_token, refresh_token, expires_in}
    │
    ├── 4. Cache tokens in OS keyring (service="kubedash", user=cluster)
    │
    └── 5. Print ExecCredential JSON to stdout
           {
             "apiVersion": "client.authentication.k8s.io/v1",
             "kind": "ExecCredential",
             "status": {
               "username": "<sub claim>",
               "expirationTimestamp": "2026-10-17T12:00:00Z",
               "token": "<id_token JWT>"
             }
           }
    │
    ▼
kubectl sends the ID token to the K8s API server
    │
    ▼
K8s API server validates: iss, aud, signature (against IdP JWKS)
    → accepts or rejects
```

**The server is a proxy, not the trust anchor.** The K8s API server
validates the ID token's `iss`, `aud`, and signature directly against the
IdP's JWKS endpoint. KubeDash is the config broker and token relay, but
the trust chain is: **IdP → K8s API server**.

#### Architecture

| Component | Location | Language | Role |
|---|---|---|---|
| `kubectl-kubedash` binary | `cli/` | Go 1.22+ | Thin client: fetch config, PKCE flow, cache, output |
| `GET /kubectl/auth/v1/config` | `backend/app/api/kubectl_auth.py` | Python (Flask-Smorest) | Serve SSO config per cluster |
| `kubectl_auth` service | `backend/app/services/kubectl_auth.py` | Python | Resolve cluster → AuthConfig |
| SSO config source | Helm `ConfigMap` → env | YAML/JSON | Admin configures once, no per-user edits |
| Token cache | OS keyring (or 0600 file) | — | ID + refresh tokens, per-cluster |

**Go dependencies:** `cobra` (CLI), `golang.org/x/oauth2` +
`coreos/go-oidc/v3` (OIDC), `github.com/zalando/go-keyring` (keyring),
`github.com/pkg/browser` (open browser), `k8s.io/client-authentication`
(ExecCredential types).

**Build:** single static binary, `CGO_ENABLED=0`, cross-compiled for
macOS (amd64, arm64), Linux (amd64, arm64), Windows (amd64). Distributed
via Krew (`kubectl krew install kubedash`), Homebrew, Chocolatey, and
GitHub Releases (with SHA256 checksums).

#### Server endpoint

`GET /kubectl/auth/v1/config?cluster=<name>` — **unauthenticated** (the
plugin is bootstrapping auth and has no token yet). Protected by TLS +
rate-limiting. The response is not secret: in a PKCE public-client flow,
`issuer` + `client_id` are public by design.

```python
# backend/app/api/kubectl_auth.py
class KubectlAuthApi(Api):
    resources_namespace = "kubectl_auth"
    tags = ["Kubectl Auth"]

    @blp.route("/kubectl/auth/v1/config", methods=["GET"])
    @blp.arguments(ClusterQuery)
    @blp.response(HTTPStatus.OK, AuthConfig)
    @blp.response(HTTPStatus.NOT_FOUND, "CLUSTER_NOT_FOUND")
    def get_config(self, args):
        return kubectl_auth.get_auth_config(args.cluster)
```

```python
# backend/app/schemas/kubectl_auth.py
class AuthConfig(BaseModel):
    issuer: str          # "https://login.example.com"
    client_id: str       # "kubedash-prod"
    token_url: str
    auth_url: str
    scopes: list[str]    # ["openid", "email", "profile"]
    expiry: int          # 3600 (seconds)
```

**Versioned at `/v1/`** — the response shape is a plugin↔server contract.
Breaking changes bump the major version.

#### Admin configuration (Helm)

```yaml
# values.yaml
kubectlAuth:
  enabled: true
  clusters:
    production:
      issuer: https://login.example.com
      clientId: kubedash-prod
      scopes: [openid, email, profile]
      expiry: 3600
    staging:
      issuer: https://login-staging.example.com
      clientId: kubedash-staging
      scopes: [openid, email]
      expiry: 1800
```

The admin registers a **public OIDC client** with the IdP (redirect URI:
`http://127.0.0.1/callback` or a range of loopback URIs), configures the
K8s API server's `--oidc-*` flags to match, and sets the Helm values.
Rotating the `clientId` or migrating IdPs is a **server-side change** —
no user kubeconfig edits.

#### Security properties

| Property | How |
|---|---|
| No SSO config in kubeconfig | Only `--server` + `--cluster-name` in `exec.args` |
| PKCE (S256) | Public client; no `client_secret` sent by the plugin |
| Loopback redirect only | `http://127.0.0.1:PORT/cb` (ephemeral port, bound to 127.0.0.1) |
| CSRF protection | `state` parameter (16 random bytes, validated on callback) |
| Token at rest | OS keyring (encrypted by the OS); fallback 0600 file |
| Token in transit (plugin→kubectl) | stdout pipe (not a shared medium); no token logging |
| TLS to server | System CA store validation; `--insecure-skip-tls-verify` warns |
| Server is not the trust anchor | K8s API server validates `iss` + `aud` + signature against IdP JWKS |
| Binary integrity | Krew (checksummed), SHA256 in GitHub Releases |
| Concurrent `get-token` | File lock / keyring CAS; second call reads the cache |

#### User installation

```bash
# Krew (recommended)
kubectl krew install kubedash

# Homebrew
brew install kubedash

# Or: download from GitHub Releases, save as kubectl-kubedash on $PATH
```

Add to `~/.kube/config`:

```yaml
users:
  - name: kubedash
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
        args:
          - kubedash
          - get-token
          - --server=https://kubedash.example.com
          - --cluster-name=production
```

Run `kubectl get pods` → browser opens → log in → done. Subsequent
calls are silent (cached token). `kubectl kubedash clean` removes the
cached token.

### 7.7 Air-Gap Deployment

OpenUnison documents a first-class **air-gap** mode: KubeDash runs in
network-isolated environments (defense, financial, OT/IT-converged,
regulated) where there is **no outbound internet** at runtime. The goal:
KubeDash installs and operates with **zero external calls at runtime** —
no phoning home, no IdP round-trip per request, no image pulls, no telemetry.

**What "air-gap" requires:**

1. **No outbound IdP call per request.** The proposed architecture already
   issues **local JWTs** (HS256, signed by `KUBEDASH_JWT_SECRET`), so the
   hot path (every request) never contacts the IdP. The IdP is only reached
   during the **login** and **refresh** flows. In air-gap mode the IdP is
   assumed to be **on the internal network** (an on-prem Keycloak/Okta/AD
   federation), so login still works — KubeDash just never reaches the
   *internet*.
2. **JWKS / IdP metadata cached offline.** OIDC discovery
   (`/.well-known/openid-configuration`) and the IdP's JWKS are fetched once
   and **cached** (Postgres + a local file). In air-gap mode KubeDash uses
   the cached metadata; it does not re-discover on every start. An admin can
   push updated JWKS via a file mount or a one-time import when the IdP
   rotates keys.
3. **Images pre-loaded.** The Helm chart uses `imagePullPolicy: IfNotPresent`
   and the operator loads images into the cluster's registry (or as
   `docker save`/`kind load` artifacts) **before** the air gap. No runtime
   pulls. The KubeDash image, PG, Redis, and any optional subcharts are all
   in the air-gap image bundle.
4. **CLI / kubectl plugin offline.** The `kubectl kubedash` binary is
   distributed as a file (not via Krew's network fetch); `kubectl kubedash
   get-token` talks only to the KubeDash server (internal), which talks only
   to the internal IdP. No internet.
5. **Observability backends optional / internal.** Prometheus/Loki/Tempo are
   user-configured internal endpoints; if absent, KubeDash degrades (no
   metrics pane) but still serves clusters. No external telemetry.
6. **Helm repos offline.** Chart + dependency charts are vendored into the
   air-gap bundle; `helm install` uses the local `Chart.yaml`/tars, not a
   remote repo.

**Air-gap install path:**

```
1. (online staging) Build the air-gap bundle:
   - KubeDash image + PG + Redis + (optional) observability images → .tar
   - Helm chart + subcharts → .tgz
   - kubectl kubedash binary (5 OS/arch) → .tar.gz
   - IdP metadata + JWKS snapshot (if not on internal net) → .json
2. (air-gap) Load images into the registry:
   - krictl load / kind load / docker load per image
3. (air-gap) Install:
   - helm install kubedash ./kubedash-<ver>.tgz \
       --set airGap.enabled=true \
       --set auth.oidc.issuer=https://sso.internal.example  # internal IdP
       --set auth.oidc.jwksFile=/etc/kubedash/jwks.json      # cached JWKS
4. (air-gap) Verify:
   - /readyz shows DB + Redis + one cluster reachable + leader
   - login via the internal IdP works
   - kubectl kubedash get-token works (browser → internal IdP → token)
```

**Helm values:**

```yaml
# values.yaml
airGap:
  enabled: false            # true in air-gap deployments
  # When true:
  #   - imagePullPolicy: IfNotPresent on all containers
  #   - OIDC discovery/JWKS served from the mounted file (no live discovery)
  #   - No external DNS required beyond the cluster + internal IdP
  jwksSecret: kubedash-oidc-jwks   # mounted at /etc/kubedash/jwks.json
  # The IdP is still required (on the internal network); air-gap ≠ no-IdP.
  # A pure "no IdP" mode (local users + local password) is a separate,
  # deferred option (§ 11).
```

**What is NOT covered by air-gap (deferred, § 11):**

- **No-IdP mode** — local username/password auth when there is no IdP at
  all (not just no internet). This needs a local user store + password
  hashing + a local token issuer. Deferred.
- **Helm chart auto-update** — in air-gap, charts are re-bundled manually.
  No auto-update.
- **Plugin auto-update** — the kubectl binary is re-distributed manually.

**Security / operational:**

| Concern | Control |
|---|---|
| No outbound calls at runtime | Only the internal IdP (login/refresh) + the K8s API servers + internal observability. Verified by a `airGap.outboundCheck` that fails `/readyz` if an unexpected external egress is attempted. |
| JWKS rotation | Admin re-mounts the JWKS file; KubeDash hot-reloads on file change (no restart). |
| Image supply chain | Air-gap bundle is signed (cosign) and verified at load time. |
| Certificate management | The aggregated API's mTLS CA + the IdP's CA are bundled in the install; no runtime cert fetch. |

**ADR:** ADR-0020.

---

## 7A. Feature Roadmap (informed by Radar)

KubeDash is a **web app** (in-cluster, multi-user, Helm-deployed) — not a
desktop or laptop tool. Distribution and onboarding follow the standard
Helm + Ingress path (§ 7). The feature set below is informed by
[skyhook-io/radar](https://github.com/skyhook-io/radar) (3.8k stars,
"the missing open-source Kubernetes UI") and adapted to KubeDash's
multi-cluster, Python/Flask, web-first architecture.

### High priority (differentiators — target v1.0)

1. **Topology view** — interactive graph of resource relationships
   (Service → Deployment → Pod, Ingress → Service, PVC → Pod). Two modes:
   **Resources** (full hierarchy) and **Traffic** (network flow, when a
   traffic source is detected). Group by namespace or app label.
   - Frontend: **Cytoscape.js** (or ELK.js for auto-layout). Live updates
     via SSE.
   - Backend: new `services/topology.py` — builds the graph from the
     informer cache (labels, selectors, endpoints, routes). No extra API
     calls.
   - New Smorest `Api`: `topology` → `/clusters/<id>/topology`.
   - New view: `src/views/Topology/`.

2. **Event / change timeline** — unified, real-time timeline of K8s events
   + resource diffs ("who changed what, when"). The core "what's broken,
   why, what changed" value prop.
   - Backend: `services/timeline.py` — watches K8s `Event` objects (via
     informer) + diffs resource changes (informer compare). Stores in
     `audit_log` (Postgres) with a ring-buffer in Redis for the last 24 h.
   - Pluggable storage: **memory** (dev, last 10k events) → **Postgres**
     (prod, pruned at 90 d). Config: `timeline.storage: memory|postgres`.
   - Frontend: `src/views/Timeline/` — virtualised list (react-window),
     filter by type (all / warnings only), resource-diff drawer.
   - SSE stream: `/ws/timeline` (or SSE `/events/timeline`).

3. **Helm release management** — list releases, inspect values + rendered
   manifests, diff revisions, upgrade / rollback / uninstall, detect
   failed upgrades + stuck hooks.
   - Backend: `services/helm.py` — shells out to `helm` (bundled in the
     image) or uses `helm-shell` / `helm` SDK. Read ops: `helm list`,
     `helm get values/manifest/history`. Write ops: `helm upgrade`,
     `helm rollback`, `helm uninstall` (gated by RBAC + `--disable-helm-write`
     flag).
   - New Smorest `Api`: `helm` → `/clusters/<id>/helm/releases`.
   - New view: `src/views/Helm/` — DataTables list, revision diff (side-by-side),
     upgrade/rollback modal with dry-run preview.

4. **GitOps (ArgoCD + FluxCD)** — fleet view showing all Argo/Flux apps
   side-by-side with sync/health/source state. Per-app detail: Topology /
   Changes / Activity tabs.
   - Backend: `services/gitops.py` — reads ArgoCD `Application`,
     `ApplicationSet`, `AppProject` CRDs + FluxCD `GitRepository`,
     `HelmRelease`, `Kustomization` CRDs via the dynamic client. Drift
     detection: compare `status.desiredState` vs `status.currentState`.
   - **Diagnosis pipeline**: field-level drift, recent events per resource,
     stuck-drift-loop detection, parsed operation failures, one-click
     remediation (sync / suspend / resume / rollback).
   - **Lifecycle awareness**: `Terminating` chip replaces stale Sync/Health
     badges; mutating ops refuse on terminating apps.
   - New Smorest `Api`: `gitops` → `/clusters/<id>/gitops/apps`.
   - New view: `src/views/GitOps/` — fleet table (DataTables), per-app
     detail with tabs.

5. **MCP server for AI agents** — built-in [Model Context Protocol](https://modelcontextprotocol.io)
   endpoint (`/mcp`) that lets Claude Code, Cursor, Copilot, OpenCode, etc.
   inspect and operate the cluster with **token-optimized data** (not raw
   YAML).
   - Read-only by default: topology, resource state, events, logs, RBAC,
     audit findings, GitOps status.
   - Write ops (restart, scale, apply, rollback) are **identified for
     client confirmation** and enforced through K8s RBAC.
   - Backend: `app/mcp/` — MCP tool definitions + handlers. Reuses the same
     `services/` layer (no duplication).
   - Tools exposed: `get_topology`, `get_resource`, `list_events`,
     `get_logs`, `get_rbac`, `get_audit`, `get_gitops_status`,
     `diagnose_network`, `manage_gitops` (write), `scale_deployment`
     (write).
   - Config: `mcp.enabled: true`, `mcp.trusted_origins: [...]`.

### Medium priority (target v1.1–v1.2)

6. **Cluster audit** — 44+ best-practices checks (security, reliability,
   efficiency) running **against the informer cache** (zero cluster-side
   install). Inspired by Polaris, Kubescape, Trivy, NSA/CISA.
   - Security: privileged containers, privilege escalation, dangerous
     capabilities, host namespaces, runtime socket mounts, sensitive host
     paths, secrets in ConfigMaps, auto-mounted SA tokens.
   - Reliability: missing probes, `latest` tag, single-replica deployments,
     missing PDB / topology spread, pod HA risk, orphan services/ingresses,
     deprecated API versions.
   - Efficiency: missing CPU/mem requests+limits, orphan ConfigMaps/Secrets,
     PVCs with no consumer, long-Pending PVCs, Released PVs retained.
   - Each finding: description, remediation guidance, severity
     (error/warning/info), framework label (CIS, NSA/CISA, Polaris).
   - Configurable: ignored namespaces (wildcard patterns), disabled checks,
     per-resource opt-out via annotation
     (`kubedash.io/ignore-checks: check1,check2`).
   - Backend: `services/audit.py` — pure functions over the informer cache.
     Runs as an RQ task (leader-only, every 5 min) + on-demand.
   - New Smorest `Api`: `audit` → `/clusters/<id>/audit`.
   - New view: `src/views/Audit/` — check-grouped remediation queue,
     DataTables with severity/category/framework filters, expand for
     affected resources.

7. **Compare resources** — side-by-side YAML diff of two resources of the
   same kind (staging vs prod Deployment, two pods that should be
   identical).
   - Entry points: "Compare" button in resource detail drawer, or compare
     mode in the resource table (toggle, pick two rows, hit Compare).
   - Side-by-side or unified view, one-click swap A ↔ B, diff-only mode
     (collapse unchanged regions), spec-only mode (drop `status`).
   - Server-assigned noise stripped: `managedFields`, `resourceVersion`,
     `kubectl.kubernetes.io/last-applied-configuration`. "Raw metadata"
     toggle to re-enable.
   - Shareable URL: `/clusters/<id>/compare?kind=&a=ns/name&b=ns/name`.
   - Frontend: `src/views/Compare/` — uses Monaco's diff editor
     (`monaco-editor` diff mode). No backend endpoint needed (client-side
     diff of two fetched resources).

8. **TLS certificate expiry** — parse TLS secrets, show certificate
   subject, issuer, validity period. Dashboard-level expiry overview
   (7 d / 30 d / 90 d buckets). Alert before outage.
   - Backend: `services/tls.py` — parses `tls.crt` / `tls.key` from
     `kubernetes.io/tls` secrets. Runs as RQ task (leader, daily) +
     on-demand.
   - New Smorest `Api`: part of `audit` or standalone `tls` →
     `/clusters/<id>/tls/certificates`.
   - New view: `src/views/TLS/` — DataTables of certs with expiry,
     colour-coded (red < 7 d, amber < 30 d, green > 30 d).

9. **Cost insights** — read OpenCost / Kubecost metrics from Prometheus.
   Allocated workload cost, namespace breakdown, efficiency scoring,
   node costs with instance type + region pricing.
   - Backend: `services/cost.py` — PromQL queries against the configured
     Prometheus (reuses `services/prometheus.py`). Auto-detects OpenCost
     vs Kubecost metric families.
   - New Smorest `Api`: `cost` → `/clusters/<id>/cost/summary`,
     `/clusters/<id>/cost/trend`.
   - New view: `src/views/Cost/` — Chart.js trend charts (6 h / 24 h /
     7 d), DataTables for namespace/workload breakdown, efficiency score
     badges.

10. **Network path diagnose** — "if traffic goes to this Ingress /
    HTTPRoute / Service, does it reach a healthy process, and which hop
    breaks first?"
    - Composes existing detections: missing backend Service, port
      mismatches, no-ready-endpoints, route not Accepted by parent
      Gateway, readiness probe targeting wrong port.
    - Hop-ordered path (Ingress → Service → Endpoints → Pod). First
      critical hop named explicitly. Each finding ships a `kubectl`
      reproducer.
    - **Optional live probe**: DNS / TCP / TLS / HTTP against the declared
      path. In-cluster: direct TCP. Out-of-cluster: K8s API server proxy
      (`get pods/proxy`). Probes add evidence, never override the static
      verdict.
    - **NetworkPolicy prediction**: statically evaluate NP ingress rules
      for the path's port. "Would block" WARNING prediction (CNI is the
      enforcement authority; live probe confirms).
    - Backend: `services/network_path.py` — pure functions over the
      informer cache + optional probe runner.
    - New Smorest `Api`: part of `resources` detail →
      `/clusters/<id>/resources/<kind>/<ns>/<name>/reachability`.
    - Frontend: "Reachability" tab in the resource detail drawer.

### Lower priority (defer — target v1.3+)

11. **Karpenter capacity diagnosis** — read-only "why is my pod pending,
    which NodePool could take it, what is disruption doing to my fleet?"
    Appears automatically when Karpenter NodePools are detected.
    - Overview: fleet KPIs, scheduling-capacity bar (requests vs
      allocatable), pending demand, NodePool inventory.
    - NodePool detail: capacity ledger, claim lifecycle, fleet composition.
    - Demand: pending pods grouped by scheduling signature, evaluated
      against every NodePool's constraints with per-predicate evidence.
    - Activity: provisioning / disruption / interruption episodes.
    - Every quantity carries per-value certainty (`= ≥ ≤ ?`) — unavailable
      is never rendered as zero.
    - Backend: `services/karpenter.py` — reads Karpenter CRDs
      (`NodePool`, `EC2NodeClass`, `NodeClaim`) via dynamic client.
    - New view: `src/views/Capacity/`.

12. **Kubernetes upgrade impact** — pre-upgrade compatibility checks.
    Compare current cluster with a target minor; order evidenced
    compatibility, health, admission, drain, runtime, config checks by
    required action.
    - Finds blockers: skipped minor versions, APIs removed in target,
      unsupported kubelet/kube-proxy skew, overlapping PDBs, removed
      feature gates, `gitRepo` volume driver (1.36), etc.
    - Distinguishes **Passed / Review / Warning / Blocked / Incomplete /
      Not applicable** (not a single "ok/warn" state).
    - Backend: `services/upgrade_impact.py` — static catalog of checks per
      K8s minor (curated, versioned with the codebase).
    - New view: `src/views/UpgradeImpact/` — Checks tab with target
      version picker.

13. **Image filesystem viewer** — browse a container image's filesystem
    without pulling it locally or exec-ing into a container.
    - Tree view with file sizes, permissions, symlink targets. Search by
      filename. Download individual files.
    - Works with public + private registries (uses cluster
      ImagePullSecrets). Disk-based layer caching.
    - Backend: `services/image_fs.py` — shells out to `umoci` or `crane`
      (bundled in the image) to inspect layers.
    - Frontend: `src/views/ImageFS/` — tree component, lazy-loaded.

14. **Live traffic visualization** — Hubble (Cilium), Istio, Beyla, or
    Caretta integration. Animated flow graph showing requests/sec between
    services. Filter by namespace, protocol, status code.
    - Auto-detects the traffic source. Setup wizard if none detected.
    - Built for large clusters: hidden traffic filtered at the source,
      bounded window, "how much of the window does this cover" label.
    - Backend: `services/traffic.py` — queries Hubble API / Istio
      (via Envoy stats in Prometheus) / Beyla (via Prometheus).
    - Frontend: `src/views/Traffic/` — Cytoscape.js animated edges,
      flow list table.

### Architectural lessons from Radar (apply to existing sections)

These are not new features — they change **how** existing components work.

- **Informer-based cache** (replaces per-request API calls). `k8s_client.py`
  maintains a long-lived watch per resource kind, cached in memory
  (per-cluster dict). The UI reads from the cache; mutations go through the
  API + update the cache on the watch event. This is why Radar is "fast on
  big clusters." → Update § 3.3.
- **SSE as the primary push channel** (not WebSocket). Server→client
  streams (events, timeline, topology updates, log tail) use **SSE**
  (`/events/<type>?cluster=&ns=&since=`). WebSocket is reserved for
  **bidirectional** cases only (exec / terminal). SSE is simpler,
  stateless, HTTP-native, load-balancer-friendly. → Update § 3.6.
- **RBAC visibility view** — "what can this ServiceAccount actually do?"
  Effective permissions (deduplicated), inherited grants via groups,
  blast-radius alerts (wildcards, cluster-admin, `create pods`
  cluster-wide). "My Permissions" panel via `SelfSubjectRulesReview`.
  Read-only first; in-UI edits deferred. → New view + `services/rbac.py`
  extension.
- **Feature flags for attack surface** — `--disable-exec`,
  `--disable-helm-write`, `--disable-local-terminal` equivalents in
  `values.yaml`: `features.exec: true`, `features.helmWrite: true`,
  `features.terminal: true`. → Update § 7.2.
- **Air-gap ready** — no phoning home, no telemetry by default. All
  external calls (Prometheus, Loki, Helm repos) are user-configured.
  → Update § 8.

---

## 8. Security

| Concern              | Control                                                    |
|----------------------|------------------------------------------------------------|
| Transport            | TLS at ingress (cert-manager optional); HSTS on UI         |
| AuthN                | OIDC SSO; short-lived JWT (15 min) in an HttpOnly cookie (or Bearer for API clients); rotating refresh tokens |
| AuthZ                | K8s RBAC proxy via SubjectAccessReview; per-cluster bindings |
| Secrets              | kubeconfigs AES-256-GCM encrypted at rest; JWT + encryption keys in env |
| Injection            | Pydantic validation on all inputs; SQLAlchemy parameterised; no raw SQL |
| CSRF                 | Session cookies are `SameSite=Lax` (access) / `Strict` (path-scoped refresh), JSON-only state-changing endpoints, no state-changing GETs (ADR-0025) |
| CORS                 | Locked to the UI origin (env `CORS_ORIGINS`)               |
| Rate limiting        | Flask-Limiter, per-IP + per-user (storage backend to be re-pointed off Redis at implementation — ADR-0029/0030 remove Redis as a stateful dep) |
| Audit                | Every mutating request → `audit_log` (who/what/when/diff)  |
| Dependencies         | `pip-audit` + `npm audit` in CI; Dependabot enabled         |
| Images               | Slim base, non-root, SCANNED (Trivy) in CI                  |
| Leader election      | PG advisory lock + `leader_lease` table + strict `fence` token (ADR-0031); no split-brain (single logical leader, fenced under active-active) |

---

## 9. Testing strategy

| Layer        | Tooling                              | Coverage target |
|--------------|--------------------------------------|-----------------|
| Unit         | pytest + pytest-asyncio              | ≥ 80 % services |
| API          | pytest + Flask test client + Testcontainers (PG, Redis, kind) | ≥ 90 % Smorest `Api` classes |
| Integration  | kind cluster + real K8s objects      | core CRUD + RBAC + logs + metrics |
| E2E          | Playwright + Helm + kind             | 5 golden user journeys |
| Performance  | k6 (load) — 500 concurrent users on `/clusters` list | p95 < 500 ms |
| Security     | Trivy (images + deps), bandit (Py), eslint-plugin-security (TS) | 0 criticals |
| Leader elect | pytest — kill leader, verify failover < 15 s, no duplicate tasks | 100 % scenarios |

**Testcontainers** is the default for DB + Redis fixtures. A shared
`kind` cluster fixture (via `kind.load_docker_image`) is used for
integration tests; it is torn down per-test-file, not per-test, for speed.

---

## 10. Conventions

- **Python** — 3.12, `ruff` (lint + format), `mypy --strict`, `uv` for deps,
  snake_case, type hints everywhere.
- **TypeScript** — strict mode, `eslint` + `prettier`, `pnpm` for deps,
  PascalCase components (matches CoreUI template convention), camelCase
  functions, kebab-case files.
- **Styling** — CoreUI SCSS variables + `@coreui/coreui` utility classes.
  No Tailwind. Custom theme overrides go in `src/scss/` (template
  convention). Dark mode via CoreUI's built-in `[data-theme="dark"]`.
- **Icons** — Font Awesome Free (`@fortawesome/fontawesome-free`). K8s
  resource icons use `fa-solid` variants; status indicators use
  `fa-circle` with color classes.
- **Git** — Conventional Commits, trunk-based with short-lived feature
  branches, PRs require 1 review + green CI.
- **API versioning** — `/api/v1/*` from day one. Breaking changes bump the
  major version. Old versions are kept for one major cycle.
- **API docs** — OpenAPI 3.0 auto-generated by Flask-Smorest, served at
  `/api/docs` (Swagger UI) and `/api/openapi.json`. The frontend TS client
  types are **generated** from the spec via `openapi-typescript` in CI, so
  the backend and frontend never drift.
- **Error shape** — all errors return `{ error: { code, message, details? } }`
  with appropriate HTTP status. Codes are stable strings
  (`CLUSTER_NOT_FOUND`, `RBAC_DENIED`, `INVALID_YAML`). Flask-Smorest
  `HttpError` subclasses map 1:1 to these codes.

---

## 11. Open / Deferred

These are **not** decisions yet. They will become ADRs when they are.

- **GitOps integration** — Argo CD / Flux read (and eventually write).
- **Cost tracking** — Kubecost integration vs. native computation.
- **Plugin system** — third-party resource types + panels.
- **Multi-tenancy beyond RBAC** — per-tenant data isolation, SSO tenant
  mapping.
- **Mobile / responsive** — current target is ≥ 1280 px; tablet support
  deferred.
- **Offline / cached mode** — TanStack Query persistence for flaky networks.
- **Kerberos / SPNEGO** — not in scope for the v1 re-architecture. OIDC is
  the sole authN mode (ADR-0001). Kerberos is expected to be fronted by an
  OIDC proxy (Kerberos → OIDC federation at the IdP edge) rather than
  natively implemented in KubeDash. Revisit only if a deployment has no
  IdP that can federate Kerberos.
- **Custom provisioning task types** — § 5E ships a set of *builtin* task
  types. Arbitrary/custom task types (plugin task handlers) are deferred.
- **Full SCIM filter grammar** — § 5F ships the Okta/EntraID/Keycloak
  provisioning subset. The complete RFC 7644 filter grammar is deferred.
- **No-IdP (local password) mode** — § 7.7 air-gap assumes an internal IdP.
  A pure local username/password mode (no IdP at all) is deferred.
  *Superseded-in-part (ADR-0021): the bootstrap-admin local mode is now
  implemented; the multi-user no-IdP mode remains deferred (ADR-0013).*
- **Celery migration** — if task volume grows beyond 4 periodic tasks or
  requires fan-out / priorities, migrate RQ → Celery (broker is already
  Redis; task modules are framework-agnostic).

---

## 12. ADR Index (pointer)

See `.skillgrid/ASSUMPTIONS.md` § `## LOCKED` for the in-force ADR index.
Each ADR is a file at `.skillgrid/knowledge/decisions/04-adr-NNNN-slug.md`.

Initial ADRs expected for this change (to be authored at brainstorming time):

- ADR-0001 — Flask + Flask-Smorest over FastAPI (sync WSGI, auto-OpenAPI,
  Pydantic-native schemas, SocketIO for real-time)
- ADR-0002 — Multi-cluster via encrypted kubeconfig registry (one-way-door)
- ADR-0003 — Observability as query-only (no ingest)
- ADR-0004 — RBAC proxy via SubjectAccessReview (not local role mapping)
- ADR-0005 — CoreUI React + free admin template over shadcn/ui/Tailwind
  (Bootstrap-based, AI-friendly scaffold, MIT-licensed, 5k stars)
- ADR-0006 — Single-container deployment (Gunicorn serves API + static SPA;
  no separate frontend container)
- ADR-0007 — RQ over Celery for async tasks (lighter, in-process, pairs with
  single-container; Redis is already a dep) — **superseded by ADR-0029**
  (queue on Postgres; ADR-0007 was index-only, no body file)
- ADR-0008 — Leader election via PG advisory lock + lease table (single
  leader runs the task worker; N replicas for HA; failover < 15 s) —
  **superseded by ADR-0031** (active-active pgEdge/Spock + strict `fence`
  token; ADR-0008 was index-only, no body file)
- ADR-0009 — SSE over WebSocket for server→client push (stateless,
  HTTP-native, LB-friendly; WebSocket only for bidirectional exec)
- ADR-0010 — Informer-based in-memory cache (per-cluster watch, no
  per-request API calls; the key to scaling on large clusters)
- ADR-0011 — kubectl credential plugin with server-managed SSO config
  (Go binary, PKCE, keyring cache; no issuer/client_id in kubeconfig)
- ADR-0012 — Aggregated API server for Project + SSOUser + SSOGroup
  (kube-aggregator pattern; read-only, mTLS, RBAC-filtered Projects,
  admin-only SSO objects; no data in etcd)
- ADR-0013 — Permission management: role templates (Postgres, not
  ClusterRoles) + self-service kubeconfig (plugin-based, multi-cluster) +
  drift detection. Combines permission-manager (templates) + gangway
  (kubeconfig) patterns, extended for multi-cluster + SSO.
- ADR-0014 — Session revocation propagation: web logout invalidates the
  kubectl session (Redis jti revocation set + OIDC RP-initiated logout +
  CSR revocation). Additive deny-list, TTL-bounded. (OpenUnison-derived.) —
  **superseded by ADR-0030** (the `jti` deny-list moves from Redis to a
  Postgres `revoked_jtis` table; the guarantee is preserved)
- ADR-0015 — Namespace-as-a-Service: self-service namespace onboarding via
  request → approve → provision, with optional TTL'd grants auto-revoked by
  the `access_expiry` task. (OpenUnison-derived.)
- ADR-0016 — Privileged Access Management: time-boxed, approved elevation
  applied *on top of* the baseline binding and auto-reverted at TTL;
  break-glass self-approve with a short cap. (OpenUnison-derived.)
- ADR-0017 — Just-In-Time login provisioning: declarative, per-cluster
  provisioning pipeline (Helm-declared tasks) triggered by login / elevation
  / NaaS approval; login-time failures don't block login. (OpenUnison-derived.)
- ADR-0018 — SCIM 2.0 Gateway: RFC 7644 user/group push from an IdP/HR
  source; `active` flag drives `users.status`; decoupled from bindings.
  (OpenUnison-derived.)
- ADR-0019 — Ingress Auth Integration: a `/auth/verify` subrequest endpoint
  for NGINX `auth_request`, Traefik `forwardauth`, Istio `ext_authz`, and
  Gateway API; forwards `X-Remote-User`/`X-Remote-Groups` to backends.
  (OpenUnison-derived.)
- ADR-0020 — Air-Gap Deployment: zero outbound calls at runtime (local JWTs,
  cached JWKS, pre-loaded images, offline CLI, vendored Helm); air-gap ≠
  no-IdP (the IdP is on the internal network). (OpenUnison-derived.)
- ADR-0029 — Queue on Postgres: `tasks` table + `SELECT ... FOR UPDATE SKIP
  LOCKED` poll worker (reaper + 3× exponential-backoff retry + dead-letter),
  replacing RQ/Redis as the task broker. Supersedes ADR-0007 (index-only).
  With ADR-0030, removes Redis as a stateful dependency.
- ADR-0030 — Session revocation on Postgres: `revoked_jtis` deny-list table
  (PK lookup on the verify-hook hot path + leader reaper), replacing the Redis
  `jti` set. Supersedes ADR-0014 (file retained).
- ADR-0031 — Active-active Postgres via pgEdge/Spock:
  `ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal`, thin operator-less Helm
  chart + run-once init `Job`, `dev/` docker-compose, `autoddl` for one-shot
  migrations, + a **strict fencing token** on `leader_lease` so the ADR-0008
  election stays correct under last-write-wins. Supersedes ADR-0008
  (index-only).

---

## 13. Glossary pointer

- **Business terms** — `.skillgrid/knowledge/glossary/01-business-terms.md`
- **Technical terms** — `.skillgrid/knowledge/glossary/02-technical-terms.md`

Canonical terms used in this file (details in the terms files):

- **Cluster** — a registered Kubernetes API server KubeDash manages.
- **Binding** — the user×cluster permission grant (viewer/editor/admin).
- **Observability backend** — a Prometheus/Loki/Tempo endpoint KubeDash queries.
- **Api** — a `flask_smorest.Api` subclass (domain-scoped REST resource).
  *Not* the skillgrid implementation plan (which also lives at
  `blueprint.md` in a change folder).
- **View** — a `src/views/<Name>/` folder (one per route), following the
  CoreUI free admin template convention. *Not* a "feature" folder.
- **CoreUI shell** — the Header + Sidebar + Footer + `_nav` + `routes`
  scaffold adopted from `coreui/coreui-free-react-admin-template`.
- **Leader** — the replica holding the `leader_lease`; enqueues the
  leader-gated tasks and holds the current `fence` (ADR-0031).
- **Follower** — a replica without the lease; serves HTTP only.
- **Task queue** — the Postgres `tasks` table + `FOR UPDATE SKIP LOCKED` claim
  loop (ADR-0029); replaced RQ/Redis. The `fence` is the monotonic
  leader-election token that fences a stale leader's writes under active-
  active (ADR-0031).
- **Informer cache** — the per-cluster, in-memory dict of K8s resources
  maintained by long-lived watches. The read path for all UI + services.
- **SSE stream** — a `text/event-stream` HTTP response used for
  server→client push (events, timeline, topology, logs). Client uses
  native `EventSource`.
- **MCP** — Model Context Protocol; the `/mcp` endpoint that exposes
  KubeDash data + actions to AI agents (Claude Code, Cursor, Copilot).
- **Credential plugin** — a kubectl exec credential plugin
  (`kubectl-kubedash`) that authenticates via KubeDash-managed OIDC SSO.
  The kubeconfig contains only `--server` + `--cluster-name`; all SSO
  config is fetched from the server at auth time.
- **ExecCredential** — the `client.authentication.k8s.io/v1` JSON object
  the plugin prints to stdout for kubectl to consume.
- **Project** — a `projects.kubedash.io/v1` object exposed via the K8s
  aggregated API. A 1:1 read-only projection of a Namespace, filtered by
  the requesting user's RBAC. `kubectl get projects` lists only the
  namespaces the user can read.
- **SSOUser** — an `auth.kubedash.io/v1` object (cluster-admin only) that
  shows a user's effective permissions across the cluster, computed
  on-the-fly from RBAC objects.
- **SSOGroup** — an `auth.kubedash.io/v1` object (cluster-admin only) that
  shows a group's effective permissions across the cluster.
- **Aggregated API** — the KubeDash service registered as a K8s
  aggregated API server (kube-aggregator pattern). Serves
  `projects.kubedash.io/v1` and `auth.kubedash.io/v1` over mTLS on port
  8443. Read-only; no data in etcd.
- **APIService** — the `apiregistration.k8s.io/v1` object that registers
  the KubeDash aggregated API with the K8s API server.
- **Role template** — a named, reusable set of RBAC rules stored in
  KubeDash's Postgres (not as a ClusterRole). Applying a template creates
  the actual Role + RoleBinding in the cluster, labelled
  `kubedash.io/template`.
- **Binding** — a `cluster_bindings` row: user × cluster × namespace ×
  template. The unit of permission grant.
- **Self-service kubeconfig** — a generated multi-cluster kubeconfig that
  references the KubeDash credential plugin (not an embedded token).
  Downloaded from the UI after login.
- **Drift detection** — the `rbac_drift_check` RQ task that compares
  cluster RBAC objects (labelled `kubedash.io/template`) against the
  templates in Postgres, and enforces or warns on divergence.
- **Tracer** — a distributed trace (Tempo/Jaeger).
- **Session revocation propagation** — the property that ending a KubeDash
  web session (logout) immediately invalidates all credentials derived from
  it, via a Redis `jti` revocation set + OIDC RP-initiated logout + CSR
  revocation. (ADR-0014.)
- **NaaS (Namespace-as-a-Service)** — self-service namespace onboarding: a
  user requests access to (or a new) namespace, an approver approves, and
  KubeDash provisions it. Optional TTL'd grants are auto-revoked.
  (ADR-0015.)
- **Elevation** — a time-boxed PAM grant that applies an elevated role
  template *on top of* a user's baseline binding and auto-reverts at TTL.
  (ADR-0016.)
- **Break-glass** — the PAM path where a `cluster-admin` self-approves their
  own elevation under a short TTL cap, for when no approver is reachable.
  (ADR-0016.)
- **Provisioning task** — a named, parameterised, idempotent cluster
  mutation declared in Helm and run by the JIT engine on a lifecycle
  trigger (login / elevation / NaaS approval). (ADR-0017.)
- **SCIM** — System for Cross-domain Identity Management (RFC 7644). The
  KubeDash SCIM gateway lets an IdP/HR source push user/group lifecycle.
  (ADR-0018.)
- **Verify endpoint** — the `/auth/verify` subrequest endpoint that ingress
  controllers call (NGINX `auth_request`, Traefik `forwardauth`, Istio
  `ext_authz`) to authenticate a request and forward `X-Remote-*` identity
  headers. (ADR-0019.)
- **Air-gap mode** — a deployment with zero outbound calls at runtime:
  local JWTs, cached JWKS, pre-loaded images, offline CLI, vendored Helm.
  The IdP is on the internal network (air-gap ≠ no-IdP). (ADR-0020.)
