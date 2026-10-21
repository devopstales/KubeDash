# KubeDash 5.0

Multi-cluster Kubernetes dashboard with OIDC auth and observability integration.
Single container: Gunicorn (Flask + Smorest API) serves the REST API **and** the
built React SPA; an in-process RQ worker runs only on the leader replica.

Layout (5.0):

```
KubeDash/
├── backend/            Flask 3 + Smorest app factory (uv)
│   ├── app/            core/, api/, models/, services/, tasks/, sockets/…
│   ├── migrations/     Alembic
│   ├── tests/          pytest (unit + kind-gated integration)
│   ├── wsgi.py         Gunicorn entrypoint (+ leader-gated RQ worker)
│   └── Dockerfile      3-stage: SPA build → uv deps → runtime (UID 10001)
├── frontend/           React 18 + TS + Vite (CoreUI template, vendored)
│   ├── src/            views/, components/, store/, lib/
│   ├── tests/          Vitest + RTL
│   └── e2e/            Playwright
├── cli/                Go kubectl credential plugin (cobra)
├── charts/kubedash/    Helm chart (N replicas, leader election)
├── tests/              e2e/oidc-mock.py, fe-airgap-check.mjs
├── dev/                docker-compose dev stack (Postgres, Redis, Grafana, …)
├── .github/workflows/  ci.yaml, e2e.yaml
└── .skillgrid/         ARCHITECTURE.md, ASSUMPTIONS.md, specs/, artifacts/
```

## Quickstart

### Backend

```bash
cd backend
uv sync
uv run pytest                      # unit suite (needs Docker for Testcontainers)
uv run pytest -m "not integration" # unit only
uv run flask --app wsgi run        # dev server on :8080 (or FLASK_RUN_PORT)
```

### Frontend

```bash
cd frontend
corepack pnpm install
corepack pnpm dev                  # Vite dev server (proxies /api to :8080)
corepack pnpm build                # production build → dist/
```

Offline frontend loop (repo-root Taskfile — ADR-0020/ADR-0021):
`task fe-install` (deps), `task fe-build` (typecheck + lint + build),
`task fe-sync` (dist → `backend/static`), `task fe-check` (no-CDN air-gap
assertion on the bundle). For the dev server use `task fe-dev`, not bare
`pnpm dev` (the latter has no `VITE_API_BASE` and will CORS-fail against
:8080).

### CLI

```bash
task build                         # or: cd cli && CGO_ENABLED=0 go build -o kubedash .
./cli/kubedash version             # → kubedash 0.1.0
```

### Chart

```bash
helm lint charts/kubedash
helm template t charts/kubedash > /dev/null
```

### Dev stack (Postgres + Redis)

```bash
docker compose -f dev/docker-compose.yml up -d
```

## Configuration

Env-driven (`backend/app/core/config.py`, `KUBEDASH_` prefix; unprefixed
aliases per ARCHITECTURE.md §3.8 accepted):

| Var | Purpose |
|---|---|
| `KUBEDASH_ROLE` | `leader` runs the RQ worker; `worker` (default) is HTTP-only |
| `KUBEDASH_REPLICA_ID` | unique replica id (K8s Downward API in the chart) |
| `KUBEDASH_JWT_SECRET` | HS256 JWT signing key |
| `KUBEDASH_SECRET_KEY` | AES-256-GCM key for kubeconfig encryption (not the JWT key) |
| `KUBEDASH_DATABASE_URL` / `DATABASE_URL` | PostgreSQL connection string |
| `KUBEDASH_REDIS_URL` / `REDIS_URL` | Redis connection string (cache + RQ broker) |
| `KUBEDASH_CORS_ORIGINS` | comma-separated allowed origins |
| `KUBEDASH_OIDC_CLIENT_ID` / `_CLIENT_SECRET` / `_ISSUER` | OIDC SSO config |
| `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL` / `KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD` | bootstrap local-admin credentials — both set enables local login (ADR-0021) |
| `KUBEDASH_ADMIN_KUBECONFIG` | path to the kubeconfig for the local (admin) cluster; empty = in-cluster (ADR-0021) |
| `KUBEDASH_STATIC_DIR` | built SPA location (`/app/static` in the image) |
| `FLASK_RUN_PORT` | dev server port (default 8080) |

## Documentation

- **Architecture:** `.skillgrid/ARCHITECTURE.md` (live layout, API, data model, deploy)
- **Assumptions + ADR index:** `.skillgrid/ASSUMPTIONS.md` (LOCKED ADRs)
- **Change specs:** `.skillgrid/specs/` (per-change briefing, blueprint, tasks, acceptance)
