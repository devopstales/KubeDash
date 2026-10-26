# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

KubeDash is a multi-cluster Kubernetes dashboard with OIDC auth and
observability integration (logs, metrics, traces). One container: Gunicorn
(Flask + Smorest) serves the REST API **and** the built React SPA; an
in-process RQ worker runs only on the leader replica (PostgreSQL advisory
lock + `leader_lease` table).

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
├── dev/                docker-compose dev stack (Postgres, Redis, Grafana, …)
├── .github/workflows/  ci.yaml, e2e.yaml
└── .skillgrid/         ARCHITECTURE.md, ASSUMPTIONS.md, specs/, artifacts/
```

## Where to read before changing

- **Architecture (live):** `.skillgrid/ARCHITECTURE.md` — layout, API, data
  model, auth flow, deployment. Update it when the codebase changes.
- **Locked decisions:** `.skillgrid/ASSUMPTIONS.md` (ADR index) and
  `.skillgrid/knowledge/decisions/04-adr-NNNN-slug.md`. ADRs are gated: check
  the index before changing architecture (stack, deployment shape, auth, push
  transport, task runner, caching).
- **Change specs:** `.skillgrid/specs/` — per-change briefing, blueprint,
  tasks, acceptance.
- **Glossary:** `.skillgrid/knowledge/glossary/01-business-terms.md`,
  `02-technical-terms.md`.

## Commands

All repo tasks are CWD-independent via the root `Taskfile.yaml` — run
`task <name>` from any subdirectory. `task --list` shows everything.

### Backend (Flask, uv-managed, `:8080`)

```bash
cd backend
uv sync
uv run pytest                      # unit suite (needs Docker for Testcontainers)
uv run pytest -m "not integration" # unit only (integration is kind-gated)
uv run flask --app wsgi run        # dev server on :8080 (or FLASK_RUN_PORT)
```

Tasks: `task backend-run` (leader role, starts RQ worker),
`task backend-run-worker` (worker role, no Leader/RQ).

### Frontend (React + Vite, pnpm via corepack)

```bash
cd frontend
corepack pnpm install
task fe-build    # typecheck (tsc --noEmit) + lint + build → frontend/dist
task fe-sync     # dist → backend/static (where Flask serves it)
task fe-check    # air-gap assertion: no https?:// or //cdn. in the bundle
task fe-dev      # vite dev server, API proxied to http://localhost:8080
```

**Always use `task fe-dev`, not bare `pnpm dev`** — the latter has no
`VITE_API_BASE` and CORS-fails against `:8080`. The frontend is air-gapped
(ADR-0020): no CDN references in the built bundle.

### CLI (Go, kubectl credential plugin)

```bash
task build        # CGO_ENABLED=0 go build -ldflags "-X …cmd.version=$VERSION"
task cross        # 5 OS/arch combos → cli/dist/
./cli/kubedash version
```

Version is injected at link time via `-X github.com/org/kubedash-cli/cmd.version`;
the bare package name is silently ignored by the linker.

### Chart

```bash
helm lint charts/kubedash
helm template t charts/kubedash > /dev/null
```

### Dev stack (Postgres + Redis + observability)

```bash
task dev-up / dev-down / dev-logs / dev-ps
task dev-clean   # destructive: deletes data volumes
task db-shell    # psql; SELECT * FROM leader_lease to observe leadership
task dev-stack   # one-command plain-HTTP env: compose + schema + backend on http://localhost:8080 (ADR-0027 default)
task dev-stack-ssl  # same, behind the nginx TLS edge: https://kubedash.dev.local:443, backend :8443, Secure cookie (ADR-0026/0027)
task dev-stack-down   # stop the backend (all dev ports) + compose stack
task dev-tls-setup    # mkcert certs + hosts entry for dev-stack-ssl (idempotent; hosts needs sudo)
```

The dev DB is **migration-managed**: `task dev-stack` applies the Alembic
migrations (the same path prod uses) instead of a `create_all` shortcut —
a fresh stack boots at head with the built-in RBAC templates seeded, and a
legacy `create_all`-era dev DB (no `alembic_version` table) is healed via
`stamp <base>` + `upgrade` (data preserved). Never hand-edit the dev DB's
schema — migrations are the source of truth.

Multi-instance leader-election testing:

```bash
task multi-up     # two instances :8081 + :8082
task multi-logs   # watch leadership; kill the leader and a follower promotes in ~10 s
task failover
```

## Configuration

Env-driven via `backend/app/core/config.py`, `KUBEDASH_` prefix (unprefixed
aliases per ARCHITECTURE.md §3.8).

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
| `KUBEDASH_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | bootstrap local-admin — both set enables local login (ADR-0021) |
| `KUBEDASH_ADMIN_KUBECONFIG` | kubeconfig path for the admin cluster; empty = in-cluster (ADR-0021) |
| `KUBEDASH_PLUGIN_SERVER` | optional; server URL for the exec-plugin kubeconfig (`GET /kubeconfig`); empty → 500 INTERNAL_ERROR on download (ADR-0011/0013) |
| `KUBEDASH_STATIC_DIR` | built SPA location (`/app/static` in the image) |
| `FLASK_RUN_PORT` | dev server port (default 8080) |

The dev stack's pinned ports match the app's default DB/Redis URLs, so no
`KUBEDASH_*_URL` is needed for the stock setup.

## Conventions

- **Backend layering:** `app/api/<domain>.py` is one Smorest `Api` per
  domain (≤ ~300 lines, Pydantic schemas, no cross-domain imports).
  `app/services/` is pure Python with **no Flask imports** — the integration
  boundary. `app/models/` is SQLAlchemy 2.0.
- **Read path:** UI and read services read from the **informer cache**, not
  per-request K8s API calls (ADR-0010). Mutations go through the API and
  update the cache on watch events.
- **Push:** SSE is the primary server→client channel; WebSocket only for
  bidirectional exec (ADR-0009).
- **Tasks:** RQ tasks in `app/tasks/` run **only on the leader**.
- **Frontend:** view-folder layout (one folder per route, CoreUI template
  convention). Server state → TanStack Query; UI state → Zustand. No
  Tailwind — CoreUI SCSS.
- **One-way doors:** the cluster registry schema and `KUBEDASH_SECRET_KEY`
  encryption are migration-gated and ADR-gated.

## Prose & writing style

Markdown the agent writes or reviews in this repo follows the `code-style`
group at `~/.agents/skills/code-style/` (synced from skillgrid, ADR-0039):

- **Generation-time** — the 21 agent-style rules at
  `~/.agents/skills/_shared/rules/prose-style.md` (naming, structure,
  citation discipline). Apply while writing specs, ADRs, reports, changelogs.
- **Review-time** — `skillgrid:style-review` audits a finished file against
  the same rules (scorecard, write-beside polish to `FILE.reviewed.md`).
- **Language style guides** — Google official guides for the languages this
  repo uses, one skill each:
  - `python` — PEP 8 + type annotations, Google docstrings (backend/)
  - `typescript` — strict mode, explicit return types (frontend/)
  - `go` — gofmt, short names, error handling (cli/)
  - `markdown` — formatting, structure, links (docs, AGENTS.md, specs)
  - `json` — formatting, naming (config files, API fixtures)
  - `shell` — Bash scripting (Taskfile, dev/ scripts)
  - `html-css` — formatting, semantics (frontend/ markup)

  The guides are advisory; they defer to the repo's formatter (`black`/`ruff`
  for Python, `tsc`/`eslint` for TypeScript, `gofmt` for Go) where the two
  disagree.

- **Code design vocabulary** — `skillgrid:codebase-design` for interface-design
  talk (module, interface, seam, depth). Use its terms when discussing
  architecture in ADRs or specs.

## Testing

- **Backend:** pytest. Integration tests are kind-gated (marked); use
  `-m "not integration"` for the unit-only loop. Testcontainers need Docker.
- **Frontend:** Vitest + React Testing Library + MSW (`pnpm test`); Playwright
  for e2e (kind + Helm, full UI flow).
- **CI:** `.github/workflows/ci.yaml` (lint + typecheck + test + build),
  `e2e.yaml` (kind cluster + full UI flow).
- **Air-gap check:** `task fe-check` asserts the built bundle has no external
  `https?://` or `//cdn.` references (ADR-0020). CI calls the same script.

## Committing & branching

- Work happens on the `rebase` work branch; `main` tracks `origin`. **Ship
  does not merge into `main` by default** — the work branch is the
  deliverable and the rollback unit. Merging into `main` is a separate,
  explicit, deliberate act (ASSUMPTIONS.md, VERIFIED).
- Conventional commits; keep work units atomic and independently revertable.

<!-- BACKLOG.MD GUIDELINES START -->
<!-- backlog.md-instructions-version: 1.51.0 -->
<CRITICAL_INSTRUCTION>

## Backlog.md Workflow

This project uses Backlog.md for task and project management.

**At the beginning of each conversation in this project, run `backlog instructions overview` before answering or taking action. Re-read it only if you have not read it yet in the current conversation.**

Use the overview to decide whether to search, read, create, or update Backlog tasks.

Before task lifecycle actions, read the matching detailed guide:
- `backlog instructions task-creation` before creating or splitting tasks
- `backlog instructions task-execution` before planning, changing status or assignee, adding a plan or implementation notes, or implementing task work
- `backlog instructions task-finalization` before checking acceptance criteria, writing final summaries, or moving tasks to terminal statuses

Use `backlog <command> --help` before running unfamiliar commands. Help shows options, fields, and examples.

Do not edit Backlog task, draft, document, decision, or milestone markdown files directly. Use the `backlog` CLI so metadata, relationships, and history stay consistent.

</CRITICAL_INSTRUCTION>
<!-- BACKLOG.MD GUIDELINES END -->
