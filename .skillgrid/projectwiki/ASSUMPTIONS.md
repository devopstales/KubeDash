# ASSUMPTIONS.md — KubeDash

Durable project understanding. Four tiers:

- **VERIFIED** — facts confirmed against the repo.
- **INFERRED (HYPOTHESIS)** — plausible, not yet confirmed.
- **LOCKED** — the ADR index: one pointer row per in-force decision (status/supersedes/date live in each ADR file's frontmatter, not here).
- **Open Questions** — unresolved, with a pointer to where the answer lives.

Operational rules that are *not* decisions (commit format, build-toolchain floor, spec/code zone order) live in AGENTS.md's `### Rules` section, not here.

## VERIFIED

**Product.** KubeDash is a multi-cluster Kubernetes dashboard: one web console for
operators to view and operate across many Kubernetes clusters, with OIDC single
sign-on, per-user RBAC delegated to the target clusters (SelfSubjectAccessReview),
query-only observability (Prometheus/Loki/Tempo), and a kubectl credential plugin
for automation. Built for platform teams running more than one cluster.

**Stack.** Python 3.12 (uv) backend — Flask 3 + flask-smorest (auto-OpenAPI),
SQLAlchemy 2 + Alembic, psycopg 3, Pydantic 2, gunicorn. React 19 + TypeScript 5.8 +
Vite frontend on the CoreUI template (pnpm; vendored SCSS, no Tailwind); TanStack
Query (server state) + Zustand (UI state). Go 1.22 kubectl credential plugin
(cobra). Deployment: one container (Gunicorn serves the REST API under `/api/v1/*`
and the built SPA), Helm chart, PostgreSQL (pgEdge active-active in dev) — no Redis
since ADR-0029/0030.

**Task runner.** In-process pgqueue worker on every replica: a scheduler thread
enqueues due tasks only while the replica leads (PG advisory lock + `leader_lease`
fencing); any replica claims and runs tasks from the Postgres `tasks` table
(`SELECT ... FOR UPDATE SKIP LOCKED`) and reaps stale claims. ADR-0029/0031.

**Config.** `backend/kubedash.ini` is the primary config source; `KUBEDASH_*` env
overrides; fail-fast at boot on missing identity/credential keys (ADR-0028).

**Auth.** OIDC is the only external authN; browser sessions in HttpOnly cookies
(`kd_access` + `kd_refresh`); `Authorization: Bearer` accepted only for the kubectl
credential plugin (ADR-0025). Local bootstrap-admin mode for dev (ADR-0021).

## INFERRED (HYPOTHESIS)

- The `openwiki/` evidence index (generated 2026-11-06) is stale on task-runner
  details (it predates ADR-0029 and still describes RQ/Redis). Treat it as
  orientation, not source of truth — the code + ADRs win.

## LOCKED

In-force decisions — one row per ADR, path to the record (relative to this file's
folder). Superseded records stay in `decisions/` but have no row here.

| ADR | Decision | Record |
|---|---|---|
| 0001 | Flask + Flask-Smorest over FastAPI (sync WSGI, auto-OpenAPI, Pydantic-native schemas) | `decisions/04-adr-0001-flask-smorest.md` |
| 0002 | Multi-cluster via encrypted kubeconfig registry (one-way-door) | `decisions/04-adr-0002-multi-cluster-registry.md` |
| 0003 | Observability as query-only (no ingest) | `decisions/04-adr-0003-observability-query-only.md` |
| 0004 | RBAC proxy via SubjectAccessReview (not local role mapping) | `decisions/04-adr-0004-rbac-proxy-sar.md` |
| 0005 | CoreUI React + free admin template over shadcn/ui/Tailwind | `decisions/04-adr-0005-coreui-react.md` |
| 0006 | Single-container deployment (Gunicorn serves API + static SPA) | `decisions/04-adr-0006-single-container.md` |
| 0009 | SSE over WebSocket for server→client push | `decisions/04-adr-0009-sse-over-websocket.md` |
| 0010 | Informer-based in-memory cache (read path — target; current spine reads direct) | `decisions/04-adr-0010-informer-cache.md` |
| 0011 | kubectl credential plugin with server-managed SSO config | `decisions/04-adr-0011-kubectl-credential-plugin.md` |
| 0012 | Aggregated API server for Project + SSOUser + SSOGroup | `decisions/04-adr-0012-aggregated-api.md` |
| 0013 | Permission management: role templates + self-service kubeconfig + drift detection | `decisions/04-adr-0013-permission-management.md` |
| 0015 | Namespace-as-a-Service (NaaS) | `decisions/04-adr-0015-namespace-as-a-service.md` |
| 0016 | Privileged Access Management (PAM) | `decisions/04-adr-0016-privileged-access-management.md` |
| 0017 | Just-In-Time login provisioning | `decisions/04-adr-0017-jit-login-provisioning.md` |
| 0018 | SCIM 2.0 Gateway | `decisions/04-adr-0018-scim-2-0-gateway.md` |
| 0019 | Ingress Auth Integration | `decisions/04-adr-0019-ingress-auth-integration.md` |
| 0020 | Air-Gap Deployment | `decisions/04-adr-0020-air-gap-deployment.md` |
| 0021 | Local Admin Auth (bootstrap password mode) | `decisions/04-adr-0021-local-admin-auth.md` |
| 0022 | Sidebar navigation: 4.1 information-parity structure, Plugins group dropped | `decisions/04-adr-0022-sidebar-nav-4-1-parity.md` |
| 0023 | User-management tables: DataTables React with the Bootstrap 5 skin | `decisions/04-adr-0023-datatables-react.md` |
| 0024 | Secret values: react-syntax-highlighter with the an-old-hope theme | `decisions/04-adr-0024-secret-syntax-highlight.md` |
| 0025 | Browser session transport: HttpOnly cookies, Bearer retained for the kubectl plugin | `decisions/04-adr-0025-http-only-session-cookie.md` |
| 0027 | Plain-HTTP dev-stack default; TLS edge becomes the opt-in dev-stack-ssl | `decisions/04-adr-0027-plain-http-dev-stack-default.md` |
| 0028 | Configuration source: kubedash.ini primary, env override, fail-fast | `decisions/04-adr-0028-ini-config-source.md` |
| 0029 | Queue on Postgres: `tasks` table + `FOR UPDATE SKIP LOCKED` worker (supersedes 0007) | `decisions/04-adr-0029-queue-on-postgres.md` |
| 0030 | Session revocation on Postgres: `revoked_jtis` deny-list (supersedes 0014) | `decisions/04-adr-0030-session-revocation-on-postgres.md` |
| 0031 | Active-active Postgres via pgEdge/Spock + fencing token on `leader_lease` (supersedes 0008) | `decisions/04-adr-0031-active-active-pgedge-spock.md` |
| 0040 | SPA object navigation: tab-private `sessionStorage` object ref + form-POST deep link | `decisions/04-adr-0040-session-object-navigation.md` |
| 0041 | Resource kinds declared in a typed catalog (backend kind catalog + frontend views) | `decisions/04-adr-0041-kind-catalog.md` |

Superseded records (no row): ADR-0007 (by 0029), ADR-0008 (by 0031), ADR-0014 (by
0030), ADR-0026 (by 0027).

Next ADR number: **0042**. 4-digit monotonic, never reused (gap 0032–0039 unused).

## Open Questions

- **23 spec zones lost in the 2026-11-12 `.skillgrid/` wipe** (pre-existing
  working-tree deletions, not restored per user direction). In-flight ones need
  re-baselining from code + ADRs before resuming:
  - `2026-11-07-kind-catalog` — TASK-073–079 in flight in the tracker (ADR-0041)
  - `2026-11-10-ha-status-page` — `app/services/ha_status.py` + `app/schemas/ha_status.py` exist
  - `2026-10-17-kubectl-oidc-plugin` — blueprint referenced by the `cli/cmd/get_token.go` stub (ADR-0011)
  - `2026-10-17-test-observability-pipeline` — briefing + blueprint were the artifacts
  The remaining 19 (the 2026-10-28/29 view changes, 2026-11-06 investigations,
  navigation-seam, frontend-kind-registry) were shipped/closed before the wipe;
  their outcomes are recoverable from the code, the tracker, and the ADRs.
