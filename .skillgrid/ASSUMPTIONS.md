# KubeDash — Assumptions & In-Force ADR Index

> This file holds the **tiered assumptions** (VERIFIED / INFERRED) and the
> **`## LOCKED` ADR index** — the in-force source of truth for which
> architectural decisions apply. The index stores a short description + the
> path to each ADR file; `status` / `date` / `supersedes` live in the file's
> frontmatter, **not** here. One decision per ADR file at
> `.skillgrid/artifacts/04-adr-NNNN-slug.md`.

**Highest sequence in use:** 0025

---

## VERIFIED

Assumptions confirmed against the code or a primary source.

- **Ship keeps the work branch; it does not merge into `main` by default.**
  Closing a change (the `ship` phase: QA gate + archive move + `state.yaml`)
  leaves the work branch (currently `rebase`) in place as the deliverable and
  the rollback unit. Merging/rebasing a multi-concern work branch into `main`
  is a separate, explicit act — `main` tracks `origin` (861 commits ahead of the
  local work as of 2026-10-18), so a 60+-commit merge is a deliberate
  blast-radius decision, not a ship default. Rollback when a branch is kept =
  the branch itself (it never left the repo). *(Working agreement, 2026-10-18;
  also stored in mnemonic as a project decision.)*

- **Swagger UI assets are always served locally (no CDN, no toggle).** The
  `/api/docs` page loads `swagger-ui.css` / `swagger-ui-standalone-preset.js` /
  `swagger-ui-bundle.js` from the app (vendored `swagger-ui-bundle` PyPI package,
  served via `importlib.resources` on `/api/docs/*` routes) — never a CDN or any
  external host. `OPENAPI_SWAGGER_UI_URL` is a local placeholder kept only
  because smorest 0.47 registers the page only when that key is set (verified in
  `flask_smorest/spec/__init__.py:100-110`). The `BearerAuth` JWT security scheme
  is declared on the spec; page-level auth wiring is deferred. Air-gap (ADR-0020).
  Confirmed by `backend/tests/api/test_apidocs.py` (9 tests) + QA report
  (`.skillgrid/specs/2026-10-17-swagger-ui-air-gap/report.md`).

## INFERRED

Assumptions reasoned from the architecture but not yet confirmed in code.

- The in-flight kubectl-oidc-plugin blueprint targets the **proposed**
  architecture (Flask-Smorest `backend/app/...`, Go `cli/`, `charts/`,
  `frontend/`) described in `ARCHITECTURE.md`. The legacy stack on `main`
  (`src/kubedash` Flask-Jinja2, `src/kdlogin` Go) is **not** the target of
  that change. *(Inferred from the spec zone + branch topology; reconcile
  against the actual build target before execution.)*

---

## LOCKED

In-force ADR index. An ADR is **in force** when its file `status` is
`accepted` **and** no later ADR's `supersedes` points at it. Superseded rows
are kept, with `In force: no`. Never delete a row; flip it instead (IRON RULE).

| Seq | Title | In force | Path |
|---|---|---|---|
| ADR-0001 | Flask + Flask-Smorest over FastAPI (sync WSGI, auto-OpenAPI, Pydantic-native schemas, SocketIO) | yes | `artifacts/04-adr-0001-flask-smorest.md` |
| ADR-0002 | Multi-cluster via encrypted kubeconfig registry (one-way-door) | yes | `artifacts/04-adr-0002-multi-cluster-registry.md` |
| ADR-0003 | Observability as query-only (no ingest) | yes | `artifacts/04-adr-0003-observability-query-only.md` |
| ADR-0004 | RBAC proxy via SubjectAccessReview (not local role mapping) — addendum 2026-10-21: the SAR verdict cache key carries every SAR attribute (`sar:<cluster>:<sub>:<verb>:<resource>:<group>:<namespace>:<name>`); resource reads use the registry credentials, so a verdict for one namespace or object must never answer for another | yes | `artifacts/04-adr-0004-rbac-proxy-sar.md` |
| ADR-0005 | CoreUI React + free admin template over shadcn/ui/Tailwind | yes | `artifacts/04-adr-0005-coreui-react.md` |
| ADR-0006 | Single-container deployment (Gunicorn serves API + static SPA) | yes | `artifacts/04-adr-0006-single-container.md` |
| ADR-0007 | RQ over Celery for async tasks | yes | `artifacts/04-adr-0007-rq-over-celery.md` |
| ADR-0008 | Leader election via PG advisory lock + lease table | yes | `artifacts/04-adr-0008-leader-election.md` |
| ADR-0009 | SSE over WebSocket for server→client push | yes | `artifacts/04-adr-0009-sse-over-websocket.md` |
| ADR-0010 | Informer-based in-memory cache | yes | `artifacts/04-adr-0010-informer-cache.md` |
| ADR-0011 | kubectl credential plugin with server-managed SSO config | yes | `artifacts/04-adr-0011-kubectl-credential-plugin.md` |
| ADR-0012 | Aggregated API server for Project + SSOUser + SSOGroup | yes | `artifacts/04-adr-0012-aggregated-api.md` |
| ADR-0013 | Permission management: role templates + self-service kubeconfig + drift detection (core implemented: templates, bind/unbind, self-service kubeconfig; drift detection not in this change) | yes | `artifacts/04-adr-0013-permission-management.md` |
| ADR-0014 | Session revocation propagation (web logout kills kubectl session) | yes | `artifacts/04-adr-0014-session-revocation-propagation.md` |
| ADR-0015 | Namespace-as-a-Service (self-service onboarding + TTL'd grants) | yes | `artifacts/04-adr-0015-namespace-as-a-service.md` |
| ADR-0016 | Privileged Access Management (additive elevation + auto-revert + break-glass) | yes | `artifacts/04-adr-0016-privileged-access-management.md` |
| ADR-0017 | Just-In-Time login provisioning (Helm-declared builtin pipeline) | yes | `artifacts/04-adr-0017-jit-login-provisioning.md` |
| ADR-0018 | SCIM 2.0 Gateway (IdP/HR push; identity decoupled from bindings) | yes | `artifacts/04-adr-0018-scim-2-0-gateway.md` |
| ADR-0019 | Ingress Auth Integration (`/auth/verify` for NGINX/Traefik/Istio/Gateway API) | yes | `artifacts/04-adr-0019-ingress-auth-integration.md` |
| ADR-0020 | Air-Gap Deployment (zero outbound calls at runtime; air-gap ≠ no-IdP) — superseded-in-part by ADR-0021 (the bootstrap-admin local mode is now implemented; the multi-user no-IdP deferral remains) | yes | `artifacts/04-adr-0020-air-gap-deployment.md` |
| ADR-0021 | Local Admin Auth — bootstrap password mode (env-driven bootstrap admin + admin kubeconfig source; SSO stays primary) | yes | `artifacts/04-adr-0021-local-admin-auth.md` |
| ADR-0022 | Sidebar navigation — 4.1 information-parity structure (sections, groups, entry names, order, admin gating); 4.1 Plugins group dropped (no 5.0 plugin system) | yes | `artifacts/04-adr-0022-sidebar-nav-4-1-parity.md` |
| ADR-0023 | User-management lists use DataTables React with the Bootstrap 5 skin (4.1 table structure; CoreUI shell unchanged) | yes | `artifacts/04-adr-0023-datatables-react.md` |
| ADR-0024 | Secret values use react-syntax-highlighter (highlight.js grammars, an-old-hope theme) instead of the 4.1 highlight.js script | yes | `artifacts/04-adr-0024-secret-syntax-highlight.md` |
| ADR-0025 | Browser session transport is HttpOnly cookies (`kd_access` + `kd_refresh`, hint `kd_session`); `Authorization: Bearer` stays accepted for the kubectl plugin; no credentials in URLs or `localStorage` | yes | `artifacts/04-adr-0025-http-only-session-cookie.md` |
| ADR-0026 | TLS edge + security header layer (nginx edge with internal HTTPS; ProxyFix gated on KUBEDASH_TLS_EDGE; 4.1 header set restored with two recorded deviations) | yes | `artifacts/04-adr-0026-tls-edge-and-security-headers.md` |

> **Note on ADR-0001..0013:** these are listed in `ARCHITECTURE.md` §12 as the
> initial-architecture decisions "to be authored at brainstorming time." As of
> this onboarding their **files do not yet exist** on disk — only the index
> rows (carried forward from ARCHITECTURE.md) and the ADR-0014..0020 files.
> The rows are marked in-force to reflect the architecture they describe.
> Authoring the 0001..0013 files is an open task (see the onboarding notes
> below).

---

## Onboarding notes (2026-10-17)

- Target codebase: the `rebase` orphan branch (docs/ADR/spec layer only).
- `adr_style`: `madr-full` (validated). Existing ADR-0014..0020 were written
  madr-minimal; **new** ADRs (and any backfill of 0001..0013) use madr-full.
- `ticketing.type`: `backlogmd` (validated) — ADR-0014..0020 need
  `.backlog/decisions/decision-014..020` copies (open task).
- `mnemonic.enabled`: true (validated) — code index is empty until the target
  branch's code is indexed (open task).
