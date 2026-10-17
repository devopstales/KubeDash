# KubeDash — Assumptions & In-Force ADR Index

> This file holds the **tiered assumptions** (VERIFIED / INFERRED) and the
> **`## LOCKED` ADR index** — the in-force source of truth for which
> architectural decisions apply. The index stores a short description + the
> path to each ADR file; `status` / `date` / `supersedes` live in the file's
> frontmatter, **not** here. One decision per ADR file at
> `.skillgrid/artifacts/04-adr-NNNN-slug.md`.

**Highest sequence in use:** 0020

---

## VERIFIED

Assumptions confirmed against the code or a primary source.

- (none recorded yet)

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
| ADR-0004 | RBAC proxy via SubjectAccessReview (not local role mapping) | yes | `artifacts/04-adr-0004-rbac-proxy-sar.md` |
| ADR-0005 | CoreUI React + free admin template over shadcn/ui/Tailwind | yes | `artifacts/04-adr-0005-coreui-react.md` |
| ADR-0006 | Single-container deployment (Gunicorn serves API + static SPA) | yes | `artifacts/04-adr-0006-single-container.md` |
| ADR-0007 | RQ over Celery for async tasks | yes | `artifacts/04-adr-0007-rq-over-celery.md` |
| ADR-0008 | Leader election via PG advisory lock + lease table | yes | `artifacts/04-adr-0008-leader-election.md` |
| ADR-0009 | SSE over WebSocket for server→client push | yes | `artifacts/04-adr-0009-sse-over-websocket.md` |
| ADR-0010 | Informer-based in-memory cache | yes | `artifacts/04-adr-0010-informer-cache.md` |
| ADR-0011 | kubectl credential plugin with server-managed SSO config | yes | `artifacts/04-adr-0011-kubectl-credential-plugin.md` |
| ADR-0012 | Aggregated API server for Project + SSOUser + SSOGroup | yes | `artifacts/04-adr-0012-aggregated-api.md` |
| ADR-0013 | Permission management: role templates + self-service kubeconfig + drift detection | yes | `artifacts/04-adr-0013-permission-management.md` |
| ADR-0014 | Session revocation propagation (web logout kills kubectl session) | yes | `artifacts/04-adr-0014-session-revocation-propagation.md` |
| ADR-0015 | Namespace-as-a-Service (self-service onboarding + TTL'd grants) | yes | `artifacts/04-adr-0015-namespace-as-a-service.md` |
| ADR-0016 | Privileged Access Management (additive elevation + auto-revert + break-glass) | yes | `artifacts/04-adr-0016-privileged-access-management.md` |
| ADR-0017 | Just-In-Time login provisioning (Helm-declared builtin pipeline) | yes | `artifacts/04-adr-0017-jit-login-provisioning.md` |
| ADR-0018 | SCIM 2.0 Gateway (IdP/HR push; identity decoupled from bindings) | yes | `artifacts/04-adr-0018-scim-2-0-gateway.md` |
| ADR-0019 | Ingress Auth Integration (`/auth/verify` for NGINX/Traefik/Istio/Gateway API) | yes | `artifacts/04-adr-0019-ingress-auth-integration.md` |
| ADR-0020 | Air-Gap Deployment (zero outbound calls at runtime; air-gap ≠ no-IdP) | yes | `artifacts/04-adr-0020-air-gap-deployment.md` |

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
