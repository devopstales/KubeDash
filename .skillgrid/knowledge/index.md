# KubeDash — Knowledge Base Index

> One-line catalog of every concept in the bundle. Every write to a concept
> file updates this file in the same edit (same-edit rule).

## decisions/

| Concept | One-line summary | Status |
|---|---|---|
| [ADR-0001 — Flask + Flask-Smorest](decisions/04-adr-0001-flask-smorest.md) | Sync WSGI stack, auto-OpenAPI from Pydantic schemas, SocketIO for WS; OIDC sole authN | accepted |
| [ADR-0002 — Multi-cluster registry](decisions/04-adr-0002-multi-cluster-registry.md) | Clusters as DB rows with AES-256-GCM encrypted kubeconfigs (one-way-door) | accepted |
| [ADR-0003 — Observability query-only](decisions/04-adr-0003-observability-query-only.md) | Query + display over user-supplied Prometheus/Loki/Tempo; no ingest, degrade don't fail | accepted |
| [ADR-0004 — RBAC via SubjectAccessReview](decisions/04-adr-0004-rbac-proxy-sar.md) | SAR proxy (not local role mapping); verdict cache key carries every SAR attribute (amended 2026-10-21) | accepted |
| [ADR-0005 — CoreUI React template](decisions/04-adr-0005-coreui-react.md) | Free CoreUI admin template over shadcn/ui/Tailwind; SCSS-only, view folders | accepted |
| [ADR-0006 — Single container](decisions/04-adr-0006-single-container.md) | Gunicorn serves API + static SPA; in-process leader-gated RQ worker | accepted |
| [ADR-0007 — RQ over Celery](decisions/04-adr-0007-rq-over-celery.md) | Redis Queue, in-process worker; Celery is the recorded exit if fan-out appears | accepted |
| [ADR-0008 — Leader election](decisions/04-adr-0008-leader-election.md) | PG advisory lock + leader_lease row; 5 s heartbeat / 10 s stale; failover < 15 s | accepted |
| [ADR-0009 — SSE over WebSocket](decisions/04-adr-0009-sse-over-websocket.md) | SSE primary push; WebSocket only for bidirectional exec | accepted |
| [ADR-0010 — Informer cache](decisions/04-adr-0010-informer-cache.md) | Per-cluster watch-maintained read cache (target pattern; base change deferred it — seam in k8s_client.py) | accepted |
| [ADR-0011 — kubectl credential plugin](decisions/04-adr-0011-kubectl-credential-plugin.md) | Server-managed SSO config (kubeconfig carries only server + cluster name); PKCE; ExecCredential | accepted |
| [ADR-0012 — Aggregated API](decisions/04-adr-0012-aggregated-api.md) | kube-aggregator pattern: Project + SSOUser + SSOGroup, read-only, mTLS, no data in etcd | accepted |
| [ADR-0013 — Permission management](decisions/04-adr-0013-permission-management.md) | Postgres role templates + self-service kubeconfig + drift detection (drift task still a stub) | accepted |
| [ADR-0014 — Session revocation propagation](decisions/04-adr-0014-session-revocation-propagation.md) | Web logout kills the kubectl session (revocation must reach the CLI) | accepted |
| [ADR-0015 — Namespace-as-a-Service](decisions/04-adr-0015-namespace-as-a-service.md) | Self-service namespace onboarding + TTL'd grants | accepted |
| [ADR-0016 — Privileged Access Management](decisions/04-adr-0016-privileged-access-management.md) | Additive elevation + auto-revert + break-glass | accepted |
| [ADR-0017 — Just-In-Time login provisioning](decisions/04-adr-0017-jit-login-provisioning.md) | Helm-declared builtin pipeline provisions users on first login | accepted |
| [ADR-0018 — SCIM 2.0 Gateway](decisions/04-adr-0018-scim-2-0-gateway.md) | IdP/HR push; identity decoupled from bindings | accepted |
| [ADR-0019 — Ingress Auth Integration](decisions/04-adr-0019-ingress-auth-integration.md) | `/auth/verify` for NGINX/Traefik/Istio/Gateway API | accepted |
| [ADR-0020 — Air-Gap Deployment](decisions/04-adr-0020-air-gap-deployment.md) | Zero outbound calls at runtime; air-gap ≠ no-IdP (superseded-in-part by ADR-0021) | accepted |
| [ADR-0021 — Local Admin Auth](decisions/04-adr-0021-local-admin-auth.md) | Bootstrap password mode; admin kubeconfig source; SSO stays primary | accepted |
| [ADR-0022 — Sidebar navigation](decisions/04-adr-0022-sidebar-nav-4-1-parity.md) | 4.1 information-parity menu structure; Plugins group dropped; 2026-11-07 amendment: Network group consolidated to Services / Ingress / Ingress Class (Gateway API kinds + GatewayClasses merged in as tabs, old URLs redirect) | accepted |
| [ADR-0023 — DataTables React](decisions/04-adr-0023-datatables-react.md) | User-management lists use DataTables React with the Bootstrap 5 skin | accepted |
| [ADR-0024 — Secret syntax highlight](decisions/04-adr-0024-secret-syntax-highlight.md) | Secret values use react-syntax-highlighter (an-old-hope theme) | accepted |
| [ADR-0025 — HttpOnly session cookie](decisions/04-adr-0025-http-only-session-cookie.md) | Session in HttpOnly cookies; Bearer retained for the kubectl plugin | accepted |
| [ADR-0026 — TLS edge + security headers](decisions/04-adr-0026-tls-edge-and-security-headers.md) | nginx TLS edge; ProxyFix gated on KUBEDASH_TLS_EDGE; 4.1 header set restored (superseded by ADR-0027) | accepted |
| [ADR-0027 — Plain-HTTP dev-stack default](decisions/04-adr-0027-plain-http-dev-stack-default.md) | Dev stack is plain HTTP :8080; the ADR-0026 TLS edge is the opt-in `task dev-stack-ssl` | accepted |
| [ADR-0028 — INI config source](decisions/04-adr-0028-ini-config-source.md) | `kubedash.ini` primary, `KUBEDASH_*` env override, fail fast at boot (no silent defaults) | accepted |
| [ADR-0040 — SPA object navigation](decisions/04-adr-0040-session-object-navigation.md) | Tab-private sessionStorage object ref + form-POST deep link; token delivered via the server session (one-shot meta, amended 2026-11-04); no object identity in the URL | accepted |
| [ADR-0041 — Kind catalog](decisions/04-adr-0041-kind-catalog.md) | Resource kinds are declared in a typed catalog (backend kind catalog + frontend `lib/kinds.ts` registry); generic `list/get` engine at the existing factory seam; per-kind methods only as named overrides; doubles become fixture data | accepted |

## glossary/

| Concept | One-line summary |
|---|---|
| [Business terms](glossary/01-business-terms.md) | Domain / product / workflow vocabulary |
| [Technical terms](glossary/02-technical-terms.md) | Architecture / platform / protocol vocabulary |

## invariants/

| Concept | One-line summary |
|---|---|
| [Browser sessions ride HttpOnly cookies](invariants/session-cookie-transport.md) | `kd_access`/`kd_refresh` HttpOnly (hint `kd_session` grants nothing); Bearer only for the kubectl plugin; no credential in URL/localStorage (ADR-0025) |
| [RQ worker runs only on the leader](invariants/leader-only-rq-worker.md) | `pg_try_advisory_lock` + `leader_lease` arbitrate; wsgi spawns the worker only when role == "leader" (ADR-0006/0007/0008) |
| [Configuration fails fast at boot](invariants/config-fail-fast.md) | INI > env, no in-code default for identities/credentials; missing key raises `ConfigError` (ADR-0028) |
| [app/services is Flask-free](invariants/services-integration-boundary.md) | No module-level Flask imports in services; one documented function-local carve-out (K8sClientPool admin branch) |
| [SAR verdict cache key carries every attribute](invariants/sar-verdict-cache-key.md) | `sar:<cluster>:<sub>:<verb>:<resource>:<group>:<namespace>:<name>`, Redis TTL 30 s; one verdict never answers for another (ADR-0004) |
| [Air-gapped bundle](invariants/air-gap-bundle.md) | `task fe-check` fails the build on any external reference; Swagger UI served from the vendored package (ADR-0020) |
| [No object identity in any SPA URL](invariants/object-nav-no-url-identity.md) | sessionStorage ref (15-min) + form-POST/303/one-shot-meta deep link; URL stays the clean route (ADR-0040) |
| [Security-header layer](invariants/security-header-layer.md) | 4.1 header set on every response; `/api/*` no-store via url_rule; HSTS only over TLS (ADR-0026/0027) |
| [Object views trim machine-managed annotations](invariants/object-view-annotation-trim.md) | Data views' Annotations table drops the two 4.1 trimAnnotations keys; the JSON block keeps the full object (overrides the 2026-10-28 verbatim deviation) |

## gotchas/

| Concept | One-line summary |
|---|---|
| [KubeDataTable stale render closures](gotchas/datatables-react-stale-render-closure.md) | Render fns bind at init only — join late query data into the row (Nodes.tsx pattern), not the closure (500e13e4) |
| [PVC Bound is a phase, not a condition](gotchas/kube-pvc-bounded-phase-not-condition.md) | `kubectl wait --for=condition=Bound` on a PVC can never pass; wait on `jsonpath='{.status.phase}'=Bound` (ce6d0b19) |

## workflows/

| Concept | One-line summary |
|---|---|
| [OIDC login → session → API access](workflows/oidc-login-session.md) | Login 302 → cookie issue → per-request JWT verify + SAR → single in-flight refresh → logout revocation |
| [Object deep link](workflows/object-deep-link.md) | In-tab open via the ref; cross-tab share via form POST → 303 → `obj_incoming` stash → one-shot meta → relay adoption |
| [Leader election → task execution → failover](workflows/leader-task-execution.md) | Candidate replicas, advisory-lock acquisition, 5 s/10 s heartbeat/stale, INTERVALS enqueue, worker, failover bound |
| [Frontend build → sync → serve](workflows/frontend-build-serve.md) | fe-build (tsc+eslint+vite) → fe-check air-gap gate → fe-sync sha256 stamp → Gunicorn-served static; image copies dist |

## reference/

| Concept | One-line summary |
|---|---|
| [Live architecture document](reference/live-architecture.md) | Pointer to `.skillgrid/ARCHITECTURE.md` with the document-division-of-labor table and its known-staleness notes |
| [Feature roadmap + open/deferred](reference/feature-roadmap.md) | Pointer to ARCHITECTURE.md §7A (roadmap) / §11 (open-deferred); roadmap items are not constraints; 2026-11-06 research findings (mcp-server, ai-investigations, change-timeline, workload-map) captured in the spec zone |
| [Research findings — durable](reference/06-research-findings.md) | Cross-change findings that outlive their source change; append-only. Currently: jscpd dead-code detection characteristics (false positives, entry-point blind spot, string wiring) from 2026-11-07-dead-code-cleanup |
