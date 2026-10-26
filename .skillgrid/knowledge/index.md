# KubeDash — Knowledge Base Index

> One-line catalog of every concept in the bundle. Every write to a concept
> file updates this file in the same edit (same-edit rule).

## decisions/

| Concept | One-line summary | Status |
|---|---|---|
| [ADR-0014 — Session revocation propagation](decisions/04-adr-0014-session-revocation-propagation.md) | Web logout kills the kubectl session (revocation must reach the CLI) | accepted |
| [ADR-0015 — Namespace-as-a-Service](decisions/04-adr-0015-namespace-as-a-service.md) | Self-service namespace onboarding + TTL'd grants | accepted |
| [ADR-0016 — Privileged Access Management](decisions/04-adr-0016-privileged-access-management.md) | Additive elevation + auto-revert + break-glass | accepted |
| [ADR-0017 — Just-In-Time login provisioning](decisions/04-adr-0017-jit-login-provisioning.md) | Helm-declared builtin pipeline provisions users on first login | accepted |
| [ADR-0018 — SCIM 2.0 Gateway](decisions/04-adr-0018-scim-2-0-gateway.md) | IdP/HR push; identity decoupled from bindings | accepted |
| [ADR-0019 — Ingress Auth Integration](decisions/04-adr-0019-ingress-auth-integration.md) | `/auth/verify` for NGINX/Traefik/Istio/Gateway API | accepted |
| [ADR-0020 — Air-Gap Deployment](decisions/04-adr-0020-air-gap-deployment.md) | Zero outbound calls at runtime; air-gap ≠ no-IdP (superseded-in-part by ADR-0021) | accepted |
| [ADR-0021 — Local Admin Auth](decisions/04-adr-0021-local-admin-auth.md) | Bootstrap password mode; admin kubeconfig source; SSO stays primary | accepted |
| [ADR-0022 — Sidebar navigation](decisions/04-adr-0022-sidebar-nav-4-1-parity.md) | 4.1 information-parity menu structure; Plugins group dropped | accepted |
| [ADR-0023 — DataTables React](decisions/04-adr-0023-datatables-react.md) | User-management lists use DataTables React with the Bootstrap 5 skin | accepted |
| [ADR-0024 — Secret syntax highlight](decisions/04-adr-0024-secret-syntax-highlight.md) | Secret values use react-syntax-highlighter (an-old-hope theme) | accepted |
| [ADR-0025 — HttpOnly session cookie](decisions/04-adr-0025-http-only-session-cookie.md) | Session in HttpOnly cookies; Bearer retained for the kubectl plugin | accepted |
| [ADR-0026 — TLS edge + security headers](decisions/04-adr-0026-tls-edge-and-security-headers.md) | nginx TLS edge; ProxyFix gated on KUBEDASH_TLS_EDGE; 4.1 header set restored | accepted |

> ADR-0001..0013: index rows exist in `ASSUMPTIONS.md` § LOCKED; their files
> are not yet authored (open task).

## glossary/

| Concept | One-line summary |
|---|---|
| [Business terms](glossary/01-business-terms.md) | Domain / product / workflow vocabulary |
| [Technical terms](glossary/02-technical-terms.md) | Architecture / platform / protocol vocabulary |

## invariants/

*(none yet)*

## workflows/

*(none yet)*

## reference/

*(none yet)*
