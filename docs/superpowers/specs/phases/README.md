# KubeDash Implementation Phases

This directory contains the phased implementation plan for KubeDash.

## Phase Overview

| Phase | Name | Focus | Status |
|-------|------|-------|--------|
| 1 | MVP | Core dashboard, ServiceAccount auth, CRD discovery, CoreUI, observability | Spec ready |
| 2 | Auth, GitOps, Plugins | OIDC/SSO, ArgoCD/Flux detection, plugin registry, AI chat | Spec ready |
| 3 | Interactive Features | Pod exec, log streaming, cloud shell | Spec ready |
| 4 | kdlogin, Docs, Hardening | kubectl plugin, documentation, security, performance | Spec ready |

## Phase 1: MVP

**File:** `phases/2026-08-24-kubedash-phase-1-mvp.md`

Delivers a minimal but production-ready Kubernetes dashboard:
- Flask app with Blueprint architecture
- PostgreSQL-backed sessions
- ServiceAccount token authentication
- CRD auto-discovery via `GET /apis`
- Core resources: namespaces, pods, deployments, services, nodes
- REST API v1 with Flask-Smorest + Swagger UI
- CoreUI + Bootstrap 5 frontend with Vite build
- OpenTelemetry and Prometheus `/metrics`
- Docker Compose for dev, Helm chart for production

## Phase 2: Auth, GitOps, and Plugins

**File:** `phases/2026-08-24-kubedash-phase-2-auth-gitops-plugins.md`

Extends MVP with enterprise features:
- OIDC/SSO authentication with PKCE
- GitOps detection for ArgoCD and Flux CD
- Plugin registry with first-party plugins
- AI chat plugin for debugging
- Project object with protected namespace support
- Advanced RBAC caching

## Phase 3: Interactive Features

**File:** `phases/2026-08-24-kubedash-phase-3-interactive-features.md`

Adds interactive cluster debugging:
- Socket-based pod exec terminal via Flask-SocketIO
- Real-time log streaming with follow mode
- Cloud shell with configurable base image
- xterm.js frontend integration
- Advanced workload management (scale, restart)

## Phase 4: kdlogin, Docs, and Hardening

**File:** `phases/2026-08-24-kubedash-phase-4-kdlogin-docs-hardening.md`

Completes the ecosystem:
- kdlogin Go-based kubectl plugin for automatic SSO login
- MkDocs documentation site
- Security hardening (headers, rate limiting, input validation)
- Performance optimization
- Multi-cluster support

## How to Use

1. Review the architecture design at `../2026-08-24-kubedash-architecture-design.md`
2. Implement each phase sequentially using the phase-specific spec
3. Each phase spec contains acceptance criteria for verification
4. Use the writing-plans skill to create detailed implementation plans per phase
