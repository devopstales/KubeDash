# Phase 2: Authentication, GitOps, and Plugin Registry

## Goal
Extend the MVP with enterprise authentication, GitOps awareness, and a plugin registry that allows first-party and community extensions.

## Scope

### In Phase 2
- OIDC/SSO authentication with PKCE
- GitOps detection: ArgoCD and Flux CD
- Plugin registry with first-party plugins
- AI chat plugin for debugging assistance
- Project object with protected namespace support
- Advanced RBAC caching

### Out of Phase 2
- Cloud shell
- Socket-based pod exec / log viewer
- kdlogin kubectl plugin
- Multi-cluster support
- MkDocs documentation site
- Advanced CRD rendering beyond core resources

---

## Key Components

### 1. OIDC / SSO
- Configurable OIDC discovery URL
- Authorization code flow with PKCE
- Token refresh via refresh tokens
- Session storage; tokens never persisted to PostgreSQL
- SSO server configuration stored in database

### 2. GitOps Detection
- Startup discovery of ArgoCD CRDs (`argoproj.io`)
- Startup discovery of Flux CD CRDs (`source.toolkit.fluxcd.io`)
- GitOps status API endpoints
- WebSocket-based real-time GitOps object updates

### 3. Plugin Registry
- Startup-time plugin discovery from `plugins/` directory
- INI-based enable/disable per plugin
- Plugin blueprint and API auto-registration
- Plugin database model auto-detection (`model.py` or `models.py`)
- First-party plugins: AI chat, cert-manager, external load balancer, helm, gateway API, trivy operator

### 4. AI Chat Plugin
- In-app chatbot for natural-language Kubernetes queries
- OpenAI-compatible LLM providers
- Local minimal chatbot mode
- Streaming responses via Flask-SocketIO
- Context-aware: current namespace, pod status, events

### 5. Project Object
- OpenShift-like project selector in UI
- `SubjectAccessReview` for namespace access
- Protected project annotation
- Cached in PostgreSQL, refreshed on login

### 6. RBAC Caching
- Cache `SubjectAccessReview` results per user per session
- Invalidate on token refresh or explicit re-auth

---

## Blueprint Additions

| Blueprint | Purpose | Key Endpoints |
|-----------|---------|---------------|
| `auth` | OIDC/SSO flow | `/auth/login`, `/auth/callback`, `/auth/token/verify`, `/auth/refresh` |
| `gitops` | ArgoCD/Flux detection | `/api/v1/gitops/status`, WebSocket `/gitops` |
| `plugins` | Plugin APIs | `/api/v1/plugins/ai-chat/*`, etc. |

---

## Plugin Registry API

```python
class PluginRegistry:
    def __init__(self):
        self.auth_providers = {}
        self.k8s_resource_handlers = {}
        self.gitops_providers = {}
        self.monitoring_providers = {}

    def register_auth(self, name, provider): ...
    def register_k8s_resource(self, group_version, kind, handler): ...
    def register_gitops(self, name, provider): ...
```

---

## Database Changes

- `openid` table for OIDC server configuration
- `projects` caching table
- Plugin-specific tables via plugin models

---

## Frontend Changes

- OIDC login button
- Project selector dropdown
- GitOps dashboard page
- AI chat panel

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | User can log in via OIDC/SSO | OAuth flow completes, session created |
| 2 | ArgoCD and Flux CRDs detected on startup | GitOps status API returns data |
| 3 | AI chat plugin loads and responds | Chat UI streams response |
| 4 | Plugin registry auto-discovers enabled plugins | Plugin APIs registered at `/api/v1/plugins/*` |
| 5 | Project selector filters namespaces by permission | UI shows accessible namespaces only |
| 6 | Protected projects cannot be deleted | Delete button disabled or returns 403 |

---

## Dependencies Added

| Dependency | Purpose |
|------------|---------|
| requests-oauthlib | OIDC flow |
|Authlib | OIDC client |
| Flask-SocketIO | Real-time GitOps and AI chat |
