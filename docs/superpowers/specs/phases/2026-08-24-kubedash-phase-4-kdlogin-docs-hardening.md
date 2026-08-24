# Phase 4: kdlogin, Documentation, and Production Hardening

## Goal
Complete the KubeDash ecosystem with the kdlogin kubectl plugin, full documentation, and production-ready hardening.

## Scope

### In Phase 4
- Kubernetes Extension API Server (`/apis` aggregation layer)
- kdlogin Go-based kubectl plugin for automatic SSO login
- MkDocs documentation site
- Security hardening
- Performance optimization
- Multi-cluster support

### Out of Phase 4
- New CRD plugins (community-driven)
- Advanced GitOps features
- Cloud shell extensions

---

## Key Components

### 1. Kubernetes Extension API Server
- Implements a Kubernetes Extension API Server compatible with the API Aggregation Layer
- Registered with the Kubernetes API server via `APIService` objects
- Discovery endpoints: `/apis`, `/apis/kubedash.devopstales.github.io`, `/apis/kubedash.devopstales.github.io/v1`, `/apis/kubedash.devopstales.github.io/v1/projects`
- Kubernetes-style responses: `APIGroupList`, `APIGroup`, `APIResourceList`, `ProjectList`, `Project`, `Status`, `Table`
- Three-tier authentication: front-proxy headers, Bearer token via `TokenReview`, Flask session
- Authorization via `SubjectAccessReview` for namespace filtering
- `Project` resource maps namespaces to permission-filtered projects
- Health checks: `/apis/healthz`, `/healthz`
- OpenAPI specs: `/apis/openapi/v2`, `/openapi/v2`, `/openapi/v3`
- kubectl-compatible `Table` format responses

### 2. kdlogin Kubectl Plugin
- Go-based kubectl plugin for automatic SSO login
- OIDC-based authentication flow
- Writes kubeconfig with SSO token
- Supports multiple clusters
- Commands: `kubectl kdlogin`, `kubectl kdlogin logout`

### 3. Documentation
- MkDocs with Material theme
- User guide: installation, authentication, navigation
- Developer guide: contributing, plugin development
- API reference from Swagger UI
- Hosted on GitHub Pages

### 4. Security Hardening
- Security headers (CSP, HSTS, X-Frame-Options)
- Rate limiting on authentication endpoints
- Input validation and sanitization
- SQL injection prevention
- XSS prevention
- CSRF protection
- Security testing suite

### 5. Performance Optimization
- Response caching for K8s API calls
- Connection pooling for Kubernetes client
- Async metrics collection
- Frontend asset optimization

### 6. Multi-Cluster Support
- Multiple K8s context management
- Cluster selector in UI
- Per-cluster authentication state

---

## kdlogin Structure

```
kdlogin/
├── cmd/kdlogin/
│   ├── root.go
│   ├── login.go
│   ├── logout.go
│   └── version.go
├── pkg/
│   ├── auth/
│   │   └── oidc.go
│   ├── kubeconfig/
│   │   └── writer.go
│   └── cluster/
│       └── selector.go
├── go.mod
└── go.sum
```

---

## Documentation Structure

```
docs/
├── index.md
├── getting-started/
│   ├── installation.md
│   ├── configuration.md
│   └── authentication.md
├── user-guide/
│   ├── dashboard.md
│   ├── projects.md
│   ├── workloads.md
│   └── gitops.md
├── developer-guide/
│   ├── contributing.md
│   ├── plugin-development.md
│   └── api-reference.md
├── mkdocs.yml
└── material/
```

---

## Security Testing

| Test Suite | Purpose |
|------------|---------|
| API security | Authentication, authorization, input validation |
| Authentication security | Session management, token handling |
| Authorization security | RBAC enforcement, privilege escalation |
| CSRF protection | Form token validation |
| SQL injection | ORM query safety |
| XSS prevention | Output encoding |
| Dependency security | SCA scanning |

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Extension API registered with Kubernetes API aggregation | `kubectl get apiservices` shows KubeDash API service |
| 2 | `kubectl get projects` works via extension API | kubectl lists permission-filtered projects |
| 3 | kdlogin plugin authenticates via OIDC and writes kubeconfig | `kubectl kdlogin` completes successfully |
| 4 | Documentation site builds and deploys | MkDocs build succeeds |
| 5 | Security headers present in responses | Header inspection |
| 6 | Rate limiting active on auth endpoints | Load test shows throttling |
| 7 | Multi-cluster selector works | Switching clusters updates all views |
| 8 | Performance benchmarks met | API p95 < 500ms under load |

---

## Dependencies Added

| Dependency | Purpose |
|------------|---------|
| kdlogin Go modules | OIDC client, kubeconfig writer |
| MkDocs + Material | Documentation |
| limiter | Rate limiting |
| defusedxml | XML security |
