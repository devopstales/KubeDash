# KubeDash Architecture Design

## Goal
Design an enterprise-grade open-source Kubernetes dashboard called **KubeDash**, built with Python/Flask, Gunicorn, Bootstrap 5, and CoreUI. The system should provide CRD-aware visualization, GitOps detection, authentication via ServiceAccount tokens and OIDC/SSO, AI-assisted debugging, socket-based terminal/log viewer, cloud shell, and an extensible plugin registry.

---

## 1. Repository Layout (Monorepo)

```
kubedash/
├── kubedash/                     # Python application
│   ├── kubedash/
│   │   ├── __init__.py
│   │   ├── app.py                # Flask app factory
│   │   ├── config.py             # INI-based configuration loader
│   │   ├── extensions.py         # Flask extensions init
│   │   ├── models/               # SQLAlchemy models
│   │   ├── schemas/              # Flask-Smorest marshmallow schemas
│   │   ├── blueprints/           # Feature blueprints
│   │   │   ├── auth/             # Login, ServiceAccount, OIDC/SSO
│   │   │   ├── api/              # REST API v1 + Swagger UI
│   │   │   ├── k8s/              # Kubernetes extension API (CRD-aware)
│   │   │   ├── gitops/           # ArgoCD/Flux detection
│   │   │   ├── monitoring/       # Prometheus metrics, OTel
│   │   │   ├── workload/         # Pods, deployments, exec, logs, terminal
│   │   │   ├── cloudshell/       # Cloud shell with configurable base image
│   │   │   └── dashboard/        # Main UI views
│   │   └── plugins/              # Plugin registry + loaders (AI chat, cert-manager, etc.)
│   ├── templates/                # Jinja2 templates (CoreUI base)
│   ├── static/                   # Bundled CSS/JS/images
│   ├── migrations/               # Alembic migrations
│   ├── kubedash.ini.example      # Example INI configuration
│   ├── pyproject.toml            # Poetry config
│   └── wsgi.py
├── kdlogin/                      # Go-based kubectl plugin (v2)
│   ├── cmd/kdlogin/
│   ├── pkg/
│   └── go.mod
├── deploy/
│   ├── helm/                     # Helm chart for production
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   └── templates/
│   └── compose/                  # Docker Compose for dev
│       ├── docker-compose.yml
│       └── .env.example
├── docs/
│   └── mkdocs.yml                 # MkDocs configuration
├── scripts/
├── Taskfile.yml                  # Task automation
└── pyproject.toml                # Root Poetry workspace
```

---

## 2. Configuration

KubeDash uses **INI-based configuration** via `kubedash.ini`, following the v4 pattern.

### Config Sections
- `[config]` — Core settings (secret key, session lifetime, K8s context)
- `[database]` — PostgreSQL connection URI
- `[oidc]` — OIDC/SSO provider settings
- `[plugins]` — Enable/disable plugins
- `[ai_chat]` — LLM provider configuration
- `[cloudshell]` — Cloud shell base image, resource limits
- `[prometheus]` — Prometheus endpoint configuration
- `[opentelemetry]` — OTLP exporter endpoint

### Loading
- `config.py` reads `kubedash.ini` using Python's `configparser`
- Environment variable overrides for containerized deployments
- No hardcoded secrets; all sensitive values via env vars or Kubernetes secrets

---

## 3. Plugin / Extension Registry

KubeDash uses a **startup-time plugin registry** inspired by v4. No hot-reloading.

### Registry API

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

### Discovery Flow

1. App starts → read `[plugins]` section from `kubedash.ini`
2. Scan `plugins/` directory for enabled plugins
3. For each enabled plugin, import its blueprint and register with Flask
4. Initialize plugin database models via `db.create_all()` if present
5. For K8s resources: call `GET /apis`, enumerate CRDs, match against plugin handlers

This enables third parties to contribute handlers for new CRDs without modifying core KubeDash code.

---

## 4. Blueprint Layout

| Blueprint | Purpose | Key Endpoints |
|-----------|---------|---------------|
| `auth` | Login, logout, token validation, OIDC flow | `/auth/login`, `/auth/callback`, `/auth/token/verify` |
| `api` | Flask-Smorest REST API + Swagger UI | `/api/v1/...`, `/api/docs` |
| `k8s` | Kubernetes extension API (CRD-aware) | `/api/v1/k8s/resources`, dynamic CRD routes |
| `gitops` | ArgoCD/Flux detection and status | `/api/v1/gitops/status` |
| `monitoring` | Prometheus metrics, OTel integration | `/metrics`, `/health` |
| `workload` | Pods, deployments, exec, logs, terminal | `/workloads/*`, `/api/v1/exec`, `/api/v1/logs` |
| `cloudshell` | Cloud shell with configurable base image | `/cloudshell/*`, `/api/v1/cloudshell` |
| `dashboard` | Main UI pages | `/`, `/dashboard/*`, `/projects/*` |

---

## 5. Authentication

### ServiceAccount Token Auth
- User pastes a K8s SA token
- KubeDash validates it against the cluster API server
- Exchanges for a short-lived session cookie

### OIDC / SSO
- Configurable OIDC discovery URL (Dex, Keycloak, Entra ID, etc.)
- Standard authorization code flow with PKCE
- Token refresh handled automatically
- Both auth methods stored as Flask sessions
- Tokens are **never persisted** to PostgreSQL (only session metadata)

### RBAC
- KubeDash calls `SubjectAccessReview` to determine which namespaces/resources the user can see
- Results cached per session

---

## 6. Kubernetes "Project" Object

- A **Project** maps to a set of namespaces the authenticated user has access to
- On login, KubeDash calls `SubjectAccessReview` for `list namespace` permission
- Displayed in the UI as an OpenShift-like project selector
- Cached in PostgreSQL, refreshed on each login
- Protected projects cannot be deleted via the UI

---

## 7. Workload Features

### Pod Exec (Socket-based Terminal)
- Uses `kubernetes.stream` to connect to pod exec via WebSocket
- Flask-SocketIO namespace `/exec` handles bidirectional terminal I/O
- Client sends keystrokes → server writes to pod stdin → server reads stdout/stderr → client renders in xterm.js
- Support for multiple terminal sessions per user

### Log Viewer
- WebSocket-based log streaming from Kubernetes pods
- Real-time log tail with follow mode
- Log level filtering and search

### Pod Management
- List pods, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs
- View pod details, environment variables, security context, volumes
- Scale deployments, restart pods

---

## 8. Cloud Shell

- Web-based terminal accessible from the KubeDash UI
- Configurable base image (default: `bitnami/kubectl:latest`)
- Runs as a pod in the user's selected namespace
- Flask-SocketIO for terminal I/O (same pattern as pod exec)
- Pre-installed tools: `kubectl`, `helm`, `kustomize`, `git`
- Resource limits configurable per namespace or globally
- Session timeout and idle disconnect

---

## 9. AI Help for Debugging

- In-app AI chatbot for natural-language Kubernetes cluster queries
- Built as a plugin (`plugins/ai_chat/`) following v4 pattern
- Supports OpenAI-compatible LLM providers (ChatGPT, Ollama, Gemini, Azure)
- Local mode with minimal chatbot (pattern-based; no external LLM)
- Streaming responses via Flask-SocketIO
- Context-aware: includes current namespace, pod status, recent events
- No MCP server required; uses lib/k8s for cluster operations

---

## 10. Frontend (CoreUI + Bootstrap 5)

**Primary approach:** Vite-based frontend build producing static assets that are collected into Flask's `static/` directory and served by Gunicorn.

**Fallback:** If the Vite build proves too complex, fall back to server-rendered Jinja2 templates with Flask-Assets bundling Bootstrap 5.

- Sidebar navigation dynamically populated based on discovered K8s resources and user permissions
- Real-time updates via Flask-SocketIO (pod status, logs, terminal, cloud shell)
- Swagger UI embedded at `/api/docs` for API exploration
- xterm.js for terminal emulation (pod exec and cloud shell)
- CoreUI components for dashboard layout

---

## 11. Observability

- **OpenTelemetry**: Flask auto-instrumentation, export to configurable OTLP collector
- **Prometheus**: `/metrics` endpoint using `prometheus_flask_exporter`
  - Request latency, active users, K8s API call counts
- Structured JSON logging via Python `logging`

---

## 12. Data Layer

- **Database**: PostgreSQL only (no pluggable backends)
- **ORM**: Flask-SQLAlchemy with Alembic migrations
- **Session storage**: PostgreSQL-backed Flask sessions
- **No token persistence**: Auth tokens kept in memory/session only
- **Plugin models**: Each plugin can define `model.py` or `models.py` for its tables

---

## 13. Development Environment

| Tool | Purpose |
|------|---------|
| **Poetry** | Python dependency management, virtualenv, scripts |
| **Docker Compose** | KubeDash app + PostgreSQL + (optional) Kind cluster |
| **Taskfile** | `task dev` (start compose), `task build` (docker build), `task test`, `task lint` |
| **pytest** | Unit + integration tests |
| **ruff** | Linting |
| **MkDocs** | Documentation generation |

---

## 14. Documentation

- **MkDocs** with Material theme for user and developer documentation
- Hosted on GitHub Pages or as a static site
- Sections: Getting Started, Authentication, Plugins, API Reference, Development

---

## 15. Deployment

| Environment | Method |
|-------------|--------|
| **Development** | `docker compose up` — app on `localhost:5000`, PostgreSQL on `5432` |
| **Production** | Helm chart with configurable values (replicas, resources, OIDC config, K8s SA) |

### Helm chart creates:
- Deployment (Gunicorn workers)
- Service (ClusterIP)
- Ingress (optional, for SSO callback)
- ServiceAccount for K8s API access
- Secret for OIDC client credentials

---

## 16. v2 Roadmap

- **kdlogin**: Go-based kubectl plugin that automates OIDC login and writes kubeconfig
- Additional plugin handlers contributed by community

---

## Decisions

| Decision | Rationale |
|----------|-----------|
| Startup discovery only | Simpler implementation, sufficient for v1 |
| Separate frontend build (Vite) with Jinja2 fallback | Better frontend DX, served as static assets by Gunicorn; pragmatic fallback if toolchain is burdensome |
| PostgreSQL only | Matches enterprise requirements, avoids SQLite production risks |
| INI-based config | Proven in v4, easy to override with env vars in containers |
| Flask-SocketIO for terminal/logs | Reuses existing WebSocket infrastructure from v4 |
| Plugin-based architecture | Mirrors v4 success; enables community extensions |
