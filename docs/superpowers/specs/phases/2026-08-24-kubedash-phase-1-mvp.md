# Phase 1: MVP — Core Dashboard

## Goal
Deliver a minimal but production-ready Kubernetes dashboard that can connect to a cluster, authenticate users via ServiceAccount tokens, discover resources including CRDs, and render them in a CoreUI-based interface with observability and deployment tooling.

## Scope

### In Phase 1
- development environment start with docker compose and Taskfile
- Flask app with Blueprint architecture
- PostgreSQL-backed sessions and metadata
- ServiceAccount token authentication
- Kubernetes API discovery: namespaces, pods, deployments, services, nodes, and CRDs
- REST API v1 with Flask-Smorest + Swagger UI
- CoreUI + Bootstrap 5 frontend with Vite build
- OpenTelemetry and Prometheus `/metrics`
- Docker Compose for local development
- Helm chart for production deployment
- Kubectl config download: bearer-token kubeconfig for ServiceAccount users, cert-based kubeconfig storage for future local users

### Out of Phase 1
- Kubernetes Extension API Server (`/apis` aggregation layer)
- OIDC/SSO
- GitOps detection (ArgoCD, Flux)
- Cloud shell
- Socket-based pod exec / log viewer
- AI chat / debugging assistant
- Plugin registry beyond core resources
- kdlogin kubectl plugin
- MkDocs documentation site

---

## Repository Structure

```
kubedash/
├── kubedash/
│   ├── kubedash/
│   │   ├── __init__.py
│   │   ├── app.py                # Flask app factory
│   │   ├── config.py             # INI-based configuration loader
│   │   ├── extensions.py         # Flask extensions init
│   │   ├── models/               # SQLAlchemy models
│   │   │   ├── session.py        # Session model for SQLAlchemy session backend
│   │   │   ├── user.py           # User, Role, UsersRoles models
│   │   │   ├── k8s_config.py     # K8s cluster connection config
│   │   │   ├── kubectl_config.py # Kubectl config fragments
│   │   │   ├── audit_log.py      # Audit log model
│   │   │   └── metrics.py        # Node and pod metrics models
│   │   ├── schemas/              # Flask-Smorest marshmallow schemas
│   │   │   ├── namespace.py
│   │   │   ├── pod.py
│   │   │   ├── deployment.py
│   │   │   ├── service.py
│   │   │   └── node.py
│   │   ├── blueprints/
│   │   │   ├── auth/             # ServiceAccount token login/logout
│   │   │   ├── api/              # REST API v1 + Swagger UI
│   │   │   ├── monitoring/       # Prometheus metrics, OTel
│   │   │   └── dashboard/        # Main UI views
│   │   └── lib/                  # Shared libraries
│   │       ├── k8s/              # Kubernetes client wrappers
│   │       │   ├── __init__.py
│   │       │   ├── client.py     # k8sClientConfigGet, client init
│   │       │   ├── namespace.py
│   │       │   ├── workload.py
│   │       │   ├── network.py
│   │       │   ├── node.py
│   │       │   └── crds.py       # CRD discovery via GET /apis
│   │       ├── sso.py            # ServiceAccount token validation
│   │       └── opentelemetry.py  # OTel setup
│   ├── templates/                # CoreUI Jinja2 base + pages
│   ├── static/                   # Collected Vite assets
│   ├── migrations/               # Alembic migrations
│   ├── kubedash.ini.example      # Example INI configuration
│   ├── pyproject.toml            # Poetry config
│   └── wsgi.py
├── deploy/
│   ├── helm/                     # Helm chart for production
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   └── templates/
│   │       ├── deployment.yaml
│   │       ├── service.yaml
│   │       ├── serviceaccount.yaml
│   │       └── secret.yaml
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

## Key Components

### 1. Configuration (INI-based)
- `config.py` reads `kubedash.ini`
- Sections: `[config]`, `[database]`, `[prometheus]`, `[opentelemetry]`
- Environment variable overrides for containerized deployments

### 2. Authentication
- ServiceAccount token auth only
- User pastes token → validated against cluster API server
- Short-lived Flask session cookie
- No token persistence to PostgreSQL

### 3. Kubectl Config Download
- API endpoint generates kubeconfig files for download
- **ServiceAccount users**: Bearer-token kubeconfig generated on-the-fly from session token
  - Token sourced from Flask session, never persisted to database
  - Cluster info from `k8s_config` table
- **Certificate-based config storage**: `kubectl_config` table stores `private_key` and `user_certificate` for local users
  - Available in Phase 1 for future cert-based auth
  - Full cert-based local user auth is Phase 2
- API returns structured kubeconfig data for frontend assembly or direct YAML download
- Audit log entry created on each kubeconfig download

### 4. Frontend
- Vite build for CoreUI + Bootstrap 5 assets
- Collected into Flask `static/` and served by Gunicorn
- Jinja2 templates for page structure
- Responsive sidebar and resource tables

### 5. Observability
- OpenTelemetry Flask instrumentation with OTLP exporter
- Prometheus `/metrics` endpoint
- Structured JSON logging

### 6. Deployment
- Docker Compose: KubeDash app + PostgreSQL
- Helm chart: Deployment, Service, ServiceAccount, Secrets

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | App starts and connects to a Kubernetes cluster via ServiceAccount token | Manual login flow + API call |
| 2 | User can download kubeconfig with ServiceAccount bearer token | Download returns valid kubeconfig YAML |
| 3 | User can list namespaces, pods, deployments, services, and nodes | UI tables populated from API |
| 4 | Swagger UI documents REST API | `/api/docs` loads successfully |
| 5 | Prometheus metrics exposed | `/metrics` returns data |
| 6 | OpenTelemetry traces exported | Trace appears in configured backend |
| 7 | Docker Compose starts dev environment in one command | `task dev` succeeds |
| 8 | Helm chart deploys to Kubernetes | `helm install` succeeds |
| 9 | **100% test coverage** for all Phase 1 code | `pytest --cov=kubedash --cov-report=term-missing` shows 100% coverage; no `--cov-fail-under` override |

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| Flask | Web framework |
| Flask-Smorest | REST API + Swagger UI |
| Flask-SQLAlchemy | ORM |
| Flask-Session | PostgreSQL-backed sessions |
| Gunicorn | WSGI server |
| Kubernetes Python client | K8s API access |
| OpenTelemetry | Distributed tracing |
| Prometheus Flask Exporter | Metrics |
| Bootstrap 5 + CoreUI | Frontend framework |
| Vite | Frontend build tool |
| Poetry | Python dependency management |
| Docker Compose | Dev environment |
| Helm | Production deployment |
| MkDocs | Documentation |

---

## Testing

Phase 1 requires **100% test coverage** for all application code. Coverage is measured by `pytest-cov` against the `kubedash` package. No coverage threshold overrides are permitted.

### Test Structure

```
kubedash/kubedash/
├── tests/
│   ├── conftest.py                 # Shared fixtures (app, db, test client, mock K8s client)
│   ├── unit/
│   │   ├── test_config.py          # Configuration loading and env overrides
│   │   ├── test_models.py          # Model creation, relationships, constraints
│   │   ├── test_k8s_client.py      # Kubernetes client wrapper and connection helpers
│   │   ├── test_k8s_namespace.py   # Namespace listing and filtering
│   │   ├── test_k8s_workload.py    # Pod/deployment/service/node getters
│   │   ├── test_k8s_crds.py        # CRD discovery via /apis
│   │   ├── test_sso.py             # ServiceAccount token validation and session auth
│   │   └── test_kubeconfig.py      # Kubeconfig generation for SA and cert users
│   ├── integration/
│   │   ├── test_auth_flow.py       # ServiceAccount login/logout/session lifecycle
│   │   ├── test_workload_api.py    # REST endpoints for namespaces, pods, deployments, services, nodes
│   │   ├── test_kubeconfig_api.py  # Kubeconfig download endpoint, audit logging
│   │   ├── test_database.py        # Migrations, schema, constraints, seed data
│   │   └── test_monitoring.py      # /metrics endpoint, OTel instrumentation
│   └── security/
│       ├── test_api_security.py    # Authentication, authorization, input validation
│       ├── test_session_security.py # Session cookie flags, CSRF, timeout
│       └── test_k8s_api_security.py # K8s client hardening, least privilege
```

### Coverage Requirements

| Scope | Requirement |
|-------|-------------|
| `kubedash/` package | **100% line + branch coverage** |
| `tests/` directory | Excluded from coverage measurement |
| Missing lines/branches | CI fails on any missing coverage |
| Report format | `term-missing` to show exact missing lines in CI logs |

### Enforcement

```xml
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
addopts = "--cov=kubedash --cov-report=term-missing --cov-fail-under=100"
```

### Test Categories

| Category | Tools | Purpose |
|----------|-------|---------|
| Unit | pytest, pytest-mock | Test individual functions, models, helpers in isolation |
| Integration | pytest, Flask test client, responses | Test full request/response cycle with mocked K8s API |
| Security | pytest | Test authz, authn, input validation, injection prevention |
| E2E | pytest-playwright (optional) | Critical user flows: login, list resources, download kubeconfig |

### Mocking Strategy

- **Kubernetes client**: Mocked via `unittest.mock` or `pytest-mock`; no real cluster required for unit/integration tests
- **Database**: SQLite in-memory for tests (`sqlite:///:memory:`); PostgreSQL only in Docker Compose
- **Sessions**: Flask test client with configured session interface
- **OTel/Prometheus**: Disabled or mocked in tests to avoid external dependencies

### CI Requirements

- PRs must pass `pytest --cov=kubedash --cov-report=term-missing` before merge
- Coverage report posted as artifact or comment
- Any drop below 100% blocks merge

---

## Out of Scope (Phase 2+)

- OIDC/SSO
- GitOps detection
- Cloud shell
- Pod exec / log streaming
- AI chat
- Plugin registry
- kdlogin
- Multi-cluster support
- Advanced RBAC caching
- Protected projects
