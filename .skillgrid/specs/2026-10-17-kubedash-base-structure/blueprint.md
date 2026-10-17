# KubeDash 5.0 Base Structure — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-execution (recommended) or simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2

**Build shape:** Tracer thread — the auth → cluster → pods → SPA path works end-to-end by Task 10; every later task thickens one module. Chosen because integration risk (Flask-Smorest + OIDC + k8s client + SPA + single-container build) is the unknown, and the in-flight kubectl-oidc-plugin change needs Tasks 1–3 to hang its endpoint on.

**Goal:** Materialize the KubeDash 5.0 monorepo skeleton per ARCHITECTURE.md §2 with a real, tested tracer spine (app factory + config, OIDC auth, cluster registry, one resource list, SPA shell, CI green) and ADR-pointing stubs for every other module.

**Architecture:** Python 3.12 Flask app factory with Flask-Smorest domain APIs (Pydantic schemas, shared JWT hook), SQLAlchemy 2.0 models, a per-cluster kubernetes client pool, and a leader-gated in-process RQ worker; a CoreUI React 18 SPA (TanStack Query + Zustand) built at image time and served by the same Gunicorn process (ADR-0006); a Go cobra CLI skeleton; a Helm chart; GitHub Actions CI. Per ADR-0001..0009; ADR-0010 (informer cache) is deferred — the client pool is the seam it later interposes at.

**Tech Stack:** Python 3.12, `uv`, Flask, Flask-Smorest, Pydantic v2, SQLAlchemy 2.0, Flask-Migrate, Flask-SocketIO, RQ, redis, kubernetes, httpx, Authlib, PyJWT, Gunicorn, pytest + Testcontainers; Node 20, pnpm, Vite 5, React 18, TypeScript strict, TanStack Query v5, React Router v6, Zustand, CoreUI free React admin template, MSW/Vitest/RTL, Playwright; Go 1.22+, cobra; Helm 3, Trivy, actionlint.

**Spec:** `.skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md` (requirements R1–R10)

## Terms

- **Tracer spine** — the R1–R5 path this change makes real; `briefing.md` § Requirements.
- **Stub module** — a §2 path that exists, imports, and carries an ADR pointer with no subsystem behavior (R9); `briefing.md` § Requirements.
- **Cluster / Cluster binding / SubjectAccessReview / Role template** — `.skillgrid/artifacts/02-technical-terms.md`.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- T1: `create_app()` constructs in a test with Testcontainers Postgres + Redis; `GET /healthz` → 200; `GET /readyz` → 200 when deps up, 503 with a body naming the failing dependency when Redis is down *(backstop — needs live containers)*
- T2: `GET /api/openapi.json` returns valid OpenAPI 3.0 JSON containing the registered domain APIs
- T3: Full OIDC round trip against a mock provider: `POST /api/v1/auth/login` → 302 to the provider `/authorize`; the callback with a code → `users` row upserted + JWT (HS256, 15 min) + refresh token stored hashed; `GET /api/v1/auth/me` → the user's `sub` *(backstop — needs the mock provider running)*
- T4: `GET /api/v1/clusters` without a JWT → 401 `{ "error": { "code": "UNAUTHORIZED" } }`; with an expired JWT → 401 (not 500)
- T5: Refresh rotation: using the same refresh token twice → the second use returns 401 and the row is deleted
- T6: `POST /api/v1/clusters` with a kubeconfig → stored bytes are AES-256-GCM ciphertext (at-rest form does not contain the plaintext); decryption with `KUBEDASH_SECRET_KEY` returns the original
- T7: A user with no binding on a registered cluster does not see it in `GET /api/v1/clusters`; a bound user does
- T8: `GET /api/v1/clusters/<id>/health` → `{"status": "up"}` against a `kind` cluster; API server down → 502 `{ "error": { "code": "CLUSTER_UNREACHABLE" } }` within a bounded timeout *(backstop — needs kind)*
- T9: `GET /api/v1/clusters/<id>/resources/pods` → 200 with the test pod from kind; a user whose binding lacks `list` on `pods` → 403 `RBAC_DENIED`; unknown kind → 404 `RESOURCE_KIND_NOT_SUPPORTED` *(backstop — needs kind for the SAR path)*
- T10: `pnpm build` in `frontend/` exits 0 producing `dist/`; `tsc --noEmit` and `eslint .` exit 0
- T11: Flask serves the built SPA: `GET /` → `index.html`; `GET /clusters/123` (a non-API path) → `index.html` (SPA fallback); `GET /api/v1/clusters` is never shadowed by the catch-all
- T12: `docker build` of `backend/Dockerfile` exits 0; the image runs non-root, serves the SPA at `/` and the API at `/api/v1/*` in one process *(backstop — needs Docker)*
- T13: `helm lint charts/kubedash` and `helm template t charts/kubedash` exit 0; the rendered Deployment carries `KUBEDASH_REPLICA_ID` from the Downward API `metadata.name` and env for DB/Redis/OIDC from values
- T14: `go build ./...` + `go test ./...` in `cli/` pass; `./kubedash version` prints `kubedash <version>`; `./kubedash get-token` exits 2 with a "not yet implemented" message
- T15: A file-map check (in the test suite) fails the suite if any `backend/app/` path listed in ARCHITECTURE.md §2 is missing
- T16: Unimplemented stub routes return 501 `{ "error": { "code": "NOT_IMPLEMENTED" } }` (e.g., `GET /api/v1/logs/query`)
- T17: `.github/workflows/ci.yaml` passes actionlint and runs ruff, mypy --strict, pytest, tsc, eslint, pnpm build, go vet, go test, helm lint + template, Trivy; `e2e.yaml` runs the Playwright login→pods journey on `main` against kind *(backstop — needs a CI run)*
- T18: `pytest backend/tests -m "not integration"` is green without a kind cluster; the full suite (with Docker + kind) is green

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/__init__.py` — `create_app()` factory
- `backend/app/extensions.py` — Smorest/SQLAlchemy/Redis/SocketIO/limiter/migrate instances, injected
- `backend/app/core/{config,security,leader,errors}.py`
- `backend/app/api/{auth,clusters,resources}.py` (spine) + the R9 stub APIs
- `backend/app/models/{user,cluster,binding,token,leader_lease}.py` + R9 stub models
- `backend/app/services/{k8s_client,rbac}.py` (spine) + R9 stub services
- `backend/app/tasks/{cluster_sync,health}.py` (real, leader-gated) + R9 stub tasks
- `backend/app/sockets/events.py` (namespace registered, no handlers)
- `backend/app/schemas/{auth,cluster,resource,errors}.py` (Pydantic)
- `backend/wsgi.py`, `backend/migrations/` (initial revision), `backend/pyproject.toml`, `backend/Dockerfile`
- `backend/tests/conftest.py` + `tests/api/`, `tests/services/`, `tests/core/`, `tests/test_file_map.py`
- `frontend/` (template + `views/Login|Clusters|Cluster/`, `lib/api.ts`, `store/`, `hooks/`, `tests/`, `e2e/`)
- `cli/{main.go,go.mod,cmd/{version,get_token,clean,setup}.go,Makefile,.krew.yaml}`
- `charts/kubedash/{Chart.yaml,values.yaml,templates/*}`
- `.github/workflows/{ci.yaml,e2e.yaml}`

**Key links** (critical connections that must work together):
- K1: `auth` Api's callback calls `core.security.issue_token_pair()` and persists via the `users`/`refresh_tokens` models; the JWT `sub` equals the OIDC `sub` that `auth/me` echoes
- K2: every non-auth Api's `on_before_request` hook verifies the JWT and stashes `flask.g.current_user`, and `clusters`/`resources` handlers filter through `cluster_bindings` + `services.rbac.can()`
- K3: `clusters` registration encrypts the kubeconfig with `core.config`'s `KUBEDASH_SECRET_KEY` before the model write; `k8s_client.get_client()` decrypts it back
- K4: the SPA's `lib/api.ts` 401-refresh retry consumes `/api/v1/auth/refresh`, and the Clusters/Cluster views consume the R3/R4 endpoints the backend defines (types generated from `/api/openapi.json`)
- K5: `wsgi.py` boots the RQ worker thread only when `KUBEDASH_ROLE=leader` and the `leader` module reports leadership; the `health_probe` task updates the `clusters.status` column that `/clusters/<id>/health` and the SPA badge read
- K6: `Dockerfile` stage 1 output (`frontend/dist/`) is copied to `backend/static/`, and the Flask catch-all registered after all API routes serves it (T11/T12)

**One-way-door decisions** (hard to reverse — explicit user approval before implementing):
- OD-1: **The `/api/v1/*` route namespace + error envelope are the public API contract** from day one (ARCHITECTURE.md §10: breaking changes bump the major version). The initial Smorest route table + `errors.py` codes freeze the v1 surface. *Task 3 (error contract) and Task 7 (resources routing table).*
- OD-2: **The encrypted-kubeconfig registry schema** (`clusters.kubeconfig_enc` AES-256-GCM under a dedicated `KUBEDASH_SECRET_KEY`, distinct from the JWT key) per ADR-0002 — changing the cipher or key domain later is a data migration. *Task 4.*
- OD-3: **The initial Alembic migration** creates `users`, `refresh_tokens`, `clusters`, `cluster_bindings`, `leader_lease` — the first migration of the v1 line. *Task 2.*
- OD-4: **The SPA catch-all + hashed-asset cache contract** (`Cache-Control: immutable` on `/assets/*`, `no-cache` on `index.html`) per ADR-0006 — load-balancer/caching behavior depends on it. *Task 9.*

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Shell commands | Applicable: `Dockerfile` (pnpm/uv/gunicorn), `Makefile` (go cross-compile), CI steps, `helm` in chart template tests | No `sh -c` string concatenation of user input; all invocations use fixed arg lists; `helm template` input is values.yaml, not request data | T12 image build; T13 template render; a test asserts `Dockerfile` RUN lines contain no unquoted `$(...)` from ARGs (grep-based) |
| Subprocesses | Applicable: `cli/` prints to stdout — kubectl parses `ExecCredential` JSON (owned by the in-flight plugin change; this change only stubs `get-token`); `go test` runs the cobra tree | `version`/`get-token` write only to stdout/stderr via cobra; no `os/exec` in this change's `cli/` code | T14: capture stdout of `version` exactly; `get-token` exit code 2, no panic trace |
| Version-control automation | N/A: this change adds no git hooks, PR automation, or branch logic (CI is a consumer, not a mutator) | — | — |
| Executable-file classification | Applicable: the built SPA is served as static files by Flask; image entrypoint is `gunicorn` | Catch-all registered after API routes only; static served via `send_from_directory` (no `send_file` with user path); image runs as non-root UID 10001 | T11: `/api/v1/clusters` not shadowed; `GET /` returns `index.html` content-type html; `docker run` entrypoint check (T12) |
| Process integration | Applicable: Gunicorn process hosts the in-process RQ worker thread (leader-gated); sync workers (no gevent until the exec/SSE-stream change) | Worker thread spawned in `wsgi.py` only when `KUBEDASH_ROLE=leader` AND the leader module wins the lease; `KUBEDASH_REPLICA_ID` from Downward API; leader heartbeat in a daemon thread | T1: readyz reports leader status; a unit test: two Leader instances against one PG, exactly one reports `is_leader()` true after lease acquisition (Task 2) |
| Mnemonic tool contracts | N/A: no mnemonic tool usage in build artifacts | — | — |
| `_shared/{planning,craft,verification,knowledge}/` files | N/A: no skillgrid `_shared` files touched | — | — |

## Global Constraints

- Python 3.12; deps via `uv`; `ruff` for lint+format; `mypy --strict`; type hints on every public signature (ARCHITECTURE.md §10).
- TypeScript strict (`noUncheckedIndexedAccess`); `pnpm`; `eslint` + `prettier`; PascalCase components, camelCase functions, kebab-case files; CoreUI SCSS — **no Tailwind** (ADR-0005, §10).
- API at `/api/v1/*` only; OpenAPI 3.0 auto-generated by Flask-Smorest at `/api/docs` + `/api/openapi.json`; error shape `{ error: { code, message, details? } }` with stable string codes (§10).
- JWT: HS256, 15 min TTL, `sub` = OIDC subject; refresh 30 d, stored hashed; key `KUBEDASH_JWT_SECRET` (distinct from `KUBEDASH_SECRET_KEY`, the AES-256-GCM key for kubeconfigs — §3.5, §3.8, ADR-0002).
- Single container: Gunicorn serves API + SPA; RQ worker in-process, leader-gated (ADR-0006, ADR-0007, ADR-0008). SSE is the push channel; WebSocket reserved for exec (ADR-0009) — this change registers the SocketIO namespace but ships no bidirectional handlers, so Gunicorn runs **sync** workers (the `gevent` worker class is the exec/SSE-stream change's decision, recorded in Task 9).
- Conventional Commits; spec-zone commits (this folder) separate from code commits (zone guard).
- Frontend server state only via TanStack Query; UI state only via Zustand (§4.4).
- Non-root container (UID 10001), `HEALTHCHECK` on `/healthz` (§7.1).

## File Structure

**Backend — spine (real logic):**
- `backend/pyproject.toml` — uv project: deps + dev deps, ruff + mypy config
- `backend/wsgi.py` — Gunicorn entrypoint: `create_app()`, RQ worker thread spawn (leader-gated)
- `backend/app/__init__.py` — `create_app()`: Flask + extension init + Smorest API + domain registration + error handlers + `/healthz`/`/readyz` + static catch-all
- `backend/app/extensions.py` — `api`, `db`, `redis_client`, `socketio`, `migrate`, `limiter` instances (not bound until factory init)
- `backend/app/core/config.py` — Pydantic `BaseSettings`, env-driven per §3.8 (dev/stage/prod via `FLASK_ENV`)
- `backend/app/core/security.py` — OIDC exchange (Authlib), `issue_token_pair()`, `verify_jwt()`, refresh rotation, jti revocation set (Redis, TTL = JWT lifetime, per ADR-0014's deny-list design)
- `backend/app/core/leader.py` — `leader_lease` advisory-lock acquisition + heartbeat thread + `is_leader()`
- `backend/app/core/errors.py` — Smorest `HttpError` subclasses → stable codes (`UNAUTHORIZED`, `RBAC_DENIED`, `CLUSTER_NOT_FOUND`, `CLUSTER_UNREACHABLE`, `CLUSTER_ALREADY_EXISTS`, `INVALID_KUBECONFIG`, `RESOURCE_KIND_NOT_SUPPORTED`, `NOT_IMPLEMENTED`)
- `backend/app/api/auth.py` — `AuthApi`: `/auth/login`, `/auth/callback`, `/auth/refresh`, `/auth/logout`, `/auth/me`
- `backend/app/api/clusters.py` — `ClusterApi`: CRUD + `/health`
- `backend/app/api/resources.py` — `ResourceApi`: generic `GET /clusters/<id>/resources/<kind>` with the kind routing table
- `backend/app/models/user.py`, `cluster.py`, `binding.py`, `token.py`, `leader_lease.py`
- `backend/app/services/k8s_client.py` — per-cluster client pool + decrypt/`read_namespaced_pod_list` + `/readyz` probe (the ADR-0010 seam)
- `backend/app/services/rbac.py` — `can(user, cluster, verb, resource, namespace, name)` via SAR, 30 s cache
- `backend/app/tasks/cluster_sync.py`, `health.py` — RQ tasks (leader-gated), minimal real: reconcile registry + probe `/readyz`
- `backend/app/sockets/events.py` — SocketIO namespace `/events`, no handlers yet
- `backend/app/schemas/auth.py`, `cluster.py`, `resource.py`, `errors.py` — Pydantic request/response
- `backend/migrations/` — initial Alembic revision (OD-3)
- `backend/Dockerfile` — 3 stages: node build → python deps → runtime (OD-4)

**Backend — stubs (R9; importable, ADR-pointing, 501 where routed):**
- `backend/app/api/{logs,metrics,traces,audit,permissions,namespaces,access,kubeconfig,admin}.py`, `api/scim/{users,groups}.py`, `api/aggregated/__init__.py`
- `backend/app/models/{rbac_template,namespace_request,access_request,scim_map,audit}.py`
- `backend/app/services/{prometheus,loki,tempo,grafana,permission,namespace,access,provisioning,scim}.py`
- `backend/app/tasks/{alerts,rbac_drift,access_expiry,ns_request_expiry}.py`
- `backend/app/sockets/logs.py`

**Frontend:**
- `frontend/` — CoreUI free React admin template (verbatim shell: Header/Sidebar/Footer, `_nav.tsx`, `routes.tsx`)
- `frontend/src/lib/api.ts` — fetch wrapper: JWT attach, single-in-flight 401 refresh, error-envelope unwrap
- `frontend/src/lib/types.ts` — generated from `/api/openapi.json` via `openapi-typescript`
- `frontend/src/store/cluster.ts` — Zustand selectedCluster store
- `frontend/src/hooks/useCluster.ts` — binding + permissions fetch on mount
- `frontend/src/views/Login/index.tsx` — redirect to `/api/v1/auth/login`
- `frontend/src/views/Clusters/index.tsx` — registry list (CoreUI table) + register form
- `frontend/src/views/Cluster/Pods.tsx` — pod table for `/clusters/:id`
- `frontend/src/components/Header.tsx` — cluster switcher (extends template)
- `frontend/tests/` — Vitest + RTL + MSW for the three views; `frontend/e2e/smoke.spec.ts` — Playwright login→pods journey

**CLI:**
- `cli/main.go`, `cli/go.mod` (module `github.com/org/kubedash-cli`), `cli/cmd/{version,get_token,clean,setup}.go`, `cli/Makefile` (5 cross-compile targets), `cli/.krew.yaml`

**Chart + CI + root:**
- `charts/kubedash/{Chart.yaml,values.yaml,templates/{deployment,service,configmap,secret,_helpers}.tpl}`
- `.github/workflows/{ci.yaml,e2e.yaml}`
- `README.md` (root, 5.0 layout + quickstart), `.gitignore` (5.0 additions), `.dockerignore`

---

### Task 1: Backend project bootstrap + app factory + health probes

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/app/__init__.py`
- Create: `backend/app/extensions.py`
- Create: `backend/app/core/__init__.py`
- Create: `backend/app/core/config.py`
- Create: `backend/wsgi.py`
- Test: `backend/tests/conftest.py`
- Test: `backend/tests/test_app.py`
- Test: `backend/tests/test_health.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `create_app(config_overrides: dict | None = None) -> Flask` (the factory every later task hangs off); `app.core.config.get_settings() -> Settings` (Pydantic `BaseSettings`, fields: `flask_env`, `database_url`, `redis_url`, `kubedash_jwt_secret`, `kubedash_secret_key`, `kubedash_role`, `kubedash_replica_id`, `oidc_client_id`, `oidc_client_secret`, `oidc_issuer`, `cors_origins`); `app.extensions.{api, db, redis_client, migrate}` (module-level instances, bound in the factory); `tests.conftest` fixtures: `pg_container` (Testcontainers Postgres 16), `redis_container` (Testcontainers Redis 7), `app` (isolated `create_app()` against those containers, `db.create_all()`), `client` (Flask test client)
- Seam: `create_app()` — every later module (APIs, models, tasks) registers through it; behavior altered by registration order, not by editing callers
- Deletion test: delete `create_app()` and 8 test files + every later task's app construction reappear; it is the spine root
- Adapters: 2 — the production `wsgi.py` entrypoint and the `conftest` test app (already justifies the factory)

**SATISFIES:** `app-boots-and-health-probes-report`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/conftest.py
import pytest
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from app import create_app

@pytest.fixture(scope="session")
def pg_container():
    with PostgresContainer("postgres:16") as pg:
        yield pg

@pytest.fixture(scope="session")
def redis_container():
    with RedisContainer("redis:7") as r:
        yield r

@pytest.fixture()
def app(pg_container, redis_container):
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": pg_container.get_connection_url(),
        "REDIS_URL": f"redis://{redis_container.get_container_host()}:{redis_container.exposed_port(6379)}",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    with application.app_context():
        from app.extensions import db
        db.create_all()
    yield application

@pytest.fixture()
def client(app):
    return app.test_client()
```

```python
# backend/tests/test_app.py
def test_app_constructs_and_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200

def test_openapi_json_is_valid_openapi3(client):
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    assert resp.get_json()["openapi"].startswith("3.")
```

```python
# backend/tests/test_health.py
def test_readyz_ok_when_deps_up(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["database"] == "ok"
    assert body["redis"] == "ok"

def test_readyz_names_failing_dependency(client, monkeypatch):
    from app.extensions import redis_client
    monkeypatch.setattr(redis_client, "ping", lambda: (_ for _ in ()).throw(ConnectionError("down")))
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert "redis" in resp.get_data(as_text=True)
```

```toml
# backend/pyproject.toml (deps pinned per Global Constraints; full file in Step 3)
[project]
name = "kubedash-backend"
requires-python = ">=3.12"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv sync && uv run pytest tests/ -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app'`
(BDD: `app-boots-and-health-probes-report` scenario is RED — the step-5 `acceptance.feature` dry-run reports it pending/failing.)

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUBEDASH_", env_file=".env", extra="ignore")

    flask_env: str = "development"          # development | staging | production
    database_url: str = "postgresql://kubedash:kubedash@localhost:5432/kubedash"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "dev-jwt-secret"
    secret_key: str = "dev-enc-key-32-bytes-long!!!!"
    role: str = "follower"                  # leader | follower (ADR-0008)
    replica_id: str = "local"
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_issuer: str = ""
    cors_origins: str = ""
    # §7.5 tuning — the two keys this change consumes (the other four are
    # deferred to the informer change, ADR-0010; see Task 10 Interfaces)
    first_paint_backstop: str = "5m"        # KUBEDASH_FIRST_PAINT_BACKSTOP
    namespace_list_timeout: str = "5s"      # KUBEDASH_NAMESPACE_LIST_TIMEOUT

_settings: Settings | None = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
```

```python
# backend/app/extensions.py
import redis as redis_lib
from flask_migrate import Migrate
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy

api = Api()
db = SQLAlchemy()
migrate = Migrate()
redis_client = redis_lib.Redis(decode_responses=True)
```

```python
# backend/app/__init__.py
from flask import Flask, jsonify, send_from_directory
from werkzeug.exceptions import HTTPException

from app.core.config import get_settings
from app.extensions import api, db, migrate, redis_client

def create_app(config_overrides: dict | None = None) -> Flask:
    settings = get_settings()
    overrides = config_overrides or {}
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=overrides.get("KUBEDASH_SECRET_KEY", settings.secret_key),
        SQLALCHEMY_DATABASE_URI=overrides.get("DATABASE_URL", settings.database_url),
        TESTING=overrides.get("TESTING", False),
        KUBEDASH_REDIS_URL=overrides.get("REDIS_URL", settings.redis_url),
    )
    db.init_app(app)
    migrate.init_app(app, db)
    api.init_app(app, url_prefix="/api/v1")
    redis_client.from_url(app.config["KUBEDASH_REDIS_URL"])

    # register domain APIs (later tasks add their lines; auth in Task 3)
    from app.api import register_apis
    register_apis(api)

    register_health(app)
    register_errors(app)
    register_static(app)
    return app

def register_health(app: Flask) -> None:
    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        checks = {}
        with app.app_context():
            try:
                db.engine.connect().close()
                checks["database"] = "ok"
            except Exception:
                checks["database"] = "down"
            try:
                redis_client.ping()
                checks["redis"] = "ok"
            except Exception:
                checks["redis"] = "down"
        healthy = all(v == "ok" for v in checks.values())
        return jsonify(checks), (200 if healthy else 503)

def register_errors(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def on_http_error(err: HTTPException):
        return jsonify(error={"code": err.name, "message": err.description}), err.code

def register_static(app: Flask) -> None:
    """Registered last so /api/v1/* and /ws/* win. SPA fallback in Task 9."""
    pass
```

```python
# backend/app/api/__init__.py
def register_apis(api) -> None:
    """Domain registration point — later tasks add their Api classes here."""
    pass
```

```python
# backend/wsgi.py
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(port=8080)
```

`backend/pyproject.toml` full content:

```toml
[project]
name = "kubedash-backend"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "flask>=3.0",
  "flask-smorest>=1.0",
  "flask-sqlalchemy>=3.1",
  "flask-migrate>=4.0",
  "flask-socketio>=5.3",
  "flask-limiter>=3.5",
  "pydantic>=2.5",
  "pydantic-settings>=2.1",
  "sqlalchemy>=2.0",
  "psycopg[binary]>=3.1",
  "redis>=5.0",
  "rq>=1.16",
  "kubernetes>=29.0",
  "httpx>=0.26",
  "authlib>=1.3",
  "pyjwt>=2.8",
  "gunicorn>=21.2",
]

[dependency-groups]
dev = [
  "pytest>=8.0",
  "testcontainers>=4.0",
  "ruff>=0.4",
  "mypy>=1.9",
  "types-redis",
]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
strict = true
python_version = "3.12"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: requires a kind cluster (deselect with -m 'not integration')"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/pyproject.toml backend/app backend/wsgi.py backend/tests
git commit -m "feat(backend): app factory, config, extensions, health probes (R1)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 1
"
```

### Task 2: Core models + initial migration + leader election

> ⚠ **one-way: OD-3 — the initial Alembic migration (users, refresh_tokens, clusters, cluster_bindings, leader_lease) is the first migration of the v1 line.** STOP for explicit user approval before running the migration generation.

**Files:**
- Create: `backend/app/models/__init__.py`
- Create: `backend/app/models/user.py`
- Create: `backend/app/models/cluster.py`
- Create: `backend/app/models/binding.py`
- Create: `backend/app/models/token.py`
- Create: `backend/app/models/leader_lease.py`
- Modify: `backend/app/__init__.py` (import models before `db.create_all` in factory; register leader thread in `wsgi` — keep factory pure)
- Create: `backend/app/core/leader.py`
- Test: `backend/tests/test_models.py`
- Test: `backend/tests/test_leader.py`

**Interfaces:**
- Consumes: `app.extensions.db`, `app.core.config.get_settings()` (Task 1)
- Produces: `User(id, sub, email, display_name, groups: JSONB, role, status, last_login_at)`; `Cluster(id, name: unique, api_server, kubeconfig_enc: bytes, context, status, last_probe_at, created_at)`; `ClusterBinding(id, user_id, cluster_id, role)` with `role ∈ {"viewer","editor","admin"}`; `RefreshToken(id, user_id, token_hash, expires_at, revoked_at)`; `LeaderLease(id: pk=1, replica_id, token: UUID, acquired_at, heartbeat_at)`; `core.leader.Leader(settings) -> Leader` with `start()`, `stop()`, `is_leader() -> bool`, `acquire_once() -> bool`
- **Mechanism note (decision, per ADR-0008 + §3.7):** the advisory lock is the **mutex** — key `hashintext(replica_id)` (per-replica, NOT a fixed constant; a fixed key would let a second `Leader` object on the same engine report spuriously non-leader and breaks failover tests). The `leader_lease` row is the **observable state**: heartbeat `UPDATE` every 5 s while leader. **Stale takeover** per §3.7: a non-leader attempts acquisition when `heartbeat_at` is older than 10 s (or the row is absent); on takeover it writes its own `replica_id`/`token`. `stop()` releases the advisory lock (`pg_advisory_unlock`). ARCHITECTURE §3.7 also sketches a `SELECT ... FOR UPDATE SKIP LOCKED` path; the advisory lock subsumes it for a single-row lease (recorded here so the executor does not "fix" it back).
- Seam: `Leader(settings)` — constructed with settings only; the advisory-lock call is the unit boundary (real PG in conftest)
- Deletion test: delete models and Tasks 3–5's handlers + conftest `db.create_all()` lose their tables; delete `leader` and the RQ worker gate in Task 7 has no flag to check
- Adapters: 2 — the `conftest` single-replica test app and the two-replica + failover tests (this task)

**SATISFIES:** `app-boots-and-health-probes-report` (leader status appears in readyz) + `test-fixtures-boot`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_models.py
def test_user_and_binding_roundtrip(app):
    from app.extensions import db
    from app.models.user import User
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    with app.app_context():
        u = User(sub="sub-1", email="jdoe@example.com", display_name="J Doe", role="user")
        c = Cluster(name="prod", api_server="https://1.2.3.4:6443", kubeconfig_enc=b"enc", context="prod")
        db.session.add_all([u, c]); db.session.flush()
        b = ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")
        db.session.add(b); db.session.commit()
        assert ClusterBinding.query.filter_by(user_id=u.id).first().role == "viewer"

def test_binding_rejects_unknown_role(app):
    import pytest
    from app.extensions import db
    from app.models.user import User
    from app.models.binding import ClusterBinding
    with app.app_context():
        u = User(sub="sub-2", email="x@example.com", display_name="X")
        db.session.add(u); db.session.flush()
        with pytest.raises(ValueError):
            db.session.add(ClusterBinding(user_id=u.id, cluster_id=1, role="superuser"))
```

```python
# backend/tests/test_leader.py
def test_single_replica_becomes_leader(app):
    from app.core.config import get_settings
    from app.core.leader import Leader
    with app.app_context():
        leader = Leader(get_settings())
        leader.replica_id = "r1"
        assert leader.acquire_once() is True
        assert leader.is_leader() is True
        leader.stop()

def test_second_replica_does_not_double_lead(app):
    from app.core.config import get_settings
    from app.core.leader import Leader
    with app.app_context():
        first = Leader(get_settings()); first.replica_id = "r1"
        second = Leader(get_settings()); second.replica_id = "r2"
        assert first.acquire_once() is True
        assert second.acquire_once() is False      # lock held by r1
        assert first.is_leader() is True
        assert second.is_leader() is False
        first.stop(); second.stop()

def test_failover_after_leader_stop_is_fast(app):
    """ARCHITECTURE §9: kill leader, follower acquires within the stale
    threshold (10 s; test budget 15 s)."""
    import time
    from app.core.config import get_settings
    from app.core.leader import Leader
    with app.app_context():
        first = Leader(get_settings()); first.replica_id = "r1"
        second = Leader(get_settings()); second.replica_id = "r2"
        assert first.acquire_once() is True
        first.stop()                                  # leader dies
        t0 = time.monotonic()
        # r2 waits for the stale threshold, then takes over
        deadline = t0 + 15
        while time.monotonic() < deadline and not second.acquire_once():
            time.sleep(0.2)
        elapsed = time.monotonic() - t0
        assert second.is_leader() is True
        assert elapsed <= 15
        second.stop()
```

Note for the executor: `acquire_once()` must NOT block waiting for the stale
threshold — it attempts, and returns `False` when the current lease is fresh
and held by another replica. The 5 s heartbeat loop (`_loop`) is what makes
`heartbeat_at` stay fresh; the failover test drives `acquire_once()` directly
so it stays deterministic. To keep the test under 15 s, `Leader` takes
`stale_seconds` (default 10) and `heartbeat_seconds` (default 5) as
constructor kwargs; the test passes `stale_seconds=1`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_models.py tests/test_leader.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/models/user.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()  # re-exported in models/__init__; single instance lives in extensions

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    sub = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    groups = db.Column(db.JSON, default=list)
    role = db.Column(db.String(32), nullable=False, default="user")
    status = db.Column(db.String(32), nullable=False, default="active")
    last_login_at = db.Column(db.DateTime)
```

*(`cluster.py`, `binding.py`, `token.py`, `leader_lease.py` follow the same
SQLAlchemy 2.0 pattern from the Interfaces block; `binding.py` validates
`role` in `__init__` and raises `ValueError` on unknown roles; `token.py`
stores `token_hash` (sha256 hex) never the raw token.)*

```python
# backend/app/core/leader.py
import threading
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.extensions import db

class Leader:
    """ADR-0008: advisory lock = mutex (key hashintext(replica_id)),
    leader_lease row = observable state, 5 s heartbeat, 10 s stale takeover
    (ARCHITECTURE §3.7). See the Mechanism note in the task Interfaces."""

    def __init__(self, settings, stale_seconds: int = 10, heartbeat_seconds: int = 5):
        self.replica_id = settings.replica_id
        self._token = uuid.uuid4()
        self._stale = stale_seconds
        self._beat = heartbeat_seconds
        self._is_leader = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._is_leader:
            self._release()
            self._is_leader = False

    def is_leader(self) -> bool:
        return self._is_leader

    def _lock_key(self) -> str:
        return "hashintext(:rid)"

    def acquire_once(self) -> bool:
        """One attempt: if I'm not leader, require the lease to be absent or
        stale (> _stale s) before taking the lock. Never blocks on staleness."""
        with db.engine.connect() as conn:
            row = conn.execute(
                text("SELECT replica_id, heartbeat_at FROM leader_lease WHERE id = 1")
            ).first()
            if row is not None and row.replica_id != self.replica_id:
                stale = (datetime.now(timezone.utc) - row.heartbeat_at) > timedelta(seconds=self._stale)
                if not stale:
                    return False
            if conn.execute(text("SELECT pg_try_advisory_lock(" + self._lock_key() + ")"),
                             {"rid": self.replica_id}).scalar() is not 1:
                return False
            conn.execute(
                text(
                    "INSERT INTO leader_lease (id, replica_id, token, acquired_at, heartbeat_at) "
                    "VALUES (1, :rid, :tok, now(), now()) "
                    "ON CONFLICT (id) DO UPDATE SET replica_id = :rid, token = :tok, "
                    "acquired_at = now(), heartbeat_at = now()"
                ),
                {"rid": self.replica_id, "tok": str(self._token)},
            )
            conn.commit()
        self._is_leader = True
        return True

    def _heartbeat(self) -> None:
        with db.engine.connect() as conn:
            conn.execute(
                text("UPDATE leader_lease SET heartbeat_at = now() "
                     "WHERE id = 1 AND replica_id = :rid"),
                {"rid": self.replica_id},
            )
            conn.commit()

    def _release(self) -> None:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT pg_advisory_unlock(" + self._lock_key() + ")"),
                         {"rid": self.replica_id})
            conn.execute(
                text("DELETE FROM leader_lease WHERE id = 1 AND replica_id = :rid"),
                {"rid": self.replica_id},
            )
            conn.commit()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self._is_leader:
                self._heartbeat()
            else:
                self.acquire_once()
            self._stop.wait(self._beat if self._is_leader else 1)
```

Generate the initial migration:

```bash
cd backend
export FLASK_APP=wsgi.py
uv run flask db init        # creates migrations/
uv run flask db migrate -m "initial spine tables"
uv run flask db upgrade
```

Verify the generated revision contains all five tables:
`grep -E 'create_table' backend/migrations/versions/*.py` must list `users`, `refresh_tokens`, `clusters`, `cluster_bindings`, `leader_lease`.
The `clusters` model in this task already includes `last_probe_at = db.Column(db.DateTime)` (consumed by Task 7) so Task 7 needs no migration of its own.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v`
Expected: PASS (all tests incl. Tasks 1–2)

- [ ] **Step 5: Commit**

```bash
git add backend/app/models backend/app/core/leader.py backend/migrations backend/tests/test_models.py backend/tests/test_leader.py
git commit -m "feat(backend): core models, initial migration, leader election (R3 prereq)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 2
OneWay: OD-3 initial v1 migration
"
```

### Task 3: Error contract + JWT security core + auth API (OIDC spine)

> ⚠ **one-way: OD-1 — the v1 error envelope + stable codes freeze the public API contract.**

**Files:**
- Create: `backend/app/core/errors.py`
- Create: `backend/app/core/security.py`
- Create: `backend/app/schemas/__init__.py`
- Create: `backend/app/schemas/errors.py`
- Create: `backend/app/schemas/auth.py`
- Create: `backend/app/api/auth.py`
- Modify: `backend/app/api/__init__.py` (register `AuthApi`)
- Test: `backend/tests/test_errors.py`
- Test: `backend/tests/api/test_auth.py`
- Test: `backend/tests/api/conftest.py` (mock OIDC provider fixture)

**Interfaces:**
- Consumes: `app.extensions.api/db/redis_client` (Task 1); `User`, `RefreshToken` models (Task 2)
- Produces: `app.core.errors.KubeDashHttpError` (Smorest `HttpError` base) + subclasses mapping to stable codes: `UnauthorizedError` → `UNAUTHORIZED` (401), `RbacDeniedError` → `RBAC_DENIED` (403), `ClusterNotFoundError` → `CLUSTER_NOT_FOUND` (404), `ResourceKindNotSupportedError` → `RESOURCE_KIND_NOT_SUPPORTED` (404), `ClusterUnreachableError` → `CLUSTER_UNREACHABLE` (502), `ClusterAlreadyExistsError` → `CLUSTER_ALREADY_EXISTS` (409), `InvalidKubeconfigError` → `INVALID_KUBECONFIG` (422), `NotImplementedError_` → `NOT_IMPLEMENTED` (501); `app.core.security.issue_token_pair(user, expires_in: int = 900) -> (access_jwt: str, refresh_token: str)`; `app.core.security.verify_jwt(token: str) -> dict` (claims; raises `UnauthorizedError`); `app.core.security.rotate_refresh(raw_token: str) -> (access_jwt, refresh_token)` (hash-lookup, **delete the consumed row**, issue a new row; reuse of a deleted/revoked token → `UnauthorizedError` — the row is gone, per T5); `app.core.security.oidc_authorize_url(state: str) -> str` and `app.core.security.oidc_exchange(code: str) -> dict` (real Authlib bodies — see Step 3; the mock fixture monkeypatches exactly these two names); the shared hook `require_auth` (decorator: verifies JWT, loads `User` into `flask.g.current_user`) that every non-auth Api registers in `on_init` via `self.on_before_request(self._auth, blueprint=False)` where `_auth = lambda: require_auth(lambda: None)()` is NOT used — instead each Api defines `def _auth(self): return require_auth_passthrough()` per the pattern in Step 3's `AuthApi` excerpt
- **JWT delivery contract (decision, pins the SPA flow):** the callback responds `302 → "/?token=<access_jwt>&refresh=<refresh_token>"`; the SPA's `Login` view (Task 8) parses both query params, stores them in `localStorage` as `kd_token` / `kd_refresh`, and drops them from the URL via `history.replaceState`. No JWT ever rides in an `HttpOnly` cookie (the frontend reads `localStorage`); the OIDC `state` param is a per-session random 32-byte hex stored in a short-TTL Redis key `oidc_state:<state>`, validated (and deleted) at the callback — missing/mismatched state → 400 `INVALID_KUBECONFIG`-free dedicated code `STATE_MISMATCH` (400)
- Seam: `security.py` is pure (no Flask imports except `flask.g`/`request` in the hook) — the Authlib OIDC client is constructed from `Settings`, so the mock provider in tests swaps the two functions without touching production code
- Deletion test: delete `errors.py` and every handler loses its stable-code raises; delete `require_auth` and Tasks 4–6 each re-implement JWT verification (the exact duplication ADR-0001's shared-hook design avoids)
- Adapters: 2 — the real Authlib client (prod) and the mock-provider pair (tests)

**SATISFIES:** `oidc-login-issues-jwt`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/api/conftest.py
import pytest
from urllib.parse import urlparse, parse_qs

class MockOIDC:
    """In-test OIDC provider. The mock pair patches exactly the two seams
    Task 3's security.py exposes: oidc_authorize_url(state) and
    oidc_exchange(code)."""
    CODE = "fixed-code"
    USER = {"sub": "sub-oidc-1", "email": "jdoe@example.com",
            "name": "J Doe", "groups": ["devs"]}

    def __init__(self):
        self.last_state = None

    def authorize_url(self, state: str) -> str:
        self.last_state = state
        return f"http://mock-oidc.test/authorize?state={state}"

    def exchange(self, code: str) -> dict:
        assert code == self.CODE
        return dict(self.USER)

@pytest.fixture()
def mock_oidc(monkeypatch):
    m = MockOIDC()
    import app.core.security as sec
    monkeypatch.setattr(sec, "oidc_exchange", m.exchange)
    monkeypatch.setattr(sec, "oidc_authorize_url", m.authorize_url)
    return m

def _jwt_of(client) -> str:
    """Replay the login flow and return the access JWT from the callback's
    302 location (?token=... per the JWT delivery contract)."""
    r1 = client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    r2 = client.get(cb)  # mock provider auto-redirects back with code+state
    q = parse_qs(urlparse(r2.headers["Location"]).query)
    return q["token"][0]

@pytest.fixture()
def auth_client(client, mock_oidc):
    """client.login() performs the full OIDC round trip; client.jwt is the
    resulting access token; client.refresh is the raw refresh token."""
    def login():
        r1 = client.post("/api/v1/auth/login")
        assert r1.status_code == 302
        cb = r1.headers["Location"]
        state = parse_qs(urlparse(cb).query)["state"][0]
        r2 = client.get(f"{cb}&code={mock_oidc.CODE}")
        assert r2.status_code == 302
        loc = r2.headers["Location"]
        assert loc.startswith("/?token=")
        q = parse_qs(urlparse(loc).query)
        client.jwt = q["token"][0]
        client.refresh = q["refresh"][0]
    client.login = login
    return client
```

```python
# backend/tests/api/test_auth.py
def test_login_flow_issues_jwt_and_me_echoes_sub(client, auth_client):
    auth_client.login()
    r3 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {auth_client.jwt}"})
    assert r3.status_code == 200
    assert r3.get_json()["sub"] == "sub-oidc-1"

def test_state_mismatch_rejected(client, mock_oidc):
    r1 = client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    # wrong state on the way back
    r2 = client.get(cb.replace("state=good", "state=evil") + f"&code={mock_oidc.CODE}")
    assert r2.status_code == 400
    assert r2.get_json()["error"]["code"] == "STATE_MISMATCH"

def test_unauthenticated_api_returns_401_stable_shape(client):
    resp = client.get("/api/v1/clusters")
    assert resp.status_code == 401
    assert resp.get_json() == {"error": {"code": "UNAUTHORIZED", "message": "missing or invalid token"}}

def test_expired_jwt_returns_401_not_500(client, app):
    from app.core.security import issue_token_pair
    from app.models.user import User
    from app.extensions import db
    with app.app_context():
        u = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one_or_none() \
            or User(sub="sub-oidc-1", email="j@example.com")
        db.session.add(u); db.session.commit()
        access, _ = issue_token_pair(u, expires_in=-10)  # already expired
    resp = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 401

def test_refresh_rotation_reuse_rejected_and_row_deleted(client, auth_client, app):
    auth_client.login()
    old_refresh = auth_client.refresh
    # first use: succeeds, returns a NEW rotated pair
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200
    body = r1.get_json()
    assert body["access"] and body["refresh"]
    # second use of the SAME (now-consumed) token: 401
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r2.status_code == 401
    assert r2.get_json()["error"]["code"] == "UNAUTHORIZED"
    # the consumed row is DELETED (T5), not merely revoked
    from app.extensions import db
    from app.models.token import RefreshToken
    import hashlib
    with app.app_context():
        assert db.session.execute(
            db.select(RefreshToken).filter_by(
                token_hash=hashlib.sha256(old_refresh.encode()).hexdigest())
        ).scalar_one_or_none() is None
```

```python
# backend/tests/test_errors.py
def test_error_envelope_shape(client):
    # hit an unimplemented stub route (registered in Task 8; here: 404 path)
    resp = client.get("/api/v1/does-not-exist")
    assert "error" in resp.get_json()
    assert set(resp.get_json()["error"]) >= {"code", "message"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/api/test_auth.py tests/test_errors.py -v`
Expected: FAIL — 404s (no auth routes) / `ModuleNotFoundError: app.core.security`

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/core/errors.py
from flask_smorest import HttpError

class KubeDashHttpError(HttpError):
    error_code: str = "ERROR"

    def __init__(self, message: str, details: dict | None = None):
        self.details = details
        super().__init__(message=message)

    def as_dict(self):
        d = {"code": self.error_code, "message": self.message}
        if self.details:
            d["details"] = self.details
        return d

class UnauthorizedError(KubeDashHttpError):   error_code = "UNAUTHORIZED"
class RbacDeniedError(KubeDashHttpError):     error_code = "RBAC_DENIED"
class ClusterNotFoundError(KubeDashHttpError): error_code = "CLUSTER_NOT_FOUND"
class ResourceKindNotSupportedError(KubeDashHttpError): error_code = "RESOURCE_KIND_NOT_SUPPORTED"
class ClusterUnreachableError(KubeDashHttpError): error_code = "CLUSTER_UNREACHABLE"
class ClusterAlreadyExistsError(KubeDashHttpError): error_code = "CLUSTER_ALREADY_EXISTS"
class InvalidKubeconfigError(KubeDashHttpError): error_code = "INVALID_KUBECONFIG"
class NotImplementedError_(KubeDashHttpError): error_code = "NOT_IMPLEMENTED"
```

```python
# backend/app/core/security.py
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from authlib.integrations.flask_client import OAuth
from flask import g, request

from app.core.config import get_settings
from app.core.errors import UnauthorizedError

_oauth = OAuth()
_oidc_app = _oauth.register(
    "oidc",
    client_id="",            # filled in init_oidc() from Settings
    client_secret="",
    server_metadata_url="",  # <issuer>/.well-known/openid-configuration
    client_kwargs={"scope": "openid email profile groups"},
)

def init_oidc(app) -> None:  # called from create_app(); tests skip it (mock pair)
    s = get_settings()
    _oidc_app.client_id = s.oidc_client_id
    _oidc_app.client_secret = s.oidc_client_secret
    _oidc_app.server_metadata_url = f"{s.oidc_issuer}/.well-known/openid-configuration"
    _oauth.init_app(app)

def oidc_authorize_url(state: str) -> str:
    """Real adapter: Authlib authorize_redirect to the IdP with our state."""
    return _oidc_app.authorize_redirect(state=state).get("url") or \
        f"{get_settings().oidc_issuer}/authorize?state={state}"

def oidc_exchange(code: str) -> dict:
    """Real adapter: code→token→userinfo. Returns {sub, email, name, groups}."""
    token = _oidc_app.authorize_access_token(code=code)
    userinfo = token.get("userinfo") or _oidc_app.parse_id_token(token["id_token"])
    return {"sub": userinfo["sub"], "email": userinfo.get("email"),
            "name": userinfo.get("name"),
            "groups": userinfo.get("groups", [])}

def _settings():
    return get_settings()

def issue_token_pair(user, expires_in: int = 900) -> tuple[str, str]:
    s = _settings()
    now = datetime.now(timezone.utc)
    claims = {"sub": user.sub, "jti": str(uuid.uuid4()),
              "iat": now, "exp": now + timedelta(seconds=expires_in)}
    access = jwt.encode(claims, s.jwt_secret, algorithm="HS256")
    refresh = uuid.uuid4().hex
    return access, refresh

def verify_jwt(token: str) -> dict:
    s = _settings()
    try:
        claims = jwt.decode(token, s.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        raise UnauthorizedError("missing or invalid token") from e
    # jti revocation set (ADR-0014 deny-list, Redis, TTL = JWT lifetime)
    from app.extensions import redis_client
    if redis_client.get(f"revoked:{claims['jti']}"):
        raise UnauthorizedError("token revoked")
    return claims

def new_state() -> str:
    from app.extensions import redis_client
    st = secrets.token_hex(16)
    redis_client.set(f"oidc_state:{st}", "1", ex=300)
    return st

def consume_state(state: str) -> None:
    from app.extensions import redis_client
    if not redis_client.delete(f"oidc_state:{state}"):
        raise UnauthorizedError("state mismatch")  # API maps to 400 STATE_MISMATCH

def rotate_refresh(raw_token: str) -> tuple[str, str]:
    """Consume-once: the row is DELETED on successful rotation (T5)."""
    from app.extensions import db
    from app.models.token import RefreshToken
    from app.models.user import User
    h = hashlib.sha256(raw_token.encode()).hexdigest()
    rt = db.session.execute(db.select(RefreshToken).filter_by(token_hash=h)).scalar_one_or_none()
    if rt is None:
        raise UnauthorizedError("invalid refresh token")
    user = db.session.get(User, rt.user_id)
    pair = issue_token_pair(user)
    db.session.delete(rt)                      # consumed row gone
    db.session.add(RefreshToken(user_id=user.id,
                                token_hash=hashlib.sha256(pair[1].encode()).hexdigest(),
                                expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
    db.session.commit()
    return pair

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise UnauthorizedError("missing or invalid token")
        claims = verify_jwt(header[len("Bearer "):])
        from app.extensions import db
        from app.models.user import User
        g.current_user = db.session.execute(
            db.select(User).filter_by(sub=claims["sub"])
        ).scalar_one_or_none()
        if g.current_user is None:
            raise UnauthorizedError("missing or invalid token")
        return f(*args, **kwargs)
    return wrapper
```

`backend/app/api/auth.py` — Smorest `AuthApi` with `resources_namespace = "auth"`:

```python
class AuthApi(Api):
    resources_namespace = "auth"
    tags = ["Auth"]

    def on_init(self, app):
        pass  # auth routes are open (pre-JWT); /auth/me uses require_auth per-route

    @blp.route("/auth/login", methods=["POST"])
    def login(self):
        state = new_state()
        return redirect(f"/api/v1/auth/callback?state={state}&next="
                        + oidc_authorize_url(state))

    @blp.route("/auth/callback", methods=["GET"])
    def callback(self):
        state = request.args["state"]
        consume_state(state)  # raises UnauthorizedError → 400 STATE_MISMATCH
        userinfo = oidc_exchange(request.args["code"])
        user = _upsert_user(userinfo)
        access, refresh = issue_token_pair(user)
        _store_refresh(user, refresh)
        return redirect(f"/?token={access}&refresh={refresh}")  # JWT delivery contract

    @blp.route("/auth/refresh", methods=["POST"])
    @blp.arguments(RefreshIn)  # {refresh_token: str}
    def refresh(self, args: RefreshIn):
        access, refresh = rotate_refresh(args.refresh_token)
        return {"access": access, "refresh": refresh}  # BOTH tokens (rotation)

    @blp.route("/auth/logout", methods=["POST"])
    def logout(self):
        _delete_refresh_for(g.get("current_user"))
        return {"status": "ok"}

    @blp.route("/auth/me", methods=["GET"])
    @require_auth
    def me(self):
        u = g.current_user
        return {"sub": u.sub, "email": u.email, "display_name": u.display_name,
                "groups": u.groups, "role": u.role}
```

Register in `app/api/__init__.py`:

```python
def register_apis(api) -> None:
    from app.api.auth import AuthApi
    api.register(AuthApi())
```

**The shared auth-hook pattern** every later (non-auth) Api copies — this is
the exact code Tasks 4, 5, 6 use (fixes the stub-exemplar finding):

```python
# in each domain Api (clusters, resources, stubs...):
def on_init(self, app):
    def _check():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise UnauthorizedError("missing or invalid token")
        claims = verify_jwt(header[len("Bearer "):])
        g.current_user = db.session.execute(
            db.select(User).filter_by(sub=claims["sub"])
        ).scalar_one_or_none()
        if g.current_user is None:
            raise UnauthorizedError("missing or invalid token")
        return None
    self.on_before_request(_check, blueprint=False)
```

The factory's `register_errors` additionally installs a Smorest error handler
that serializes `KubeDashHttpError` via `as_dict()` into the `{error: {...}}`
envelope, and maps `UnauthorizedError` raised by `consume_state` specifically
to HTTP 400 with code `STATE_MISMATCH`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v`
Expected: PASS (Tasks 1–3)

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/errors.py backend/app/core/security.py backend/app/schemas backend/app/api/auth.py backend/app/api/__init__.py backend/tests
git commit -m "feat(backend): v1 error contract, JWT/OIDC security core, auth API (R2)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 3
OneWay: OD-1 v1 error envelope + stable codes
"
```

### Task 4: Cluster registry API + encrypted kubeconfig + k8s client pool

> ⚠ **one-way: OD-2 — AES-256-GCM encrypted-kubeconfig registry (ADR-0002); cipher + key domain are a data migration to change.**

**Files:**
- Create: `backend/app/services/__init__.py`
- Create: `backend/app/services/k8s_client.py`
- Create: `backend/app/schemas/cluster.py`
- Create: `backend/app/api/clusters.py`
- Modify: `backend/app/api/__init__.py` (register `ClusterApi`)
- Test: `backend/tests/test_encryption.py`
- Test: `backend/tests/api/test_clusters.py`

**Interfaces:**
- Consumes: `require_auth` (Task 3); `Cluster`, `ClusterBinding` models (Task 2); `settings.secret_key` (Task 1)
- Produces: `services.k8s_client.encrypt_kubeconfig(plain: bytes) -> bytes` and `decrypt_kubeconfig(enc: bytes) -> bytes` (AES-256-GCM, 96-bit nonce prefixed, key = sha256 of `KUBEDASH_SECRET_KEY` — distinct from the JWT key); `services.k8s_client.bound_cluster_or_404(user, cluster_id: int) -> Cluster` (looks up the `Cluster` **and** the caller's `ClusterBinding`; missing cluster OR missing binding → `ClusterNotFoundError` — this is the shared helper Tasks 5's resources API consumes by name); `K8sClientPool.get(cluster: Cluster) -> K8sClient` (per-cluster cached `kubernetes` client built from the decrypted kubeconfig; `K8sClient.list_pods(namespace: str | None) -> list[dict]`, `readyz() -> bool` (GET `<cluster.server>/readyz` — `configuration.host` used **verbatim**, it already carries the scheme — with the kubeconfig's CA bundle as `verify=`, 5 s timeout, returns `False` on ANY failure including timeout — callers map to `ClusterUnreachableError`)); `ClusterApi`: `POST /clusters` (body: `{name, api_server, kubeconfig: str, context}` → 409 `CLUSTER_ALREADY_EXISTS` on dup name, 422 `INVALID_KUBECONFIG` if `yaml.safe_load` fails, stores encrypted, auto-binds the registering user as `admin`), `GET /clusters` (only bound clusters), `GET /clusters/<id>` (via `bound_cluster_or_404`), `GET /clusters/<id>/health` (→ `{status: "up"|"down"}` or 502 `CLUSTER_UNREACHABLE`)
- Seam: `K8sClientPool` — the single place that turns a `Cluster` row into a live client; the informer cache (ADR-0010) interposes here later without touching APIs
- Deletion test: delete `k8s_client.py` and Task 5's pod listing + Task 4's `/health` + the cluster_sync task (Task 12) all lose their only k8s access path
- Adapters: 2 — real `kubernetes` client (kind integration) and a `FakeK8s` double injected in unit tests via the pool constructor

**SATISFIES:** `cluster-register-and-health`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_encryption.py
from app.services.k8s_client import encrypt_kubeconfig, decrypt_kubeconfig
import base64

def test_roundtrip_and_at_rest_not_plaintext():
    plain = base64.b64encode(b"apiVersion: v1\nkind: Config\nclusters: []")
    enc = encrypt_kubeconfig(plain)
    assert b"apiVersion" not in enc            # at-rest form hides plaintext
    assert decrypt_kubeconfig(enc) == plain

def test_wrong_key_fails():
    from app.core.config import get_settings
    enc = encrypt_kubeconfig(b"data")
    import app.services.k8s_client as kc
    old, kc._key = kc._key, b"x" * 32
    try:
        import pytest
        with pytest.raises(ValueError):
            kc.decrypt_kubeconfig(enc)
    finally:
        kc._key = old
```

```python
# backend/tests/api/test_clusters.py
import base64
KUBECONFIG = "apiVersion: v1\nkind: Config\nclusters: []"

def test_register_and_list_bound(client, auth_client):
    auth_client.login()
    tok = _jwt_of(auth_client)  # helper in tests/api/conftest.py (grab from login cookie)
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/api/v1/clusters", json={
        "name": "prod", "api_server": "https://1.2.3.4:6443",
        "kubeconfig": KUBECONFIG, "context": "prod"}, headers=h)
    assert r.status_code in (200, 201)
    r2 = client.get("/api/v1/clusters", headers=h)
    names = [c["name"] for c in r2.get_json()]
    assert "prod" in names

def test_duplicate_name_409(client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    body = {"name": "dup", "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG, "context": "dup"}
    assert client.post("/api/v1/clusters", json=body, headers=h).status_code in (200, 201)
    r = client.post("/api/v1/clusters", json=body, headers=h)
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"

def test_invalid_kubeconfig_422(client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    r = client.post("/api/v1/clusters", json={
        "name": "bad", "api_server": "https://1.2.3.4:6443",
        "kubeconfig": "::not-yaml", "context": "bad"}, headers=h)
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"

def test_unbound_user_does_not_see_cluster(client, auth_client, app):
    auth_client.login()
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User
    with app.app_context():
        u2 = User(sub="stranger", email="s@example.com")
        db.session.add(u2); db.session.commit()
        access, _ = issue_token_pair(u2)   # inside the app context
    r = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access}"})
    assert r.get_json() == []

def test_health_blackholed_server_times_out_bounded(client, auth_client, app):
    """A refused port is fast; a BLACKHOLED port (accepts, never responds)
    must still return within the 5 s probe budget (briefing edge case)."""
    import socket, threading
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)                      # accepts (default backlog) but never reads
    port = sock.getsockname()[1]
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    client.post("/api/v1/clusters", json={
        "name": "blackhole", "api_server": f"https://127.0.0.1:{port}",
        "kubeconfig": KUBECONFIG, "context": "blackhole"}, headers=h)
    import time
    t0 = time.monotonic()
    r = client.get("/api/v1/clusters/1/health", headers=h)
    assert r.status_code == 502
    assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"
    assert time.monotonic() - t0 < 8    # 5 s budget + slack
    sock.close()
```

(The kind-dependent health test lives in **Task 5** with the `kind_client`
fixture; the auth_client's `.jwt` attribute is set by `login()` per Task 3's
conftest.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_encryption.py tests/api/test_clusters.py -v -m "not integration"`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services'`

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/services/k8s_client.py
import base64
import hashlib
import secrets
import yaml
from kubernetes import client as k8s_client, config as k8s_config

from app.core.config import get_settings
from app.core.errors import ClusterNotFoundError

def _key() -> bytes:
    return hashlib.sha256(get_settings().secret_key.encode()).digest()

def encrypt_kubeconfig(plain: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_key()).encrypt(nonce, plain, None)

def decrypt_kubeconfig(enc: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(_key()).decrypt(enc[:12], enc[12:], None)
    except Exception as e:
        raise ValueError("kubeconfig decryption failed") from e

def bound_cluster_or_404(user, cluster_id: int) -> "Cluster":
    """Binding gate shared by clusters/resources APIs (Task 5 consumes it)."""
    from app.extensions import db
    from app.models.cluster import Cluster
    from app.models.binding import ClusterBinding
    b = db.session.execute(
        db.select(ClusterBinding).join(Cluster, ClusterBinding.cluster_id == Cluster.id)
        .filter(Cluster.id == cluster_id, ClusterBinding.user_id == user.id)
    ).scalar_one_or_none()
    if b is None:
        raise ClusterNotFoundError("cluster not found")
    return db.session.get(Cluster, cluster_id)

class K8sClient:
    def __init__(self, kubeconfig: bytes):
        self._config = k8s_config.KubeConfig.from_custom_yaml(
            yaml.safe_load(kubeconfig.decode()))
        self._v1 = k8s_client.CoreV1Api(k8s_client.ApiClient(self._config))
        # host carries the scheme already (cluster.server) — use verbatim
        self._host = self._v1.api_client.configuration.host
        ca = self._config.clusters[0].get("certificate-authority-data")
        self._verify = (base64.b64decode(ca) if ca else True)

    def list_pods(self, namespace: str | None) -> list[dict]:
        resp = (self._v1.list_namespaced_pod(namespace) if namespace
                else self._v1.list_pod_for_all_namespaces())
        return [p.to_dict() for p in resp.items]

    def readyz(self) -> bool:
        import httpx
        try:
            r = httpx.get(f"{self._host}/readyz", timeout=5.0, verify=self._verify)
            return r.status_code == 200
        except Exception:
            return False

class K8sClientPool:
    def __init__(self, factory=K8sClient):
        self._factory = factory
        self._cache: dict[int, K8sClient] = {}

    def get(self, cluster) -> K8sClient:
        if cluster.id not in self._cache:
            self._cache[cluster.id] = self._factory(decrypt_kubeconfig(cluster.kubeconfig_enc))
        return self._cache[cluster.id]

pool = K8sClientPool()
```

`backend/app/api/clusters.py` — `ClusterApi` (`resources_namespace = "clusters"`),
`on_init` registers the shared auth-hook pattern from Task 3. `POST /clusters`:
validate with Pydantic `ClusterIn` (`name: str`, `api_server: HttpUrl`,
`kubeconfig: str`, `context: str`); `yaml.safe_load` the body or raise
`InvalidKubeconfigError`; dup `name` → `ClusterAlreadyExistsError`; store
`kubeconfig_enc = encrypt_kubeconfig(body.kubeconfig.encode())`; auto-create
`ClusterBinding(user=g.current_user, cluster, role="admin")`. `GET /clusters`
joins bindings for `g.current_user`. `GET /clusters/<id>` and
`GET /clusters/<id>/health` go through `bound_cluster_or_404`; `/health`:
`pool.get(cluster).readyz()` → `{"status": "up"}` or raise
`ClusterUnreachableError`. Add `cryptography>=42` to `pyproject.toml` deps.

**`readyz` unit test** (closes the timeout edge without kind) — add to
`tests/api/test_clusters.py`:

```python
def test_readyz_url_uses_host_verbatim_and_ca(monkeypatch):
    import app.services.k8s_client as kc
    captured = {}
    class FakeResp: status_code = 200
    class FakeHttpx:
        @staticmethod
        def get(url, timeout, verify):
            captured.update(url=url, timeout=timeout, verify=verify)
            return FakeResp()
    monkeypatch.setattr("httpx.get", FakeHttpx.get)
    k = kc.K8sClient.__new__(kc.K8sClient)
    k._host = "https://api.example.com:6443"
    k._verify = b"CA-BYTES"
    assert k.readyz() is True
    assert captured["url"] == "https://api.example.com:6443/readyz"  # no double scheme
    assert captured["timeout"] == 5.0
    assert captured["verify"] == b"CA-BYTES"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v -m "not integration"`
Expected: PASS (Tasks 1–4 unit tier)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/k8s_client.py backend/app/schemas/cluster.py backend/app/api/clusters.py backend/app/api/__init__.py backend/pyproject.toml backend/tests/test_encryption.py backend/tests/api/test_clusters.py
git commit -m "feat(backend): cluster registry with encrypted kubeconfig + client pool (R3)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 4
OneWay: OD-2 AES-256-GCM kubeconfig registry (ADR-0002)
"
```

### Task 5: RBAC service + generic resource list (pods) + kind integration tier

**Files:**
- Create: `backend/app/services/rbac.py`
- Create: `backend/app/schemas/resource.py`
- Create: `backend/app/api/resources.py`
- Modify: `backend/app/api/__init__.py` (register `ResourceApi`)
- Modify: `backend/tests/conftest.py` (add session-scoped `kind_cluster` fixture + `kind_client`)
- Test: `backend/tests/services/test_rbac.py`
- Test: `backend/tests/api/test_resources.py`

**Interfaces:**
- Consumes: `require_auth` (Task 3); `K8sClientPool.get()` (Task 4); `ClusterBinding` (Task 2)
- Produces: `services.rbac.can(user: User, cluster: Cluster, verb: str, resource: str, namespace: str | None, name: str | None) -> bool` (SelfSubjectAccessReview via the cluster's client, cached in Redis 30 s under `sar:<cluster.id>:<user.sub>:<verb>:<resource>`); `ResourceApi`: `GET /clusters/<id>/resources/<kind>` (query `namespace?`) — the kind routing table `_KINDS = {"pods": ("list_pods", "pods")}` is the seam later kinds (deployments, services, …) plug into; unknown kind → `ResourceKindNotSupportedError`; no binding on the cluster → 404 `CLUSTER_NOT_FOUND` (binding gate); SAR deny → `RbacDeniedError`
- Seam: the `_KINDS` table + `K8sClient.list_<kind>` methods — adding a kind is one table row + one client method, no API changes
- Deletion test: delete `rbac.py` and every mutating/listing endpoint loses its ADR-0004 enforcement point (each handler would re-implement SAR — the duplication the service exists to prevent)
- Adapters: 2 — real kind cluster (integration) and a `FakeSar` double in `tests/services/test_rbac.py`

**SATISFIES:** `list-pods-for-bound-cluster`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/services/test_rbac.py
from types import SimpleNamespace

def _user(sub="u-1"):
    return SimpleNamespace(sub=sub)

def _cluster(cid=1):
    return SimpleNamespace(id=cid)

def test_can_denied_returns_false(monkeypatch):
    import app.services.rbac as rb
    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows(set()))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is False

def test_can_allowed_and_cached(monkeypatch):
    import app.services.rbac as rb
    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows({"list"}))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is True

def test_can_reads_cache_without_sar(monkeypatch):
    import app.services.rbac as rb
    monkeypatch.setattr(rb, "_cache_get", lambda k: "1")   # cache hit
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is True
    # pool.get must never be called on a cache hit:
    monkeypatch.setattr(rb.pool, "get", lambda c: (_ for _ in ()).throw(AssertionError("SAR called on cache hit")))
    assert rb.can(_user("u-2"), _cluster(2), "list", "pods", None, None) is True

def _client_allows(verbs: set[str]):
    class FakeStatus:
        def __init__(s, ok): s.allowed = ok
    class FakeSarApi:
        def create_self_subject_access_review(s, body):
            return SimpleNamespace(status=FakeStatus(body.resource_attributes.verb in verbs))
    class FakeClient:
        _config = object()
        _auth_api = FakeSarApi()
    return SimpleNamespace(_auth_api=FakeSarApi(),
                           api=SimpleNamespace(_auth_api=FakeSarApi()))
```

```python
# backend/tests/api/test_resources.py
import pytest

def test_unknown_kind_404_stable_code(client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = client.get("/api/v1/clusters/1/resources/widgets", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"

def test_unbound_cluster_404(client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = client.get("/api/v1/clusters/999/resources/pods", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"

@pytest.mark.integration
def test_list_pods_on_kind(client, auth_client, kind_client):
    cid, kubeconfig = kind_client
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    client.post("/api/v1/clusters", json={
        "name": "kind-test", "api_server": "https://127.0.0.1:6443",
        "kubeconfig": kubeconfig.decode(), "context": "kind-kind-test"}, headers=h)
    r = client.get(f"/api/v1/clusters/{cid}/resources/pods?namespace=default", headers=h)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert any(p["metadata"]["name"] == "kubedash-pod" for p in items)

@pytest.mark.integration
def test_rbac_denied_403(client, kind_client, app):
    """Denial path without kind RBAC gymnastics: a user whose K8s identity has
    no grants. The kind kubeconfig's user is 'kind' (admin) — so create a
    second binding for a KubeDash user and patch the SAR for that user's
    (cluster, user) pair to deny (the service seam), then expect 403."""
    cid, kubeconfig = kind_client
    from app.extensions import db
    from app.models.user import User
    from app.models.cluster import Cluster
    from app.models.binding import ClusterBinding
    import app.services.rbac as rb
    with app.app_context():
        c = Cluster.query.filter_by(name="kind-test").first()
        u = User(sub="denied-sa", email="d@example.com")
        db.session.add_all([u, ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")])
        db.session.commit()
        from app.core.security import issue_token_pair
        access, _ = issue_token_pair(u)
    import app.services.rbac as rb2
    orig = rb2._sar_allowed
    rb2._sar_allowed = lambda *a, **k: False
    try:
        r = client.get(f"/api/v1/clusters/{c.id}/resources/pods",
                       headers={"Authorization": f"Bearer {access}"})
    finally:
        rb2._sar_allowed = orig
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
```

`kind_cluster` / `kind_client` in `tests/conftest.py`. Per ARCHITECTURE.md §9
the cluster is **torn down per test file, not per test** (speed) — and, per
the critic fix, not held for the whole session: `kind_cluster` is
session-scoped *creation* (one cluster serves all integration files), but a
`pytest_runtest_logreport`-driven hook deletes + recreates it between test
**files** that use it, so a wedged cluster in one file cannot poison the next:

```python
# backend/tests/conftest.py (append)
import subprocess
import pytest

_KIND = "kubedash-test"
_kind_created = False

def _kind_available() -> bool:
    r = subprocess.run(["kind", "version"], capture_output=True)
    return r.returncode == 0

def _kind_create() -> bytes:
    global _kind_created
    existing = subprocess.run(["kind", "get", "clusters"],
                              capture_output=True, text=True).stdout
    if _KIND not in existing:
        subprocess.run(["kind", "create", "cluster", "--name", _KIND], check=True)
        _kind_created = True
    kubeconfig = subprocess.run(["kind", "get", "kubeconfig", "--name", _KIND],
                                capture_output=True, text=True).stdout.encode()
    subprocess.run(["kubectl", f"--context=kind-{_KIND}", "run", "kubedash-pod",
                    "--image=nginx:alpine", "--restart=Never"], check=True)
    return kubeconfig

@pytest.fixture(scope="session")
def kind_cluster():
    if not _kind_available():
        pytest.skip("kind not available")
    return _kind_create()

@pytest.fixture(scope="session")
def kind_client(kind_cluster, app):
    """(cluster_id, kubeconfig_bytes) — registers the kind cluster as a
    KubeDash Cluster row bound to the test user."""
    from app.extensions import db
    from app.models.cluster import Cluster
    from app.models.binding import ClusterBinding
    from app.models.user import User
    enc = encrypt_kubeconfig(kind_cluster)
    with app.app_context():
        u = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        c = Cluster(name="kind-test", api_server="https://127.0.0.1:6443",
                    kubeconfig_enc=enc, context="kind-kind-test")
        db.session.add(c); db.session.flush()
        db.session.add(ClusterBinding(user_id=u.id, cluster_id=c.id, role="admin"))
        db.session.commit()
        yield c.id, kind_cluster
        db.session.delete(c); db.session.commit()

# per-test-file teardown (ARCHITECTURE §9): a wedged cluster can't poison
# the next integration file
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_logreport(report):
    yield
    if report.when == "teardown" and report.fspath.name.startswith("test_"):
        # file-boundary detection: run after the last test of a file
        pass  # implemented via a module-scope fixture below instead

@pytest.fixture(scope="module", autouse=True)
def _kind_file_boundary(request):
    yield
    if "integration" in str(getattr(request.node, "markers", [])):
        subprocess.run(["kind", "delete", "cluster", "--name", _KIND],
                       capture_output=True)
        subprocess.run(["kind", "create", "cluster", "--name", _KIND],
                       capture_output=True)
        global _kind_created
```

(The executor implements the boundary as the `module`-scoped fixture shown —
one delete+create per integration test file, matching §9's "per test file,
not per test".)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/services/test_rbac.py tests/api/test_resources.py -v -m "not integration"`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.rbac'`

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/services/rbac.py
from app.extensions import redis_client
from app.services.k8s_client import pool
from kubernetes import client as kc

SAR_TTL = 30  # seconds (ARCHITECTURE.md §3.3)

def _cache_key(cluster_id: int, sub: str, verb: str, resource: str) -> str:
    return f"sar:{cluster_id}:{sub}:{verb}:{resource}"

def _sar_allowed(client, verb: str, resource: str, namespace: str | None, name: str | None) -> bool:
    sar = kc.SelfSubjectAccessReview(
        kc.SelfSubjectAccessReviewSpec(
            resource_attributes=kc.SelfSubjectAccessReviewResourceAttributes(
                verb=verb, resource=resource, namespace=namespace, name=name)))
    api = kc.AuthorizationV1Api(kc.ApiClient(client._config))
    return api.create_self_subject_access_review(body=sar).status.allowed

def can(user, cluster, verb: str, resource: str, namespace: str | None, name: str | None) -> bool:
    k = _cache_key(cluster.id, user.sub, verb, resource)
    hit = redis_client.get(k)
    if hit is not None:
        return hit == "1"
    ok = _sar_allowed(pool.get(cluster), verb, resource, namespace, name)
    redis_client.set(k, "1" if ok else "0", ex=SAR_TTL)
    return ok
```

*Test note:* the rbac tests monkeypatch `rb._sar_allowed` (not a per-call
factory) — the three tests above are written against `rb.can(...)` with
`SimpleNamespace` user/cluster doubles; replace the `_client_allows` helper
with a direct patch: `monkeypatch.setattr(rb, "_sar_allowed",
lambda client, verb, resource, ns, name: verb in {"list"})` (and `set()` for
the denied case). The `pool.get` patch stays, proving the cache-hit path
never reaches the pool.

`backend/app/api/resources.py` — `ResourceApi` (`resources_namespace = "resources"`):

```python
_KINDS = {"pods": ("list_pods", "pods")}   # kind → (K8sClient method, api resource name)

@blp.route("/clusters/<int:cluster_id>/resources/<kind>", methods=["GET"])
def list_resources(self, cluster_id: int, kind: str):
    if kind not in _KINDS:
        raise ResourceKindNotSupportedError(f"kind '{kind}' not supported")
    cluster = _bound_cluster_or_404(cluster_id)  # binding gate
    method, api_resource = _KINDS[kind]
    namespace = request.args.get("namespace")
    if not rbac.can(g.current_user, cluster, "list", api_resource, namespace, None):
        raise RbacDeniedError("list on " + api_resource)
    items = getattr(pool.get(cluster), method)(namespace)
    return {"items": items, "kind": kind, "cluster": cluster.name}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v -m "not integration"` (unit tier green)
Run: `cd backend && uv run pytest tests/api/test_resources.py -v -m integration` (if kind available)
Expected: PASS on both tiers

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/rbac.py backend/app/schemas/resource.py backend/app/api/resources.py backend/app/api/__init__.py backend/tests
git commit -m "feat(backend): RBAC SAR service + generic pod list endpoint, kind integration tier (R4, R10)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 5
"
```

### Task 6: Stub module surface (R9) + file-map guard

**Files:**
- Create: `backend/app/api/{logs,metrics,traces,audit,permissions,namespaces,access,kubeconfig,admin}.py`
- Create: `backend/app/api/scim/{__init__,users,groups}.py`
- Create: `backend/app/api/aggregated/{__init__,projects,sso_users,sso_groups}.py`
- Create: `backend/app/models/{rbac_template,namespace_request,access_request,scim_map,audit}.py`
- Create: `backend/app/services/{prometheus,loki,tempo,grafana,permission,namespace,access,provisioning,scim}.py`
- Create: `backend/app/tasks/{alerts,rbac_drift,access_expiry,ns_request_expiry}.py`
- Create: `backend/app/sockets/{__init__,logs}.py`
- Create: `backend/app/aggregated/{__init__,project,sso_user,sso_group}.py`
- Create: `backend/app/api/kubectl_auth.py`, `backend/app/schemas/kubectl_auth.py` (stub — the in-flight plugin change replaces the body; file-map guard covers the path)
- Create: `backend/app/api/_authhook.py` (shared `apply_auth(api)` extracted from Task 3's pattern)
- Modify: `backend/app/api/__init__.py` (register the stub APIs)
- Test: `backend/tests/test_file_map.py`
- Test: `backend/tests/api/test_stubs.py`

**Interfaces:**
- Consumes: `register_apis` (Task 3 pattern); `NotImplementedError_` (Task 3)
- Produces: one module per path in ARCHITECTURE.md §2's `backend/app/` tree that the spine did not build; each module: a docstring naming the owning ADR (`per .skillgrid/artifacts/04-adr-00NN-slug.md`) + minimal valid surface. API stubs register a Smorest `Api` whose single route returns `NotImplementedError_` (501). Model stubs: SQLAlchemy class with `__tablename__` + a `STUB = True` class attr, **not** registered in the initial migration (their owning change adds the migration). Service stubs: module-level docstring + a `raise NotImplementedError_` function matching the name ARCHITECTURE.md §3.3 gives (e.g., `services/namespace.py` → `provision(...)`). Task stubs: an RQ-callable function that logs + no-ops. `test_file_map.py` — the guard: a hard-coded list of the §2 `backend/app/` paths (copied verbatim from ARCHITECTURE.md §2 at authoring time) asserted to exist on disk; the test fails the suite when a path goes missing
- Seam: the file map list in `test_file_map.py` is the contract between ARCHITECTURE.md §2 and the tree; updating §2 means updating the list in the same PR
- Deletion test: delete the stubs and the file-map test fails; the in-flight kubectl-oidc-plugin change loses the `api/__init__.py` registration point for `kubectl_auth`
- Adapters: 1 (the test) — no seam needed beyond the file map

**SATISFIES:** `stub-surface-matches-architecture`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_file_map.py
import pathlib
import pytest

# ARCHITECTURE.md §2 — backend/app/ file map (spine paths + stub paths).
# Keep in sync with .skillgrid/ARCHITECTURE.md §2 when that file changes.
EXPECTED = [
    "app/__init__.py", "app/extensions.py",
    "app/core/config.py", "app/core/security.py", "app/core/leader.py", "app/core/errors.py",
    "app/api/__init__.py", "app/api/auth.py", "app/api/clusters.py", "app/api/resources.py",
    "app/api/logs.py", "app/api/metrics.py", "app/api/traces.py", "app/api/audit.py",
    "app/api/permissions.py", "app/api/namespaces.py", "app/api/access.py",
    "app/api/kubeconfig.py", "app/api/admin.py",
    "app/api/scim/__init__.py", "app/api/scim/users.py", "app/api/scim/groups.py",
    "app/api/aggregated/__init__.py", "app/api/aggregated/projects.py",
    "app/api/aggregated/sso_users.py", "app/api/aggregated/sso_groups.py",
    "app/models/user.py", "app/models/cluster.py", "app/models/binding.py",
    "app/models/token.py", "app/models/leader_lease.py",
    "app/models/rbac_template.py", "app/models/namespace_request.py",
    "app/models/access_request.py", "app/models/scim_map.py", "app/models/audit.py",
    "app/services/k8s_client.py", "app/services/rbac.py",
    "app/services/prometheus.py", "app/services/loki.py", "app/services/tempo.py",
    "app/services/grafana.py", "app/services/permission.py", "app/services/namespace.py",
    "app/services/access.py", "app/services/provisioning.py", "app/services/scim.py",
    "app/tasks/cluster_sync.py", "app/tasks/health.py", "app/tasks/alerts.py",
    "app/tasks/rbac_drift.py", "app/tasks/access_expiry.py", "app/tasks/ns_request_expiry.py",
    "app/sockets/events.py", "app/sockets/logs.py",
    # aggregated API service layer (§2, ADR-0012) — stubs
    "app/aggregated/__init__.py", "app/aggregated/project.py",
    "app/aggregated/sso_user.py", "app/aggregated/sso_group.py",
    # kubectl plugin bootstrap endpoint (§2 line: api/kubectl_auth.py) —
    # stub now; the in-flight kubectl-oidc-plugin change replaces its body
    "app/api/kubectl_auth.py", "app/schemas/kubectl_auth.py",
    "app/schemas/__init__.py",
    "app/schemas/auth.py", "app/schemas/cluster.py", "app/schemas/resource.py", "app/schemas/errors.py",
]

@pytest.mark.parametrize("rel", EXPECTED)
def test_path_exists(rel):
    base = pathlib.Path(__file__).resolve().parents[1]
    assert (base / rel).is_file(), f"ARCHITECTURE.md §2 path missing: {rel}"
```

```python
# backend/tests/api/test_stubs.py
def test_stub_routes_return_501_not_implemented(client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    for path in ("/api/v1/logs/query", "/api/v1/metrics/query", "/api/v1/traces"):
        r = client.get(path, headers=h)
        assert r.status_code == 501, path
        assert r.get_json()["error"]["code"] == "NOT_IMPLEMENTED", path
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_file_map.py tests/api/test_stubs.py -v`
Expected: FAIL — parametrized missing-path failures for every stub not yet created

- [ ] **Step 3: Write the stubs**

Each stub API follows one pattern (shown for `logs.py`; the other 8 API stubs +
scim repeat it with their ADR pointer and routes per ARCHITECTURE.md §3.2/§5):

```python
# backend/app/api/logs.py
"""Log query — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md
(ADR-0003). Live Loki query lands with the observability change; SSE log tail
per ADR-0009. Stub route returns 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint as blp
from app.core.errors import NotImplementedError_
from app.api._authhook import apply_auth   # shared hook from Task 3's pattern

class LogsApi(Api):
    resources_namespace = "logs"
    tags = ["Logs"]

    def on_init(self, app):
        apply_auth(self)

    @blp.route("/logs/query", methods=["GET"])
    def query(self):
        raise NotImplementedError_("logs query not implemented in base structure")
```

Task 6 therefore also creates `backend/app/api/_authhook.py` (extracted from
Task 3's shared pattern so the 10 stub APIs don't repeat it):

```python
# backend/app/api/_authhook.py
from flask import g, request
from app.core.security import verify_jwt
from app.core.errors import UnauthorizedError
from app.extensions import db
from app.models.user import User

def apply_auth(api) -> None:
    def _check():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise UnauthorizedError("missing or invalid token")
        claims = verify_jwt(header[len("Bearer "):])
        g.current_user = db.session.execute(
            db.select(User).filter_by(sub=claims["sub"])
        ).scalar_one_or_none()
        if g.current_user is None:
            raise UnauthorizedError("missing or invalid token")
        return None
    api.on_before_request(_check, blueprint=False)
```

(Tasks 4 and 5's spine APIs use `apply_auth` too — Task 3's "shared
auth-hook pattern" excerpt IS this function; the spine tasks import it
rather than inline it.)

Stub model pattern (`models/rbac_template.py`):

```python
"""Role templates — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
Migration for this table lands with the permission-management change."""
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class RBACTemplate(db.Model):
    __tablename__ = "rbac_templates"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
```

Stub service pattern (`services/prometheus.py`):

```python
"""Prometheus client — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md.
Thin httpx query/range client lands with the observability change."""
from app.core.errors import NotImplementedError_

def query(promql: str, **kw) -> dict:
    raise NotImplementedError_("prometheus query not implemented in base structure")
```

Stub task pattern (`tasks/rbac_drift.py`):

```python
"""RBAC drift detection — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
Runs every 10 min on the leader once templates exist."""
import logging
log = logging.getLogger(__name__)

def run() -> None:
    log.info("rbac_drift: stub no-op (base structure)")
```

Register all stub APIs in `app/api/__init__.py` alongside the spine ones.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v -m "not integration"`
Expected: PASS — full unit tier incl. the file-map guard

- [ ] **Step 5: Commit**

```bash
git add backend/app backend/tests/test_file_map.py backend/tests/api/test_stubs.py
git commit -m "feat(backend): ADR-pointing stub surface for all ARCHITECTURE.md §2 paths (R9)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 6
"
```

### Task 7: RQ worker spine (leader-gated) + cluster_sync/health tasks

**Files:**
- Create: `backend/app/tasks/__init__.py`
- Modify: `backend/app/tasks/cluster_sync.py`, `backend/app/tasks/health.py` (real implementations)
- Modify: `backend/wsgi.py` (RQ worker thread spawn, leader-gated)
- Test: `backend/tests/test_worker_gate.py`
- Test: `backend/tests/tasks/test_health.py`

**Interfaces:**
- Consumes: `Leader` (Task 2); `K8sClientPool` (Task 4); `Cluster` model (Task 2)
- Produces: `wsgi.py` — after `create_app()`, if `settings.role == "leader"`: start `Leader`, start an `rq.Worker` in a daemon thread (queue `kubedash`); **enqueue mechanism** (the critic gap): the worker thread doubles as the scheduler — each loop iteration, for each task path in `INTERVALS` (`app.tasks.health.run` every 60 s, `app.tasks.cluster_sync.run` every 300 s), it enqueues only when `leader.is_leader()` is True AND the interval has elapsed; then `worker.work(timeout=5)` drains the queue. A follower that loses leadership stops scheduling within one 5 s poll; a promoted follower resumes within one interval. (RQ's built-in cron jobs would run on every replica regardless of leadership — hence the leader-checked loop, not raw cron.) `tasks.health.run()` — for each `Cluster` row, hit `/readyz` and set `status = "up"|"down"` + `last_probe_at` (5 s timeout, no exception escape); `tasks.cluster_sync.run()` — same probe; on `status == "down"` it logs a warning (the alert path is a later change — **no `consecutive_down` column**: dropped as scope creep per critic, `last_probe_at` came in Task 2's migration)
- Seam: the worker/scheduler threads read `leader.is_leader()` each poll — swapping RQ for Celery later (ARCHITECTURE.md §11) touches only `wsgi.py`
- Deletion test: delete the worker gate and the two tasks run on every replica (duplicate jobs — the exact failure ADR-0008's gate prevents)
- Adapters: 1 (in-process thread) — the gate itself is the seam

**SATISFIES:** `app-boots-and-health-probes-report` (leader status) + threat-matrix process-integration RED test

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/tasks/test_health.py
def test_health_task_marks_down_cluster(app, monkeypatch):
    """Unit tier: pool.get is patched to raise (decryption of b"" fails) —
    the task must catch it and mark the cluster down without escaping."""
    import app.tasks.health as health
    from app.extensions import db
    from app.models.cluster import Cluster
    with app.app_context():
        c = Cluster(name="dead", api_server="https://127.0.0.1:1",
                    kubeconfig_enc=b"", context="dead")
        db.session.add(c); db.session.commit()
        cid = c.id
    monkeypatch.setattr(health.pool, "get",
                        lambda cluster: (_ for _ in ()).throw(ValueError("no kubeconfig")))
    health.run()
    with app.app_context():
        row = db.session.get(Cluster, cid)
        assert row.status == "down"
        assert row.last_probe_at is not None

def test_health_task_marks_up_cluster(app, monkeypatch):
    import app.tasks.health as health
    from app.extensions import db
    from app.models.cluster import Cluster
    with app.app_context():
        c = Cluster(name="live", api_server="https://1.2.3.4:6443",
                    kubeconfig_enc=b"", context="live")
        db.session.add(c); db.session.commit()
        cid = c.id
    monkeypatch.setattr(health.pool, "get",
                        lambda cluster: type("F", (), {"readyz": staticmethod(lambda: True)})())
    health.run()
    with app.app_context():
        assert db.session.get(Cluster, cid).status == "up"
```

```python
# backend/tests/test_worker_gate.py
import rq

def test_worker_thread_not_started_on_follower(monkeypatch):
    monkeypatch.setenv("KUBEDASH_ROLE", "follower")
    import importlib, app.wsgi as wsgi
    importlib.reload(wsgi)
    assert wsgi.worker_thread is None

def test_worker_thread_started_on_leader_candidate(monkeypatch):
    monkeypatch.setenv("KUBEDASH_ROLE", "leader")
    import importlib, app.wsgi as wsgi
    importlib.reload(wsgi)
    assert wsgi.worker_thread is not None
    assert wsgi.worker_thread.daemon

def test_enqueued_job_runs_when_leader(app, monkeypatch):
    """The gate must not just exist — a job enqueued while is_leader() is
    True must actually execute (ADR-0008: the gate prevents duplicate runs,
    not all runs)."""
    import app.wsgi as wsgi
    from app.extensions import redis_client
    ran = []
    def fake_health():
        ran.append(1)
    monkeypatch.setattr("app.tasks.health.run", fake_health)
    q = rq.Queue("kubedash", connection=redis_client)
    q.enqueue("app.tasks.health.run")   # registered task path
    wsgi.worker.work_one()              # process exactly one job
    assert ran == [1]
```

(`wsgi.worker` is the module-level `rq.Worker` reference; `work_one()`
processes a single job and returns — the deterministic form of the
idle-when-not-leader behavior. The scheduler loop itself is asserted by the
`wsgi.worker_thread is not None` tests plus a unit test of the loop function
`wsgi._schedule_if_leader(leader, queue, intervals)` called directly with a
fake leader returning False → no enqueue, True → enqueue.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_worker_gate.py tests/tasks/ -v`
Expected: FAIL — `wsgi.worker_thread` attribute missing; `tasks/health.py` is a stub

- [ ] **Step 3: Write minimal implementation**

```python
# backend/wsgi.py (full file)
import logging
import threading

import rq

from app import create_app

log = logging.getLogger(__name__)
app = create_app()
worker: rq.Worker | None = None
worker_thread: threading.Thread | None = None
INTERVALS = {"app.tasks.health.run": 60, "app.tasks.cluster_sync.run": 300}

def _schedule_if_leader(leader, queue: rq.Queue) -> None:
    """One scheduler tick: enqueue due tasks ONLY while this replica leads."""
    if not leader.is_leader():
        return
    for path, _interval in INTERVALS.items():
        queue.enqueue(path)

def _start_worker_if_leader() -> None:
    global worker, worker_thread
    from app.core.config import get_settings
    from app.core.leader import Leader
    from app.extensions import redis_client
    if get_settings().role != "leader":
        return
    leader = Leader(get_settings())
    leader.start()
    worker = rq.Worker(["kubedash"], connection=redis_client)

    def _run():
        queue = rq.Queue("kubedash", connection=redis_client)
        last = {}
        import time
        while True:
            now = time.monotonic()
            for path, interval in INTERVALS.items():
                if leader.is_leader() and now - last.get(path, 0) >= interval:
                    queue.enqueue(path)
                    last[path] = now
            worker.work(timeout=5)   # process what's queued; idle 5 s between polls

    worker_thread = threading.Thread(target=_run, daemon=True)
    worker_thread.start()
    app.extensions_leader = leader  # kept on the app for readyz

if __name__ != "__main__":
    _start_worker_if_leader()
```

```python
# backend/app/tasks/health.py
"""Cluster health probe — RQ task, leader-gated (ADR-0007/0008).
Updates clusters.status + last_probe_at from /readyz."""
import logging
from datetime import datetime, timezone

from app.extensions import db
from app.models.cluster import Cluster
from app.services.k8s_client import pool

log = logging.getLogger(__name__)

def run() -> None:
    with db.scoped_session() if hasattr(db, "scoped_session") else db.session() as s:
        for c in s.query(Cluster).all():
            try:
                ok = pool.get(c).readyz()
            except Exception:
                ok = False
            c.status = "up" if ok else "down"
            c.last_probe_at = datetime.now(timezone.utc)
        s.commit()
```

*Session note:* the task runs outside a request; under Flask-SQLAlchemy 3.x
use the session factory `db.scoped_session()` (or an explicit
`db.session()` within `app.app_context()`). The executor wires whichever the
Flask-SQLAlchemy version provides — the tests above drive `health.run()`
directly, so the session handling is verified, not assumed.

`tasks/cluster_sync.py`: same probe shape as health; on `status == "down"` it
logs a warning (the alert path is a later change). No model changes in this
task — `last_probe_at` came in Task 2's migration.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/ -v -m "not integration"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/wsgi.py backend/app/tasks backend/tests
git commit -m "feat(backend): leader-gated RQ worker + real cluster_sync/health tasks (R9 spine tasks)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 7
"
```

### Task 8: Frontend scaffold — CoreUI template + SPA shell + three views

**Files:**
- Create: `frontend/` (copy of `coreui/coreui-free-react-admin-template`, then extend)
- Modify: `frontend/src/_nav.tsx`, `frontend/src/routes.tsx`, `frontend/src/components/Header.tsx` (cluster switcher)
- Create: `frontend/src/lib/api.ts`, `frontend/src/lib/types.ts`, `frontend/src/store/cluster.ts`, `frontend/src/hooks/useCluster.ts`
- Create: `frontend/src/views/Login/index.tsx`, `frontend/src/views/Clusters/index.tsx`, `frontend/src/views/Cluster/{index,Pods}.tsx`
- Create: `frontend/tests/api.test.ts`, `frontend/tests/views/Clusters.test.tsx`, `frontend/tests/views/Cluster.test.tsx`, `frontend/tests/msw.ts` (MSW node server helper)
- Create: `frontend/e2e/smoke.spec.ts`, `frontend/playwright.config.ts`
- Modify: `frontend/package.json` (add deps: `@tanstack/react-query`, `react-router-dom`, `zustand`, `socket.io-client`, `@fortawesome/fontawesome-free`, `monaco-editor`; dev: `msw`, `openapi-typescript`)

**Interfaces:**
- Consumes: the backend v1 contract (Task 3–5): `/api/v1/auth/login|callback|refresh|me`, `/api/v1/clusters[/<id>[/health]]`, `/api/v1/clusters/<id>/resources/pods`, error envelope
- Produces: `lib/api.ts` — `apiFetch(path: string, init?: RequestInit) -> Promise<{ data: unknown; error: { code: string; message: string } | null; meta: { status: number } }` (attaches `kd_token` from localStorage/cookie, on 401 runs a single in-flight `POST /api/v1/auth/refresh` then retries once, on 403 toasts "no permission"); `store/cluster.ts` — Zustand store `{ selectedCluster: { id, name } | null, setSelectedCluster }`; `views/Clusters` — CoreUI table of bound clusters + a register form (name, api_server, kubeconfig textarea, context) posting to R3; `views/Cluster/Pods.tsx` — TanStack Query `useQuery(["pods", clusterId, ns])` hitting R4, rendered in a CoreUI table with status icons (Font Awesome `fa-circle`); `views/Login` — on mount redirects to `/api/v1/auth/login`; `useCluster()` — fetches `/auth/me` + `/clusters` on mount, populates the store, exposes `permissions` for later button-hiding (R4's 403 path is where it pays off)
- Seam: `apiFetch` is the single HTTP seam — the MSW handlers in tests and the e2e's real Flask server are the two adapters; switching the backend base URL is one env var (`VITE_API_BASE`)
- Deletion test: delete `lib/api.ts` and all three views lose auth attach + refresh (each would re-implement 401 handling — the duplication the wrapper exists to prevent)
- Adapters: 2 — MSW (unit/component) + real Flask-served bundle (e2e)

**SATISFIES:** `spa-shell-renders-cluster-pods`

- [ ] **Step 1: Scaffold + write the failing tests**

```bash
cd frontend
# template is already copied in (setup step below); install KubeDash deps
pnpm add @tanstack/react-query react-router-dom zustand socket.io-client @fortawesome/fontawesome-free monaco-editor
pnpm add -D msw openapi-typescript @playwright/test
pnpm exec playwright install chromium
```

```typescript
// frontend/tests/api.test.ts
import { apiFetch } from "../src/lib/api";

global.fetch = jest.fn();
const fetchMock = global.fetch as jest.Mock;

test("attaches bearer token", async () => {
  fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ items: [] }) });
  localStorage.setItem("kd_token", "tok-1");
  const r = await apiFetch("/api/v1/clusters");
  expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer tok-1");
  expect(r.data).toEqual({ items: [] });
});

test("401 triggers single refresh then retry", async () => {
  fetchMock
    .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: { code: "UNAUTHORIZED", message: "x" } }) })
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access: "tok-2" }) })  // refresh
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ items: [1] }) });
  localStorage.setItem("kd_token", "tok-1");
  const r = await apiFetch("/api/v1/clusters");
  expect(r.data).toEqual({ items: [1] });
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(localStorage.getItem("kd_token")).toBe("tok-2");
});

test("error envelope is surfaced, not thrown", async () => {
  fetchMock.mockResolvedValueOnce({ ok: false, status: 403, json: async () => ({ error: { code: "RBAC_DENIED", message: "nope" } }) });
  const r = await apiFetch("/api/v1/clusters/1/resources/pods");
  expect(r.error?.code).toBe("RBAC_DENIED");
});

test("second 401 uses the ROTATED refresh token (double rotation works)", async () => {
  // 1st request 401 → refresh (rt-1 → rt-2) → retry ok
  // 2nd request 401 → refresh (rt-2 → rt-3) → retry ok
  fetchMock
    .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: { code: "UNAUTHORIZED", message: "x" } }) })
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access: "tok-2", refresh: "rt-2" }) })
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ items: [1] }) })
    .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: { code: "UNAUTHORIZED", message: "x" } }) })
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access: "tok-3", refresh: "rt-3" }) })
    .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ items: [2] }) });
  localStorage.setItem("kd_token", "tok-1");
  localStorage.setItem("kd_refresh", "rt-1");
  const r1 = await apiFetch("/api/v1/clusters");
  expect(r1.data).toEqual({ items: [1] });
  expect(localStorage.getItem("kd_refresh")).toBe("rt-2");   // rotated token stored
  const r2 = await apiFetch("/api/v1/clusters");
  expect(r2.data).toEqual({ items: [2] });
  expect(localStorage.getItem("kd_refresh")).toBe("rt-3");
});
```

```tsx
// frontend/tests/views/Clusters.test.tsx
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { server } from "../msw";   // MSW node server (template setup)
import { http, HttpResponse } from "msw";
import ClustersView from "../../src/views/Clusters";

beforeEach(() =>
  server.use(
    http.get("*/api/v1/clusters", () =>
      HttpResponse.json({ items: [{ id: 1, name: "prod", status: "up" }] })),
  ),
);

test("lists bound clusters from the API", async () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/clusters"]}>
        <ClustersView />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  expect(await screen.findByText("prod")).toBeTruthy();
});
```

```tsx
// frontend/tests/views/Cluster.test.tsx
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { http, HttpResponse } from "msw";
import { server } from "../msw";
import ClusterView from "../../src/views/Cluster";
import { useClusterStore } from "../../src/store/cluster";

beforeEach(() => {
  useClusterStore.getState().setSelectedCluster({ id: 1, name: "prod" });
  server.use(
    http.get("*/api/v1/clusters/1/resources/pods", () =>
      HttpResponse.json({ items: [{ metadata: { name: "p1" }, status: { phase: "Running" } }] })),
  );
});

test("renders the pod table for the selected cluster", async () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/clusters/1"]}>
        <ClusterView />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  expect(await screen.findByText("p1")).toBeTruthy();
  expect(screen.getByText("Running")).toBeTruthy();
});
```

**Pinned export names:** `views/Clusters/index.tsx` default-exports
`ClustersView`; `views/Cluster/index.tsx` default-exports `ClusterView`
(which renders `./Pods.tsx`); `views/Login/index.tsx` default-exports
`LoginView`; `store/cluster.ts` exports `useClusterStore` with state
`{ selectedCluster: { id: number; name: string } | null }` and action
`setSelectedCluster`. `msw.ts` (test helper) exports `server`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && pnpm test`
Expected: FAIL — `lib/api` not found / views not implemented

- [ ] **Step 3: Write minimal implementation**

```typescript
// frontend/src/lib/api.ts
const API_BASE = import.meta.env.VITE_API_BASE ?? "";
let inFlightRefresh: Promise<string> | null = null;

export interface ApiResult<T = unknown> {
  data: T | null; error: { code: string; message: string } | null; meta: { status: number };
}

async function refreshOnce(): Promise<string> {
  if (!inFlightRefresh) {
    inFlightRefresh = fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: localStorage.getItem("kd_refresh") ?? "" }),
    }).then(r => {
      if (!r.ok) throw new Error("refresh failed");
      return r.json();
    }).then(j => {
      localStorage.setItem("kd_token", j.access);
      localStorage.setItem("kd_refresh", j.refresh);  // ROTATED token (backend always rotates)
      return j.access as string;
    }).finally(() => { inFlightRefresh = null; });
  }
  return inFlightRefresh;
}

export async function apiFetch<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  const doFetch = (token: string | null) =>
    fetch(`${API_BASE}${path}`, { ...init,
      headers: { ...(init.headers ?? {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) } });
  let res = await doFetch(localStorage.getItem("kd_token"));
  if (res.status === 401) {
    try { const t = await refreshOnce(); res = await doFetch(t); }
    catch { /* fall through to error envelope */ }
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) return { data: null, error: body.error ?? { code: "UNKNOWN", message: String(res.status) }, meta: { status: res.status } };
  return { data: body as T, error: null, meta: { status: res.status } };
}
```

Views per the Interfaces block: `Login` (on mount: if the URL carries
`?token=…&refresh=…` from the OIDC callback, store both in localStorage and
`history.replaceState` to `/`; otherwise redirect to `/api/v1/auth/login`),
`Clusters` (CoreUI `CTable` + register `CForm`), `Cluster/index.tsx`
(default-exports `ClusterView`, renders `./Pods.tsx`: TanStack Query +
`CTable`, `FontAwesomeIcon` status icons). `routes.tsx` wires
`/login`, `/clusters`, `/clusters/:id`; `ProtectedRoute` checks for a stored
token + a successful `/auth/me` (via `useCluster()`). `Header.tsx` gains the
cluster switcher `CDropdown` bound to the Zustand store. `main.tsx` wraps the
app in `QueryClientProvider`. Generate types once the backend runs
(`pnpm exec openapi-typescript http://localhost:8080/api/openapi.json -o src/lib/types.ts`;
committed in this task).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && pnpm test && pnpm exec tsc --noEmit && pnpm lint && pnpm build`
Expected: PASS on all four

- [ ] **Step 5: Commit**

```bash
git add frontend
git commit -m "feat(frontend): CoreUI SPA shell with Login/Clusters/Cluster views + api client (R5)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 8
"
```

### Task 9: Single-container Dockerfile + SPA static serving (catch-all)

> ⚠ **one-way: OD-4 — catch-all ordering + hashed-asset cache headers (ADR-0006).**

**Files:**
- Create: `backend/Dockerfile`
- Create: `.dockerignore`
- Modify: `backend/app/__init__.py` (`register_static` — real catch-all + cache headers)
- Test: `backend/tests/test_static.py`
- Test: `backend/tests/test_dockerfile.py`

**Interfaces:**
- Consumes: `frontend/dist/` (Task 8); Flask app (Task 1)
- Produces: `register_static(app)` — `GET /assets/<path:f>` → `send_from_directory(static_dir, f)` with `Cache-Control: immutable, max-age=31536000`; `GET /<path:p>` (non-API, non-`/ws/*`, non-`/api/v1/*`) → `index.html` with `Cache-Control: no-cache`; the route is registered **last** in the factory (after Smorest + SocketIO registration) and is **idempotency-guarded** (`if app.config.get("_STATIC_REGISTERED"): return`; tests set `KUBEDASH_STATIC_DIR` via `config_overrides` BEFORE `create_app()` — no re-registration call needed); `Dockerfile` — stage 1 `node:20` → `pnpm install --frozen-lockfile` → `pnpm build` (build context is the repo root, `frontend/` subfolder); stage 2 `python:3.12-slim` → `uv sync --frozen --no-dev` from `backend/`; stage 3 runtime — copy `app/` + `wsgi.py` + `frontend/dist/` → `/app/static/`, `USER 10001`, `HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"`, `CMD ["gunicorn", "-b", "0.0.0.0:8080", "wsgi:app"]` with worker count/threads from `GUNICORN_WORKERS` / `GUNICORN_THREADS` env (defaults 4/2, §7.1). **Worker class: sync** — ADR-0009 makes SSE the push channel and this change ships no bidirectional WS handler (SocketIO's long-poll fallback is not enabled per §3.6, but no route uses it yet either); the `gevent` dep + `GUNICORN_WORKER_CLASS` env seam are added by the exec/SSE-stream change that first needs it (critic scope-creep fix — documented here so it is a decision, not a drift)
- Seam: `static_dir` resolved from `KUBEDASH_STATIC_DIR` config (default `/app/static`) — the conftest `app` fixture passes a temp fake `dist/` via `config_overrides` before `create_app()`
- Deletion test: delete `register_static` and the SPA is unservable (ADR-0006's whole point — no nginx)
- Adapters: 2 — the image build (real dist) and the test's fake dist dir

**SATISFIES:** `chart-renders-deployment-with-replica-id` (image half) + `spa-shell-renders-cluster-pods` (serving half)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_static.py
# The conftest `app` fixture is rebuilt for these tests with a fake dist dir
# passed via config_overrides BEFORE create_app() (no re-registration):
import pytest

@pytest.fixture()
def static_app(pg_container, redis_container, tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "main.abc.js").write_text("console.log(1)")
    (tmp_path / "index.html").write_text("<html>kubedash</html>")
    from app import create_app
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": pg_container.get_connection_url(),
        "REDIS_URL": f"redis://{redis_container.get_container_host()}:{redis_container.exposed_port(6379)}",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
        "KUBEDASH_STATIC_DIR": str(tmp_path),
    })
    with application.app_context():
        from app.extensions import db
        db.create_all()
    return application

@pytest.fixture()
def static_client(static_app):
    return static_app.test_client()

def test_index_served_at_root_and_spa_fallback(static_client):
    r = static_client.get("/")
    assert r.status_code == 200 and b"kubedash" in r.data
    assert r.headers["Cache-Control"] == "no-cache"
    r2 = static_client.get("/clusters/123")  # non-API path → SPA fallback
    assert r2.status_code == 200 and b"kubedash" in r2.data
    r3 = static_client.get("/assets/main.abc.js")
    assert r3.status_code == 200
    assert "immutable" in r3.headers["Cache-Control"]

def test_api_not_shadowed_by_catchall(static_client):
    r = static_client.get("/api/v1/clusters")
    assert r.status_code == 401  # auth hook, NOT index.html
    assert b"<html>" not in r.data
```

```python
# backend/tests/test_dockerfile.py
def test_dockerfile_runs_use_no_user_and_fixed_args():
    import pathlib, re
    df = pathlib.Path(__file__).resolve().parents[1] / "Dockerfile"
    text = df.read_text()
    assert re.search(r"^USER 10001", text, re.M), "must run non-root"
    # threat matrix: no unquoted command-substitution from ARGs in RUN lines
    for line in text.splitlines():
        if line.strip().startswith("RUN"):
            assert "$(" not in line or "${" in line, f"unquoted $() in RUN: {line}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_static.py tests/test_dockerfile.py -v`
Expected: FAIL — `register_static` is a no-op; `Dockerfile` missing

- [ ] **Step 3: Write minimal implementation**

```python
# backend/app/__init__.py — replace the Task 1 stub:
def register_static(app: Flask) -> None:
    """Last registration: /api/v1/* and /ws/* win over the SPA catch-all (OD-4).
    Idempotency-guarded: KUBEDASH_STATIC_DIR is read at registration time from
    app.config (set via config_overrides before create_app in tests)."""
    if app.config.get("_STATIC_REGISTERED"):
        return
    app.config["_STATIC_REGISTERED"] = True
    from flask import abort, send_from_directory
    static_dir = app.config.get("KUBEDASH_STATIC_DIR", "/app/static")

    @app.get("/assets/<path:filename>")
    def assets(filename: str):
        resp = send_from_directory(static_dir, "assets/" + filename)
        resp.headers["Cache-Control"] = "immutable, max-age=31536000"
        return resp

    @app.get("/<path:path_>")
    def spa(path_):
        if path_.startswith(("api/", "ws/")) or path_.endswith((".js", ".css", ".ico", ".png", ".json", ".map")):
            abort(404)
        resp = send_from_directory(static_dir, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
```

(The Task 1 factory already calls `register_static(app)` last; Task 1's
no-op body is replaced by this one — same call site, no double registration.)

```dockerfile
# backend/Dockerfile (build context = repo root)
# --- stage 1: frontend build ----------------------------------------------
FROM node:20 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# --- stage 2: python deps --------------------------------------------------
FROM python:3.12-slim AS deps
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# --- stage 3: runtime ------------------------------------------------------
FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=deps /app/.venv /app/.venv
COPY backend/app ./app
COPY backend/wsgi.py ./
COPY --from=frontend /build/dist ./static
ENV PATH="/app/.venv/bin:$PATH" \
    KUBEDASH_STATIC_DIR=/app/static \
    GUNICORN_WORKERS=4 GUNICORN_THREADS=2
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["sh", "-c", "exec gunicorn -w \"$GUNICORN_WORKERS\" --threads \"$GUNICORN_THREADS\" -b 0.0.0.0:8080 wsgi:app"]
```

No `gevent` dep (sync workers — see the worker-class decision in the
Interfaces block). The `sh -c` line is the only command-substitution in the
Dockerfile and it uses only env vars set in the same image (satisfies the
threat-matrix RUN/ENV check in `test_dockerfile.py` — update that test to
allow `$VAR` in the CMD line, restricting the rule to `RUN` lines as written).

- [ ] **Step 4: Run tests + build the image**

Run: `cd backend && uv run pytest tests/test_static.py tests/test_dockerfile.py -v`
Run: `docker build -f backend/Dockerfile -t kubedash:base-structure .`
Expected: tests PASS; `docker build` exits 0
Smoke: `docker run --rm -p 8080:8080 kubedash:base-structure && curl -sf localhost:8080/healthz` → `{"status":"ok"}` (backstop T12; needs Docker — if unavailable in this env, record it in the task notes and let CI's e2e job carry it)

- [ ] **Step 5: Commit**

```bash
git add backend/Dockerfile .dockerignore backend/app/__init__.py backend/pyproject.toml backend/tests/test_static.py backend/tests/test_dockerfile.py
git commit -m "feat(deploy): multi-stage single-container image + SPA catch-all serving (R6, OD-4)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 9
OneWay: OD-4 catch-all ordering + asset cache headers (ADR-0006)
"
```

### Task 10: Helm chart + CI/CD workflows

**Files:**
- Create: `charts/kubedash/Chart.yaml`
- Create: `charts/kubedash/values.yaml`
- Create: `charts/kubedash/templates/_helpers.tpl`
- Create: `charts/kubedash/templates/deployment.yaml`
- Create: `charts/kubedash/templates/service.yaml`
- Create: `charts/kubedash/templates/configmap.yaml`
- Create: `charts/kubedash/templates/secret.yaml`
- Create: `.github/workflows/ci.yaml`
- Create: `.github/workflows/e2e.yaml`
- Create: `e2e/oidc-mock.py` (CI service container; ~80-line Flask mock per the Interfaces note)
- Create: `frontend/e2e/smoke.spec.ts` (if not fully written in Task 8)
- Test: `backend/tests/test_chart.py` (template assertions)

**Interfaces:**
- Consumes: the image contract (Task 9: port 8080, `/healthz`, `KUBEDASH_*` env); the §7.2 values subset (`image`, `gunicorn`, `leaderElection`, `auth.oidc`, `postgresql.enabled`, `redis.enabled`)
- Produces: a chart that renders a Deployment with: `KUBEDASH_REPLICA_ID` from the Downward API (`fieldRef: metadata.name`), `KUBEDASH_ROLE=leader` (all replicas are candidates — the election decides, §7.4), env for `DATABASE_URL`/`REDIS_URL`/OIDC from values/secret, `GUNICORN_WORKERS`/`GUNICORN_THREADS` from `gunicorn.*` values into the container env (the image's CMD reads them — §7.1 tunables), **and the six §7.5 tuning keys as env only where `Settings` reads them**: this change adds exactly two to `Settings` — `first_paint_backstop: str = "5m"` and `namespace_list_timeout: str = "5s"` (the spine's two knobs: the SPA's "syncing…" backstop and the namespace LIST timeout) — and the chart renders `KUBEDASH_FIRST_PAINT_BACKSTOP` + `KUBEDASH_NAMESPACE_LIST_TIMEOUT`; the other four §7.5 keys (`context_switch_timeout`, `max_scope_candidates`, `list_page_size`, `namespace_scope`) are **deferred to the informer change (ADR-0010)** that first consumes them (critic fix: env keys with no `Settings` field are silently dropped by Pydantic). A Service (port 80 → 8080); a ConfigMap (OIDC public config + feature flags); a Secret (`OIDC_CLIENT_SECRET`, `KUBEDASH_JWT_SECRET`, `KUBEDASH_SECRET_KEY` — all three read by `Settings`/`init_oidc`). `ci.yaml` jobs: `backend` (setup-python 3.12 + uv → ruff check, mypy, pytest `-m "not integration"`), `frontend` (setup-node 20 + pnpm → tsc --noEmit, eslint, pnpm build), `cli` (go 1.22 → go vet, go test), `chart` (helm lint + helm template + `pytest backend/tests/test_chart.py`), `image` (docker build + trivy image, fail on CRITICAL). `e2e.yaml` (on `main`): kind cluster → docker load image → `helm install` → Playwright `e2e/smoke.spec.ts` (login with mock OIDC → clusters list → pods table)
- Seam: values.yaml keys → Deployment env is the seam; prod vs dev clusters differ only in values
- Deletion test: delete the chart and there is no deploy path for the image (the §7.4 install story breaks)
- Adapters: 2 — dev values (embedded PG/Redis subcharts off by default in the base structure; external URLs) and the CI-rendered template test

**SATISFIES:** `chart-renders-deployment-with-replica-id` + `ci-green-on-base-structure`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_chart.py
import subprocess, yaml, pathlib

def _template() -> str:
    return subprocess.run(["helm", "template", "t", str(pathlib.Path(__file__).resolve().parents[2] / "charts/kubedash")],
                          check=True, capture_output=True, text=True).stdout

def test_deployment_has_replica_id_from_downward_api():
    docs = [d for d in yaml.safe_load_all(_template()) if d and d.get("kind") == "Deployment"]
    assert docs, "no Deployment rendered"
    env = {e["name"]: e for e in docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
    rid = env["KUBEDASH_REPLICA_ID"]
    assert rid["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    assert env["KUBEDASH_ROLE"]["value"] == "leader"

def test_oidc_env_wired_from_values():
    out = subprocess.run(["helm", "template", "t", str(pathlib.Path(__file__).resolve().parents[2] / "charts/kubedash"),
                          "--set", "auth.oidc.issuer=https://idp.test",
                          "--set", "auth.oidc.clientId=kubedash",
                          "--set", "image.repository=ghcr.io/org/kubedash"],
                         check=True, capture_output=True, text=True).stdout
    assert "https://idp.test" in out
    assert "KUBEDASH_OIDC_CLIENT_ID" in out and "kubedash" in out
    assert "ghcr.io/org/kubedash" in out

def test_gunicorn_and_tuning_env_rendered():
    out = subprocess.run(["helm", "template", "t", str(pathlib.Path(__file__).resolve().parents[2] / "charts/kubedash"),
                          "--set", "gunicorn.workers=8", "--set", "gunicorn.threads=3"],
                         check=True, capture_output=True, text=True).stdout
    assert "GUNICORN_WORKERS" in out and "8" in out
    assert "GUNICORN_THREADS" in out and "3" in out
    assert "KUBEDASH_FIRST_PAINT_BACKSTOP" in out
    assert "KUBEDASH_NAMESPACE_LIST_TIMEOUT" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/test_chart.py -v`
Expected: FAIL — chart dir missing / helm template error

- [ ] **Step 3: Write the chart + workflows**

`Chart.yaml`: `name: kubedash`, `version: 0.1.0`, `appVersion: "0.1.0"`, `type: application`.
`values.yaml` — the §7.2 subset with dev defaults (`replicaCount: 1`,
`image.repository: ghcr.io/org/kubedash`, `image.tag: "0.1.0"`,
`gunicorn: {workers: 4, threads: 2}`, `leaderElection: {heartbeatInterval: 10s, staleThreshold: 30s}`,
`auth.oidc: {issuer: "", clientId: "", clientSecret: ""}`,
`postgresql: {enabled: false}`, `redis: {enabled: false}`,
`cluster: {firstPaintBackstop: 5m, ...}` per §7.5).
`deployment.yaml` — the env block per the Interfaces block, including the
Downward API `KUBEDASH_REPLICA_ID`, `KUBEDASH_JWT_SECRET`/`KUBEDASH_SECRET_KEY`/
`OIDC_CLIENT_SECRET` from the Secret, the §7.5 tuning keys as env, liveness
`/healthz` + readiness `/readyz` probes, `securityContext.runAsUser: 10001`.
`service.yaml` (ClusterIP 80→8080), `configmap.yaml` (OIDC public + features),
`secret.yaml` (stringData from values, `type: Opaque`).

`.github/workflows/ci.yaml`:

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [rebase, main]
jobs:
  backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
        working-directory: backend
      - run: uv run ruff check . && uv run mypy app
        working-directory: backend
      - run: uv run pytest -m "not integration"
        working-directory: backend
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm }
      - run: pnpm install --frozen-lockfile
        working-directory: frontend
      - run: pnpm exec tsc --noEmit && pnpm lint && pnpm build
        working-directory: frontend
  cli:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22" }
      - run: go vet ./... && go test ./...
        working-directory: cli
  chart:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
      - run: helm lint charts/kubedash && helm template t charts/kubedash > /dev/null
  image:
    runs-on: ubuntu-latest
    needs: [frontend, backend]
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v6
        with: { context: ., file: backend/Dockerfile, tags: kubedash:ci, load: true }
      - uses: aquasecurity/trivy-action@0.24.0
        with: { image-ref: kubedash:ci, severity: CRITICAL, exit-code: "1" }
  lint-workflows:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          docker run --rm -v ${{ github.workspace }}:/wt rhysd/actionlint
```

`.github/workflows/e2e.yaml` (on `main` push): kind + `helm install` with the
dev values + a mock OIDC + `pnpm exec playwright test e2e/smoke.spec.ts`.
**Mock OIDC for e2e (decision, per the threat-matrix process-integration row):**
a ~80-line Flask app at `e2e/oidc-mock.py` (checked in, run as a CI service
container on port 9096) implementing `/authorize` (302 back with
`code=fixed&state=<echoed>`), `/token` (returns a static ID token), and
`/.well-known/openid-configuration` — the same contract as Task 3's
`MockOIDC`, but network-reachable so the real Authlib adapter runs in e2e
(the unit tier monkeypatches; e2e exercises the real `oidc_authorize_url` /
`oidc_exchange` bodies). The Playwright journey: hit `/login` → the app
302-chains through the mock IdP back to `/?token=…` → the SPA stores the JWT
→ `/clusters` → register the kind cluster → `/clusters/<id>` shows the pod.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_chart.py -v`
Run: `actionlint` (local or via the workflow's own lint job)
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add charts .github backend/tests/test_chart.py frontend/e2e frontend/playwright.config.ts
git commit -m "feat(deploy): Helm chart + CI/CD workflows (R6, R8)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 10
"
```

### Task 11: Go CLI skeleton

**Files:**
- Create: `cli/go.mod` (module `github.com/org/kubedash-cli`, go 1.22)
- Create: `cli/main.go`
- Create: `cli/cmd/version.go`
- Create: `cli/cmd/get_token.go`
- Create: `cli/cmd/clean.go`
- Create: `cli/cmd/setup.go`
- Create: `cli/Makefile`
- Create: `cli/.krew.yaml`
- Test: `cli/cmd/version_test.go`

**Interfaces:**
- Consumes: nothing (cobra only — the oauth2/keyring deps are the in-flight plugin change's)
- Produces: `kubedash version` → `kubedash <version>` on stdout (version from `var version = "0.1.0"` overridable via `-ldflags "-X main.version=..."`, printed by `main.Execute()`); `kubedash get-token` → exits 2, stderr `get-token: not yet implemented (see .skillgrid/specs/2026-10-17-kubectl-oidc-plugin/blueprint.md)`; `clean` / `setup` → same not-implemented shape; `Makefile` targets `build` (local) + `cross` (5 combos: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64, `CGO_ENABLED=0`)
- Seam: cobra command tree — `get-token`'s body is where the plugin change plugs its `pkg/oidc` flow
- Deletion test: delete `cli/` and the in-flight plugin change has no module to land its `pkg/` packages in
- Adapters: 1 (local binary) — no seam needed

**SATISFIES:** `cli-version-prints`

- [ ] **Step 1: Write the failing test**

```go
// cli/cmd/version_test.go
package cmd

import (
	"bytes"
	"testing"
)

func TestVersionOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := buf.String(); got != "kubedash 0.1.0\n" {
		t.Errorf("version output = %q, want %q", got, "kubedash 0.1.0\n")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd cli && go test ./...`
Expected: FAIL — `rootCmd` undefined (no cmd package yet)

- [ ] **Step 3: Write minimal implementation**

```go
// cli/cmd/root.go (package cmd)
var rootCmd = &cobra.Command{
	Use:   "kubedash",
	Short: "KubeDash kubectl credential plugin (spine: version only in base structure)",
	SilenceUsage: true,
}
func Execute() { _ = rootCmd.Execute() }
func init() {
	rootCmd.AddCommand(versionCmd, getTokenCmd, cleanCmd, setupCmd)
}

// cli/cmd/version.go
var version = "0.1.0" // overwritten via -ldflags "-X cmd.version=<v>"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the plugin version",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "kubedash %s\n", version)
	},
}

// cli/cmd/get_token.go
var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Print an ExecCredential (not yet implemented — see the kubectl-oidc-plugin blueprint)",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.ErrOrStderr(), "get-token: not yet implemented (see .skillgrid/specs/2026-10-17-kubectl-oidc-plugin/blueprint.md)")
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetErr(fmt.Errorf("not implemented"))
		_ = cmd.SilenceUsage
		// exit 2:
		os.Exit(2)
	},
}
```

`clean.go` / `setup.go` — same not-implemented shape. `go mod tidy` adds
`cobra`. `Makefile`:

```make
BIN=kubedash
VERSION ?= 0.1.0
build:
	CGO_ENABLED=0 go build -ldflags "-X cmd.version=$(VERSION)" -o $(BIN) .
cross:
	for t in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do \
	  os=$${t%_*}; arch=$${t#*_}; ext=""; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "-X cmd.version=$(VERSION)" -o dist/$(BIN)-$$os-$$arch$$ext .; \
	done
```

`.krew.yaml` — standard krew manifest (versioned binary references, 5
platforms), `version: v0.1.0`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd cli && go vet ./... && go test ./... && make build && ./kubedash version && ./kubedash get-token; test $? -eq 2`
Expected: all pass; `version` prints `kubedash 0.1.0`; `get-token` exits 2

- [ ] **Step 5: Commit**

```bash
git add cli
git commit -m "feat(cli): Go cobra skeleton, version real, get-token stubbed to plugin change (R7)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 11
"
```

### Task 12: acceptance.feature + root docs + full-suite verification

**Files:**
- Create: `.skillgrid/specs/2026-10-17-kubedash-base-structure/acceptance.feature`
- Create: `README.md` (root — 5.0 layout, quickstart: dev loop per component)
- Modify: `.gitignore` (5.0 additions: `backend/.venv`, `frontend/node_modules`, `frontend/dist`, `cli/dist`, `*.pyc`, `.mypy_cache`, `.ruff_cache`)
- Modify: `.skillgrid/state.yaml` (current_phase → `blueprint` committed now; `slicing` after tasks.md lands — committed in THIS task's step 4, not left loose)

**Interfaces:**
- Consumes: every scenario name the tasks' SATISFIES lines reference
- Produces: `acceptance.feature` — one `Feature:` containing **10 scenarios** (the names below are scenario names, not feature names; Gherkin has one feature per file): `app-boots-and-health-probes-report`, `oidc-login-issues-jwt`, `cluster-register-and-health`, `list-pods-for-bound-cluster`, `spa-shell-renders-cluster-pods`, `chart-renders-deployment-with-replica-id`, `cli-version-prints`, `stub-surface-matches-architecture`, `ci-green-on-base-structure`, `test-fixtures-boot` — mapping 1:1 to the Must-Have truths (T1–T18 grouped by scenario)
- Seam: none (deliverable)
- Deletion test: n/a
- Adapters: n/a

**SATISFIES:** (closes all open scenarios)

- [ ] **Step 1: Write acceptance.feature**

```gherkin
Feature: KubeDash 5.0 base structure tracer spine

  Background:
    Given a KubeDash app built by create_app() against Testcontainers Postgres and Redis

  Scenario: app boots and health probes report
    When GET /healthz is called
    Then the response is 200
    When GET /readyz is called with dependencies up
    Then the response is 200 with database "ok" and redis "ok"
    When GET /readyz is called with Redis down
    Then the response is 503 and the body names "redis"

  Scenario: OIDC login issues a JWT
    When an unauthenticated browser POSTs /api/v1/auth/login
    Then the response is 302 to the OIDC authorize URL
    When the callback completes with a valid code
    Then a users row is upserted by sub and a JWT (HS256, 15 min) plus a hashed refresh token are issued
    When GET /api/v1/auth/me is called with the JWT
    Then the response echoes the OIDC sub
    When GET /api/v1/clusters is called without a JWT
    Then the response is 401 {"error": {"code": "UNAUTHORIZED"}}
    When a refresh token is used twice
    Then the second use is 401 and the stored row is revoked

  Scenario: cluster register and health
    When an authenticated user POSTs /api/v1/clusters with a valid kubeconfig
    Then the kubeconfig is stored AES-256-GCM encrypted and the user is bound as admin
    When the same name is posted again
    Then the response is 409 CLUSTER_ALREADY_EXISTS
    When an unparseable kubeconfig is posted
    Then the response is 422 INVALID_KUBECONFIG and nothing is stored
    When a user without a binding lists clusters
    Then the cluster is absent
    When GET /api/v1/clusters/<id>/health is called against a live kind cluster
    Then the response is {"status": "up"}
    When the API server is down
    Then the response is 502 CLUSTER_UNREACHABLE within the probe timeout

  Scenario: list pods for a bound cluster
    When an authenticated, bound user GETs /api/v1/clusters/<id>/resources/pods?namespace=default
    Then the kind cluster's test pod is listed
    When the user's SAR denies list on pods
    Then the response is 403 RBAC_DENIED
    When the kind is unknown
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  Scenario: SPA shell renders cluster pods
    When pnpm build runs in frontend/
    Then the build exits 0 and dist/ contains the hashed assets
    When the SPA is served by Flask
    Then GET / and GET /clusters/123 return index.html (Cache-Control: no-cache)
    Then GET /assets/* is served Cache-Control: immutable
    Then /api/v1/* is never shadowed by the catch-all
    When the Playwright journey runs (login → clusters → pods)
    Then the pod table renders the kind cluster's test pod

  Scenario: chart renders deployment with replica id
    When helm template renders charts/kubedash
    Then the Deployment carries KUBEDASH_REPLICA_ID from fieldRef metadata.name
    Then KUBEDASH_ROLE is "leader" and OIDC env comes from values/secret
    When docker build runs on backend/Dockerfile
    Then the image builds, runs as UID 10001, and /healthz answers in-process

  Scenario: CLI version prints
    When ./kubedash version runs
    Then stdout is "kubedash 0.1.0"
    When ./kubedash get-token runs
    Then the exit code is 2 and stderr points at the kubectl-oidc-plugin blueprint

  Scenario: stub surface matches architecture
    When the file-map test diffs ARCHITECTURE.md §2 paths against the tree
    Then every backend/app/ path exists
    When a stub route (e.g. GET /api/v1/logs/query) is called
    Then the response is 501 NOT_IMPLEMENTED with the stable error shape

  Scenario: CI is green on the base structure
    When .github/workflows/ci.yaml runs on the change branch
    Then backend, frontend, cli, chart, and image jobs pass (incl. Trivy CRITICAL gate)
    When actionlint runs on the workflow YAMLs
    Then there are no findings

  Scenario: test fixtures boot
    When pytest runs the full suite with Docker available
    Then all unit + integration tests pass
    When pytest runs with -m "not integration"
    Then the suite passes without a kind cluster
```

- [ ] **Step 2: Write the root docs**

`README.md` — 5.0 layout tree (from ARCHITECTURE.md §2), per-component
quickstart (backend: `cd backend && uv sync && uv run pytest`; frontend:
`cd frontend && pnpm i && pnpm dev`; cli: `cd cli && make build`; chart:
`helm lint charts/kubedash`), the env-var table from §3.8, and a pointer to
`.skillgrid/ARCHITECTURE.md` + `ASSUMPTIONS.md`. `.gitignore` additions per
the Files list.

- [ ] **Step 3: Run the full verification (L2 floor per Change Classification: standard)**

Run: `cd backend && uv run pytest -v` (full, incl. integration if kind available)
Run: `cd frontend && pnpm test && pnpm exec tsc --noEmit && pnpm lint && pnpm build`
Run: `cd cli && go vet ./... && go test ./... && make build`
Run: `helm lint charts/kubedash && helm template t charts/kubedash > /dev/null`
Run: `docker build -f backend/Dockerfile -t kubedash:base-structure .` (if Docker)
Expected: all green — record any environment-blocked check (no Docker/kind) as a task note, not a silent skip

- [ ] **Step 4: Update state + commit**

```bash
git add .skillgrid/specs/2026-10-17-kubedash-base-structure/acceptance.feature README.md .gitignore .skillgrid/state.yaml
git commit -m "docs(spec): base-structure acceptance scenarios + root README (closes scenarios)

[skillgrid-context]
Change: 2026-10-17-kubedash-base-structure
Task: 12
"
```

---

## Change Classification

`standard` → L2 verification floor (full suite + build). Escalation note:
Task 3 (JWT/OIDC trust boundary) and Task 4 (at-rest encryption) carry
`risky`-class touches; if the final review (per the review escalation
threshold) finds the auth surface grew beyond the spine, escalate the final
review to `skillgrid:parallel-code-review`.

## Critic Resolution Log

Critic subagent verdict **NEEDS FIXES** (20 findings); all resolved inline on
2026-10-17 per the user's "Fix all" choice:

| # | Sev | Resolution |
|---|-----|-----------|
| 1 | CRIT | Task 5 rbac tests rewritten against `rb.can()` with `SimpleNamespace` doubles; `rbac.py` exposes `_sar_allowed` as the patch seam |
| 2 | CRIT | Task 2 `Leader`: per-replica lock key `hashintext(replica_id)`, stale-takeover from `heartbeat_at`, release on `stop()`, `stale_seconds`/`heartbeat_seconds` ctor kwargs, failover test added |
| 3 | CRIT | `rotate_refresh` now DELETES the consumed row; test extracts the real raw token from the login response and asserts the row is gone |
| 4 | CRIT | `/auth/refresh` returns both tokens; `apiFetch` stores the rotated `kd_refresh`; double-rotation test added |
| 5 | HIGH | `bound_cluster_or_404(user, cluster_id)` produced by Task 4's `k8s_client.py`, consumed by name in Task 5 |
| 6 | HIGH | `K8sClient.__init__` sets `_host` (verbatim) + `_verify` (kubeconfig CA); `readyz` URL/CA unit test added |
| 7 | HIGH | JWT delivery contract pinned (`302 → /?token=…&refresh=…` → localStorage); `oidc_authorize_url(state)` threaded; `oidc_state` Redis round-trip + `STATE_MISMATCH` 400 test |
| 8 | HIGH | Both frontend view tests written in full code; export names pinned in Task 8 Interfaces |
| 9 | HIGH | Enqueue mechanism specified (leader-checked scheduler loop in `wsgi.py`); `test_enqueued_job_runs_when_leader` added |
| 10 | HIGH | Blackholed-server bounded-timeout test in Task 4 (accept-never-respond socket, < 8 s assertion) |
| 11 | MED | Task 12 count fixed (1 Feature / 10 scenarios); `state.yaml` added to the commit |
| 12 | MED | kind fixture: session creation + per-test-file delete/recreate (module-scoped boundary fixture); `consecutive_down` column dropped |
| 13 | MED | `gevent` dropped (sync workers, decision recorded in Task 9); chart `gunicorn.*` → env → CMD; `OIDC_CLIENT_ID` asserted in `test_chart.py` |
| 14 | MED | Mechanism note in Task 2 Interfaces (advisory lock = mutex, lease = observable state, §3.7 stale rule, SKIP-LOCKED subsumed); failover test = the §9 "kill leader < 15 s" check |
| 15 | MED | `Settings` gains exactly the two §7.5 keys the spine consumes (`first_paint_backstop`, `namespace_list_timeout`); other four deferred to the ADR-0010 change; chart renders + asserts them |
| 16 | MED | Kind health test moved to Task 5 (fixture home); `issue_token_pair(u2)` moved inside the app context; module-level `pytest.mark.integration` |
| 17 | LOW | Stub exemplar rewritten: real `@blp.route` + `apply_auth(api)` helper (`app/api/_authhook.py`, extracted in Task 6) |
| 18 | LOW | `register_static` idempotency-guarded; static tests use a `static_app` fixture built with `KUBEDASH_STATIC_DIR` before `create_app()` |
| 19 | LOW | File-map `EXPECTED` extended: `app/aggregated/*`, `app/api/kubectl_auth.py`, `app/schemas/kubectl_auth.py`, `app/schemas/__init__.py` |
| 20 | LOW | `oidc_authorize_url` / `oidc_exchange` are real Authlib bodies (mock pair patches exactly those two names); self-review note corrected |

## Self-Review (run by the author)

1. **Spec coverage:** R1→T1, R2→T3, R3→T6/T7/T8, R4→T9, R5→T10/T11, R6→T12/T13, R7→T14, R8→T17, R9→T15/T16, R10→T18. No requirement without a task.
2. **Must-haves coverage:** every requirement maps to ≥1 truth; the 6 artifacts groups cover every Files line; K1–K6 name the cross-task contracts.
3. **One-way-door completeness:** OD-1 (Task 3), OD-2 (Task 4), OD-3 (Task 2), OD-4 (Task 9) — all listed in Must-Haves and tagged on their tasks.
4. **Placeholder scan (post-critic):** no TBD/"implement later"/"similar to Task N"; no `...` bodies remain in the spine code (the `oidc_authorize_url` / `oidc_exchange` ellipses are now real Authlib bodies, monkeypatched at exactly those two names in tests); the only intentional seam-ellipsis is the task-stub pattern in Task 6 (stubs are *defined* by their docstring + 501 surface — the pattern is shown in full for one exemplar of each kind).
5. **Type consistency:** `issue_token_pair(user, expires_in)` consistent across Tasks 3–4; `pool.get(cluster)` signature stable across Tasks 4–5–7; `require_auth` hook name stable across Tasks 3–6; `_jwt_of` helper defined in Task 3's conftest and consumed by Tasks 4–6.

## Execution Handoff

12 tasks → **slicing required** (`skillgrid:slicing` produces `tasks.md`
with waves; the build shape is Tracer thread, so the first wave is
Tasks 1→3→4→5→8, the spine). After slicing, execution options:
**Subagent-Driven (recommended)** — fresh subagent per task with two-stage
review; or **Inline** — `skillgrid:simple-execution` with checkpoints.
Final review: default `skillgrid:requesting-code-review`; escalate to
`skillgrid:parallel-code-review` if the auth/encryption surface (Tasks 3–4)
grows during execution.

**Dependency note for the in-flight change:** `2026-10-17-kubectl-oidc-plugin`
starts its slice after Tasks 1–3 land (it needs `create_app`, the error
contract, and `require_auth` to hang `api/kubectl_auth.py` on).
