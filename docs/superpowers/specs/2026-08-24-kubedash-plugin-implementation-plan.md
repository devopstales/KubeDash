# KubeDash v5 Plugin Implementation Plan

## Goal
Port all v4 plugins to the v5 architecture, preserving functionality while adapting to the new monorepo layout, Flask-Smorest API patterns, plugin registry, and modern stack.

---

## Plugin Inventory from v4

| # | Plugin | Purpose | v4 Path |
|---|--------|---------|---------|
| 1 | ai_chat | In-app AI chatbot for K8s queries | `plugins/ai_chat/` |
| 2 | application_catalog | Embedded external apps with iframe proxy | `plugins/application_catalog/` |
| 3 | cert_manager | cert-manager CRDs (Issuer, Certificate, etc.) | `plugins/cert_manager/` |
| 4 | external_loadbalancer | MetalLB/Cilium LB resources | `plugins/external_loadbalancer/` |
| 5 | flux | FluxCD GitOps objects + graph | `plugins/flux/` |
| 6 | gateway_api | Kubernetes Gateway API resources | `plugins/gateway_api/` |
| 7 | helm | Helm chart/release browser | `plugins/helm/` |
| 8 | iframe_proxy | Reverse proxy for embedded apps | `plugins/iframe_proxy/` |
| 9 | registry | OCI registry management | `plugins/registry/` |
| 10 | trivy_operator | Trivy security reports | `plugins/trivy_operator/` |

---

## v5 Plugin Architecture

### Directory Layout

```
kubedash/kubedash/
├── plugins/
│   ├── __init__.py              # PluginRegistry, discovery, registration
│   ├── ai_chat/
│   │   ├── __init__.py          # Blueprint + page routes
│   │   ├── api.py               # Flask-Smorest REST API
│   │   ├── model.py             # SQLAlchemy models
│   │   ├── schemas.py           # Marshmallow schemas (v5 addition)
│   │   ├── services.py          # Business logic (renamed from functions.py)
│   │   ├── intent_parser.py     # NL intent parsing
│   │   ├── provider_registry.py # LLM provider registry
│   │   ├── k8s_adapter.py       # K8s operations for chat
│   │   ├── llm_provider.py      # Base LLM provider
│   │   ├── minimal_provider.py  # Pattern-based fallback
│   │   ├── diagnostics.py       # Health checks
│   │   └── templates/           # Jinja2 templates
│   ├── application_catalog/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py
│   │   ├── schemas.py
│   │   ├── services.py
│   │   ├── helpers.py
│   │   └── templates/
│   ├── cert_manager/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py            # Empty — no persistent state
│   │   ├── schemas.py
│   │   ├── services.py
│   │   └── templates/
│   ├── external_loadbalancer/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py            # Empty — no persistent state
│   │   ├── schemas.py
│   │   ├── services.py
│   │   └── templates/
│   ├── flux/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py            # Empty — no persistent state
│   │   ├── schemas.py
│   │   ├── services.py
│   │   ├── graph.py            # Cytoscape graph builder
│   │   ├── details.py          # Object detail parsing
│   │   ├── actions.py          # Suspend/Resume/Sync
│   │   ├── helm_releases.py
│   │   ├── kustomizations.py
│   │   ├── notifications.py
│   │   ├── sources.py
│   │   ├── websocket.py        # SocketIO handlers
│   │   └── templates/
│   ├── gateway_api/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py            # Empty — no persistent state
│   │   ├── schemas.py
│   │   ├── services.py
│   │   └── templates/
│   ├── helm/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py            # Empty — no persistent state
│   │   ├── schemas.py
│   │   ├── services.py
│   │   └── templates/
│   ├── iframe_proxy/
│   │   ├── __init__.py          # Blueprint only — no UI page
│   │   └── services.py          # Proxy logic
│   ├── registry/
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── model.py
│   │   ├── schemas.py
│   │   ├── services.py
│   │   └── templates/
│   └── trivy_operator/
│       ├── __init__.py
│       ├── api.py
│       ├── model.py            # Empty — no persistent state
│       ├── schemas.py
│       ├── services.py
│       └── templates/
```

---

## Plugin Registry Design (v5)

### Core Registry (`plugins/__init__.py`)

```python
class PluginRegistry:
    """Startup-time plugin discovery and registration."""

    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.plugins = {}
        self.blueprints = {}
        self.api_blueprints = {}

    def discover(self, plugins_dir, enabled_names):
        """Scan plugins/ for __init__.py, filter by enabled_names."""
        ...

    def register(self, plugin_name):
        """Import plugin module, register blueprint + API blueprints, create tables."""
        ...

    def register_all(self):
        """Register all enabled plugins."""
        ...

    def get_blueprint(self, plugin_name):
        """Return plugin's UI blueprint for sidebar nav."""
        ...
```

### Registration Flow

1. App factory reads `[plugins]` from `kubedash.ini`
2. `PluginRegistry.discover()` scans `plugins/` directory
3. For each enabled plugin, `register()`:
   - Imports `plugins.<name>`
   - Registers UI blueprint under `/plugins/<name>`
   - Registers API blueprint under `/api/v1/plugins/<name>`
   - Calls `db.create_all()` if plugin has `model.py`
4. Plugin blueprints available for sidebar navigation injection

---

## Per-Plugin Implementation Plan

### 1. ai_chat (Phase 2)

**v4 → v5 changes:**
- Move from `plugins.ai_chat` to `kubedash.plugins.ai_chat`
- API blueprints registered under `/api/v1/plugins/ai-chat/` instead of `/ai-chat/`
- Add Marshmallow schemas for request/response validation
- Use `lib.sso.get_user_token()` instead of direct session access
- Conversations stored in PostgreSQL via Flask-SQLAlchemy
- WebSocket streaming via Flask-SocketIO (already in v5 stack)
- Schemas: `ChatMessageSchema`, `ConversationSchema`, `ProviderInfoSchema`

**Files to create:** 12 files (mirror v4 structure + schemas.py)
**Dependencies:** `asyncio` (stdlib), Flask-SocketIO (already in v5)

---

### 2. application_catalog (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.application_catalog`
- APIs under `/api/v1/plugins/application-catalog/`
- Add Marshmallow schemas: `ApplicationSchema`, `ApplicationCreateSchema`
- CSP update logic moved to `services.py`
- `iframe_proxy` dependency: proxy logic extracted to shared utility or kept as sub-module

**Files to create:** 7 files
**DB table:** `application_catalog` (unchanged from v4)

---

### 3. cert_manager (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.cert_manager`
- APIs under `/api/v1/plugins/cert-manager/`
- Add schemas: `IssuerSchema`, `ClusterIssuerSchema`, `CertificateSchema`, `CertificateRequestSchema`
- K8s client calls go through `lib.k8s` wrappers
- No DB models (read-only CRD viewer)

**Files to create:** 6 files
**DB table:** None

---

### 4. external_loadbalancer (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.external_loadbalancer`
- APIs under `/api/v1/plugins/external-loadbalancer/`
- Add schemas: `IPAddressPoolSchema`, `L2AdvertisementSchema`, `BGPAdvertisementSchema`, `BGPPeerSchema`
- Supports MetalLB + Cilium

**Files to create:** 6 files
**DB table:** None

---

### 5. flux (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.flux`
- APIs under `/api/v1/plugins/flux/`
- Add schemas: `FluxObjectSchema`, `GraphSchema`, `SummarySchema`
- WebSocket handlers in `websocket.py` using Flask-SocketIO
- Graph builder (`graph.py`) produces Cytoscape.js JSON
- Actions (Suspend/Resume/Sync) as PATCH endpoints

**Files to create:** 11 files
**DB table:** None

---

### 6. gateway_api (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.gateway_api`
- APIs under `/api/v1/plugins/gateway-api/`
- Add schemas: `GatewayClassSchema`, `GatewaySchema`, `HTTPRouteSchema`, `GRPCRouteSchema`, `TCPRouteSchema`, `TLSRouteSchema`, `ReferenceGrantSchema`, `BackendTLSPolicySchema`
- 8+ resource types, all read-only CRD viewers

**Files to create:** 6 files
**DB table:** None

---

### 7. helm (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.helm`
- APIs under `/api/v1/plugins/helm/`
- Add schemas: `HelmChartSchema`, `HelmReleaseSchema`
- Read-only release browser

**Files to create:** 6 files
**DB table:** None

---

### 8. iframe_proxy (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.iframe_proxy`
- No UI page route (proxy only)
- Services module contains all proxy logic from v4 `__init__.py`
- Registered as utility blueprint, not shown in sidebar

**Files to create:** 2 files
**DB table:** None

---

### 9. registry (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.registry`
- APIs under `/api/v1/plugins/registry/`
- Add schemas: `RegistryServerSchema`, `RegistryImageSchema`, `RegistryTagSchema`, `RegistryEventSchema`
- Auth tokens stored base64-encoded (same as v4)
- Webhook endpoint for registry events

**Files to create:** 7 files
**DB tables:** `registry`, `registry_events`

---

### 10. trivy_operator (Phase 2)

**v4 → v5 changes:**
- Move to `kubedash.plugins.trivy_operator`
- APIs under `/api/v1/plugins/trivy-operator/`
- Add schemas for all 10+ report types
- Cluster-scoped + namespace-scoped report variants
- Events attached to detail views

**Files to create:** 6 files
**DB table:** None

---

## Common v5 Plugin Pattern

Every plugin follows this structure:

### `__init__.py`
```python
from flask import Blueprint, render_template, request, session
from flask_login import login_required
from lib.helper_functions import get_logger
from lib.sso import get_user_token

plugin_bp = Blueprint("plugin_name", __name__, url_prefix="/plugins", template_folder="templates")
logger = get_logger()

@plugin_bp.route("/plugin-name", methods=["GET", "POST"])
@login_required
def plugin_page():
    user_token = get_user_token(session)
    # ... render template with namespaces, etc.
    return render_template("plugin_page.html", ...)
```

### `api.py`
```python
from flask_smorest import Blueprint
from lib.helper_functions import get_logger

plugin_api_bp = Blueprint("plugin_api", "plugin_api", url_prefix="/plugin-name", description="...")

@plugin_api_bp.route("/resources")
class ResourcesList(MethodView):
    @login_required
    def get(self):
        # ... return jsonify({"data": ...})
        pass
```

### `schemas.py` (v5 addition)
```python
from flask_smorest import MarshmallowSchema
from marshmallow import fields

class ResourceSchema(MarshmallowSchema):
    class Meta:
        type_ = "resource"
        strict = True
    name = fields.Str()
    namespace = fields.Str()
    # ...
```

### `services.py` (renamed from functions.py)
```python
def resource_get(user_role, user_token, namespace):
    """Fetch resources from K8s API."""
    ...
```

### `model.py`
```python
from lib.components import db

class PluginModel(db.Model):
    __tablename__ = "plugin_table"
    id = db.Column(db.Integer, primary_key=True)
    # ...
```

---

## Configuration (`kubedash.ini`)

```ini
[plugins]
enabled = ai_chat, application_catalog, cert_manager, external_loadbalancer, flux, gateway_api, helm, iframe_proxy, registry, trivy_operator

[ai_chat]
read_only = false
llm_base_url = http://localhost:11434/v1
llm_model = llama3

[registry]
# Registry-specific config if needed
```

---

## Implementation Order

| Phase | Plugins | Rationale |
|-------|---------|-----------|
| Phase 1 | None | Core dashboard only |
| Phase 2 | cert_manager, external_loadbalancer, gateway_api, helm, trivy_operator | Read-only CRD viewers, no extra dependencies |
| Phase 2 | flux | GitOps detection + graph (requires WebSocket) |
| Phase 2 | registry, application_catalog, iframe_proxy | Stateful plugins with DB tables |
| Phase 2 | ai_chat | Requires LLM provider, SocketIO streaming |

---

## Testing Strategy

Each plugin gets:
- `tests/unit/test_<plugin>_services.py` — service logic with mocked K8s client
- `tests/unit/test_<plugin>_api.py` — API endpoints with Flask test client
- `tests/unit/test_<plugin>_models.py` — DB models (if applicable)
- Mock strategy: `responses` library for K8s API, SQLite in-memory for DB

---

## Dependencies Added in Phase 2

| Dependency | Purpose |
|------------|---------|
| requests-oauthlib | OIDC flow |
| Authlib | OIDC client |
| Flask-SocketIO | Real-time GitOps and AI chat |
| requests | iframe_proxy HTTP forwarding |
| cytoscape.js (frontend) | Flux graph visualization |
