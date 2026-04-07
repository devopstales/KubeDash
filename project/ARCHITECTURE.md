# KubeDash — System Architecture

> **Version:** 1.0.0  
> **Last Updated:** 2026-03-29  
> **Status:** Active Development  

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Application Layers](#2-application-layers)
3. [Flask Application Factory](#3-flask-application-factory)
4. [Blueprint Organization](#4-blueprint-organization)
5. [Database Architecture](#5-database-architecture)
6. [Authentication Architecture](#6-authentication-architecture)
7. [Kubernetes Client Architecture](#7-kubernetes-client-architecture)
8. [Real-Time Architecture](#8-real-time-architecture)
9. [Plugin Architecture](#9-plugin-architecture)
10. [Caching Strategy](#10-caching-strategy)
11. [API Architecture](#11-api-architecture)
12. [Frontend Architecture](#12-frontend-architecture)
13. [Multi-Replica Architecture](#13-multi-replica-architecture)
14. [Security Architecture](#14-security-architecture)
15. [Multi-Cluster Architecture](#15-multi-cluster-architecture)
16. [Error Handling](#16-error-handling)

---

## 1. Architecture Overview

KubeDash follows a **layered architecture** with clear separation of concerns. The application is organized into presentation, API, service, and data layers, with cross-cutting concerns handled by dedicated modules.

### High-Level System Diagram

```
                    ┌─────────────────────────────┐
                    │        Load Balancer         │
                    │    (Ingress / Gateway API)   │
                    └──────────┬──────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
    │  KubeDash      │ │  KubeDash    │ │  KubeDash    │
    │  Replica 1     │ │  Replica 2   │ │  Replica N   │
    │  (Flask+WSGI)  │ │  (Flask+WSGI)│ │  (Flask+WSGI)│
    └──┬──────┬──────┘ └──┬──────┬────┘ └──┬──────┬────┘
       │      │           │      │         │      │
       │      └───────────┼──────┼─────────┘      │
       │                  │      │                 │
  ┌────▼──────┐    ┌──────▼──┐  ┌▼─────────┐  ┌───▼────────────┐
  │PostgreSQL │    │  Redis  │  │SocketIO  │  │ Kubernetes     │
  │  Primary  │    │ Cluster │  │ PubSub   │  │ API Server(s)  │
  └───────────┘    └─────────┘  │ (Redis)  │  └────────────────┘
                                └──────────┘
```

### Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Server-side rendering + API | Flask + Jinja2 + flask-smorest | Full-page rendering for initial load, AJAX for dynamic updates. Reduces frontend complexity. |
| Per-user K8s tokens | User-scoped K8s client | Enforces Kubernetes RBAC at the API server level. No permission escalation through KubeDash. |
| Redis for sessions | Flask-Session + Redis | Enables multi-replica deployment with shared session state. |
| Plugin auto-discovery | Directory scanning + entry points | Plugins can be internal or pip-installed packages. |
| Blueprint per domain | Flask Blueprints | Clean separation, independent routing, testable modules. |

---

## 2. Application Layers

```
┌──────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER                                          │
│  ┌─────────────────────┐  ┌────────────────────────────────┐ │
│  │  Views (Jinja2)     │  │  API (flask-smorest)           │ │
│  │  HTML Rendering     │  │  JSON REST + OpenAPI Docs      │ │
│  └─────────┬───────────┘  └──────────┬─────────────────────┘ │
├────────────┼─────────────────────────┼───────────────────────┤
│  SERVICE LAYER                                               │
│  ┌─────────▼─────────────────────────▼─────────────────────┐ │
│  │  Business Logic Services                                │ │
│  │  AuthService | K8sService | UserService | ConfigService │ │
│  └─────────┬───────────────────────────┬───────────────────┘ │
├────────────┼───────────────────────────┼─────────────────────┤
│  DATA LAYER                                                  │
│  ┌─────────▼───────────┐  ┌────────────▼──────────────────┐  │
│  │  SQLAlchemy Models  │  │  Kubernetes API Client        │  │
│  │  Repository Pattern │  │  (per-user token binding)     │  │
│  └─────────┬───────────┘  └────────────┬──────────────────┘  │
│            │                           │                     │
│  ┌─────────▼───────────┐  ┌────────────▼──────────────────┐  │
│  │  PostgreSQL/SQLite  │  │  K8s API Server               │  │
│  └─────────────────────┘  └───────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│  CROSS-CUTTING CONCERNS                                      │
│  Cache (Redis) | Auth Decorators | Error Handling | Logging  │
│  Socket.IO Events | Plugin System                            │
└──────────────────────────────────────────────────────────────┘
```

### Layer Rules

| Rule | Description |
|------|-------------|
| **Views → Services** | Views NEVER access SQLAlchemy models or K8s client directly |
| **API → Services** | API endpoints call services, never repositories |
| **Services → Data** | Services coordinate between repositories and K8s client |
| **No reverse deps** | Lower layers never import from upper layers |
| **Cross-cutting only via decorators/middleware** | Auth, caching, logging applied declaratively |

---

## 3. Flask Application Factory

The application uses the **factory pattern** for testability and multi-instance support.

```python
# kubedash-ui/__init__.py
def create_app(config_name: str = "default") -> Flask:
    """Application factory.
    
    1. Create Flask instance
    2. Load configuration (kubedash.ini → DB → env vars)
    3. Initialize extensions (SQLAlchemy, Migrate, Redis, SocketIO)
    4. Register Blueprints (views + API)
    5. Discover and register plugins
    6. Register error handlers
    7. Register CLI commands
    """
    app = Flask(__name__)
    
    # Config loading order: file → db → env
    app.config.from_object(config[config_name])
    load_ini_config(app, "kubedash.ini")
    
    # Extensions
    init_extensions(app)
    
    # Blueprints
    register_views(app)
    register_api(app)
    
    # Plugins
    discover_and_register_plugins(app)
    
    # Error handlers
    register_error_handlers(app)
    
    return app
```

### Extension Initialization

```python
# kubedash-ui/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from flask_socketio import SocketIO
from flask_smorest import Api
from flask_login import LoginManager

db = SQLAlchemy()
migrate = Migrate()
sess = Session()
socketio = SocketIO()
smorest_api = Api()
login_manager = LoginManager()

def init_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    sess.init_app(app)           # Redis-backed sessions
    socketio.init_app(app, 
        message_queue=app.config["REDIS_URL"],  # Multi-replica pub/sub
        async_mode="eventlet"
    )
    smorest_api.init_app(app)
    login_manager.init_app(app)
```

---

## 4. Blueprint Organization

KubeDash uses two types of Blueprints:

### View Blueprints (HTML — Jinja2)

Responsible for rendering full pages. Registered at root paths.

```python
# kubedash-ui/views/__init__.py
def register_views(app):
    from .auth import auth_bp          # /auth/
    from .dashboard import dashboard_bp # /
    from .workloads import workloads_bp # /workloads/
    from .networking import network_bp  # /networking/
    from .storage import storage_bp     # /storage/
    from .security import security_bp   # /security/
    from .cluster import cluster_bp     # /cluster/
    from .admin import admin_bp         # /admin/
    from .settings import settings_bp   # /settings/
    
    for bp in [auth_bp, dashboard_bp, workloads_bp, network_bp,
               storage_bp, security_bp, cluster_bp, admin_bp, settings_bp]:
        app.register_blueprint(bp)
```

### API Blueprints (JSON — flask-smorest)

Responsible for data operations. All prefixed with `/api/v1/`.

```python
# kubedash-ui/api/__init__.py
def register_api(app):
    from .v1.auth import auth_blp       # /api/v1/auth/
    from .v1.users import users_blp     # /api/v1/users/
    from .v1.namespaces import ns_blp   # /api/v1/namespaces/
    from .v1.workloads import wl_blp    # /api/v1/workloads/
    from .v1.networking import net_blp  # /api/v1/networking/
    from .v1.storage import stor_blp    # /api/v1/storage/
    from .v1.security import sec_blp    # /api/v1/security/
    from .v1.cluster import cl_blp      # /api/v1/cluster/
    from .v1.settings import set_blp    # /api/v1/settings/
    
    for blp in [auth_blp, users_blp, ns_blp, wl_blp, net_blp,
                stor_blp, sec_blp, cl_blp, set_blp]:
        smorest_api.register_blueprint(blp)
```

### Blueprint ↔ Service Mapping

```
View Blueprint ──→ Service ←── API Blueprint
     │                │              │
     │                ▼              │
     │          Business Logic       │
     │                │              │
     ▼                ▼              ▼
  render_template()  K8s/DB    jsonify()
```

Both View and API blueprints call the SAME service layer. No logic duplication.

---

## 5. Database Architecture

### ORM Strategy

- **SQLAlchemy 2.x** with the new-style mapped classes
- **Alembic** (via Flask-Migrate) for schema migrations
- **Repository pattern** for data access abstraction

### Core Models

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│    User      │     │    Role      │     │   Permission     │
├──────────────┤     ├──────────────┤     ├──────────────────┤
│ id           │     │ id           │     │ id               │
│ username     │◄───┐│ name         │◄───┐│ name             │
│ email        │    ││ description  │    ││ resource         │
│ password_hash│    │└──────────────┘    ││ action           │
│ auth_provider│    │     ▲              │└──────────────────┘
│ oidc_token   │    │     │              │        ▲
│ is_active    │    │ ┌───┴──────────┐   │ ┌──────┴───────────┐
│ created_at   │    │ │ user_roles   │   │ │role_permissions  │
└──────────────┘    │ │ (M2M)       │   │ │ (M2M)            │
                    │ ├──────────────┤   │ ├──────────────────┤
                    └─┤ user_id     │   └─┤ role_id          │
                      │ role_id ────┘     │ permission_id ───┘
                      └──────────────┘     └──────────────────┘

┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   ClusterConfig  │    │   AppConfig      │    │   AuditLog       │
├──────────────────┤    ├──────────────────┤    ├──────────────────┤
│ id               │    │ id               │    │ id               │
│ name             │    │ key              │    │ user_id          │
│ api_server_url   │    │ value            │    │ action           │
│ ca_certificate   │    │ section          │    │ resource_type    │
│ auth_mode        │    │ source           │    │ resource_name    │
│ kubeconfig_data  │    │ updated_at       │    │ namespace        │
│ is_default       │    │ updated_by       │    │ details (JSON)   │
│ is_active        │    └──────────────────┘    │ timestamp        │
└──────────────────┘                            └──────────────────┘

┌──────────────────┐    ┌──────────────────┐
│   PluginState    │    │   UserGroup      │
├──────────────────┤    ├──────────────────┤
│ id               │    │ id               │
│ plugin_name      │    │ name             │
│ is_enabled       │    │ description      │
│ config (JSON)    │    │ users (M2M)      │
│ db_tables_created│    │ roles (M2M)      │
│ version          │    └──────────────────┘
└──────────────────┘
```

### Plugin Table Convention

All plugin-created tables use the prefix `plugin_`:

```
plugin_helm_releases
plugin_helm_repositories
plugin_registry_images
plugin_fluxcd_sources
plugin_fluxcd_kustomizations
plugin_cert_certificates
plugin_trivy_reports
plugin_kubecost_allocations
```

### Database Environment Split

```python
# config.py
class DevelopmentConfig:
    SQLALCHEMY_DATABASE_URI = "sqlite:///kubedash.db"
    
class ProductionConfig:
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://kubedash:password@localhost:5432/kubedash"
    )
```

### Migration Strategy

```bash
# Generate migration after model change
flask db migrate -m "Add cluster_config table"

# Apply migrations
flask db upgrade

# Rollback
flask db downgrade
```

---

## 6. Authentication Architecture

KubeDash supports **three authentication modes**: Local, OIDC/SSO, and Combined.

### Authentication Flow

```
                         ┌───────────┐
                         │  Browser  │
                         └─────┬─────┘
                               │
                    ┌──────────▼──────────┐
                    │  Login Page         │
                    │  ┌─────┐ ┌────────┐ │
                    │  │Local│ │SSO/OIDC│ │
                    │  └──┬──┘ └───┬────┘ │
                    └─────┼────────┼──────┘
                          │        │
              ┌───────────▼─┐   ┌──▼───────────────┐
              │ Verify      │   │ Redirect to IdP  │
              │ username +  │   │ (OAuth2 flow)    │
              │ password    │   └──┬───────────────┘
              └──────┬──────┘      │
                     │        ┌────▼───────────────┐
                     │        │ Callback: validate │
                     │        │ id_token, extract  │
                     │        │ user info + groups │
                     │        └────┬───────────────┘
                     │             │
              ┌──────▼─────────────▼──────┐
              │  Create/Update User in DB │
              │  Store session in Redis   │
              │  Store K8s token context  │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────────┐
              │  Redirect to Dashboard    │
              └───────────────────────────┘
```

### K8s Authentication Matrix

| User Type | Auth Source | K8s Token | K8s Permissions |
|-----------|-----------|-----------|-----------------|
| **Admin (local)** | Local password | Service Account / kubeconfig token | Full cluster-admin |
| **SSO User** | OIDC provider | User's OIDC token (passed through) | User's K8s RBAC |
| **Service Account** | Token auth | SA token | SA RBAC |

### Token Isolation

```python
# kubedash-ui/core/k8s_client.py

def get_k8s_client(user: User) -> kubernetes.client.ApiClient:
    """Create a K8s API client scoped to the current user's permissions.
    
    CRITICAL: Each user gets their OWN client instance.
    Admin users use the local kubeconfig/service account.
    SSO users use their OIDC token for K8s API calls.
    """
    if user.role == "admin" and user.auth_provider == "local":
        # Admin: use local kubeconfig or in-cluster SA
        return _create_admin_client()
    elif user.auth_provider == "oidc":
        # SSO user: use their OIDC token
        return _create_oidc_client(user.oidc_token)
    else:
        raise AuthenticationError("No valid K8s credentials")
```

### K8s Connection Mode Detection

```python
def _detect_k8s_mode() -> str:
    """Detect whether we're running in-cluster or out-of-cluster.
    
    Priority:
    1. Explicit config from kubedash.ini
    2. Check for in-cluster SA token (/var/run/secrets/...)
    3. Fall back to kubeconfig
    """
    config_mode = current_app.config.get("K8S_MODE", "auto")
    
    if config_mode == "in-cluster":
        kubernetes.config.load_incluster_config()
        return "in-cluster"
    elif config_mode == "kubeconfig":
        kubernetes.config.load_kube_config(
            config_file=current_app.config.get("KUBECONFIG_PATH")
        )
        return "kubeconfig"
    else:  # auto
        try:
            kubernetes.config.load_incluster_config()
            return "in-cluster"
        except kubernetes.config.ConfigException:
            kubernetes.config.load_kube_config()
            return "kubeconfig"
```

### RBAC Model

```
Admin (built-in)
├── Full cluster access (cluster-admin equivalent)
├── User management
├── Plugin management
└── Settings management

Operator
├── Read/Write workloads in assigned namespaces
├── View cluster resources (read-only)
└── Cannot manage users or settings

Viewer
├── Read-only access to assigned namespaces
└── Cannot exec into pods or view secrets

Custom Roles
├── Configurable permission sets
├── Mapped to K8s RBAC subjects
└── Namespace-scoped or cluster-scoped
```

---

## 7. Kubernetes Client Architecture

### Client Factory Pattern

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│  Request     │─────▶│  K8sClientFactory│─────▶│ Cached      │
│  (with user) │      │                  │      │ K8s Client  │
└─────────────┘      │  Per-user token   │      │ (per user)  │
                     │  Client caching   │      └──────┬──────┘
                     │  Auto-refresh     │             │
                     └──────────────────┘             │
                                                ┌─────▼──────┐
                                                │ K8s API    │
                                                │ Server     │
                                                └────────────┘
```

### K8s Service Layer

```python
# kubedash-ui/services/k8s_service.py

class K8sService:
    """Centralized Kubernetes operations.
    
    Every method receives the user context to ensure
    proper token scoping. NEVER uses a global client.
    """
    
    def list_namespaces(self, user: User) -> list[Namespace]:
        client = get_k8s_client(user)
        v1 = kubernetes.client.CoreV1Api(client)
        return v1.list_namespace().items
    
    def list_pods(self, user: User, namespace: str) -> list[Pod]:
        client = get_k8s_client(user)
        v1 = kubernetes.client.CoreV1Api(client)
        return v1.list_namespaced_pod(namespace).items
    
    def get_pod_logs(self, user: User, namespace: str, 
                     pod: str, container: str, follow: bool = False):
        client = get_k8s_client(user)
        v1 = kubernetes.client.CoreV1Api(client)
        if follow:
            return v1.read_namespaced_pod_log(
                pod, namespace, container=container,
                follow=True, _preload_content=False
            )
        return v1.read_namespaced_pod_log(
            pod, namespace, container=container, tail_lines=1000
        )
    
    def exec_pod(self, user: User, namespace: str,
                 pod: str, container: str, command: list[str]):
        """WebSocket exec into a pod container."""
        client = get_k8s_client(user)
        return stream(
            kubernetes.client.CoreV1Api(client).connect_get_namespaced_pod_exec,
            pod, namespace, container=container,
            command=command, stderr=True, stdin=True,
            stdout=True, tty=True, _preload_content=False
        )
```

---

## 8. Real-Time Architecture

KubeDash uses **Socket.IO** for three real-time features:

### 1. Kubernetes Event Stream

```
K8s Watch API ──▶ Flask Backend ──▶ Socket.IO ──▶ Browser
  (per namespace)    (filter/enrich)   (emit)     (render)
```

### 2. Pod Log Streaming

```
K8s Log API ──▶ Flask Backend ──▶ Socket.IO ──▶ xterm.js
  (follow=true)    (buffer)        (room)      (terminal)
```

### 3. Pod Console (Exec)

```
Browser (xterm.js) ◀──▶ Socket.IO ◀──▶ Flask Backend ◀──▶ K8s Exec API
   stdin/stdout          bidirectional    WebSocket         WebSocket
```

### Socket.IO Rooms Architecture

```python
# kubedash-ui/core/events.py

@socketio.on("join_namespace_events")
def handle_join_events(data):
    """Join a room for namespace-scoped K8s events."""
    namespace = data["namespace"]
    user = current_user
    
    # Verify user has access to this namespace
    if not k8s_service.can_access_namespace(user, namespace):
        emit("error", {"message": "Access denied"})
        return
    
    room = f"events:{namespace}"
    join_room(room)
    
    # Start K8s watch if not already running for this namespace
    start_event_watcher(namespace, room)

@socketio.on("join_pod_logs")
def handle_join_logs(data):
    """Stream logs from a specific pod/container."""
    room = f"logs:{data['namespace']}:{data['pod']}:{data['container']}"
    join_room(room)
    start_log_stream(data, room)

@socketio.on("pod_exec")
def handle_exec(data):
    """Interactive exec session with a pod."""
    room = f"exec:{data['namespace']}:{data['pod']}:{data['container']}"
    join_room(room)
    start_exec_session(data, room)
```

### Multi-Replica Socket.IO

Redis is used as the **message queue** for Socket.IO, enabling events to be broadcast across all replicas:

```
Replica 1 (watcher) ──emit──▶ Redis PubSub ──▶ Replica 2 (client connected)
                                             ──▶ Replica 3 (client connected)
```

Configuration:

```python
socketio = SocketIO(
    message_queue="redis://redis:6379/0",
    async_mode="eventlet"
)
```

---

## 9. Plugin Architecture

### Plugin Lifecycle

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│Discover  │────▶│Register  │────▶│ Activate │────▶│  Ready   │
│(scan dir)│     │(metadata)│     │(create   │     │(serving) │
│          │     │          │     │ tables)  │     │          │
└─────────┘     └──────────┘     └──────────┘     └──────────┘
     │                                                  │
     │  Auto-detected from                              │
     │  kubedash-ui/plugins/ or                       ┌────▼────┐
     │  external packages                          │Deactivate│
     │  via entry_points                           └─────────┘
```

### Base Plugin Contract

```python
# kubedash-ui/plugins/base.py

class BasePlugin(ABC):
    """All plugins MUST extend this class."""
    
    # Plugin metadata
    name: str                    # Unique identifier
    display_name: str            # Human-readable name
    version: str                 # Semantic version
    description: str             # Short description
    
    # Menu integration — ALL plugins appear under the Plugins sidebar menu
    menu_icon: str               # CoreUI icon name
    menu_order: int              # Sort order within Plugins menu
    
    # Table prefix (always: plugin_{name}_)
    @property
    def table_prefix(self) -> str:
        return f"plugin_{self.name}_"
    
    @abstractmethod
    def register(self, app: Flask) -> None:
        """Register blueprints, models, and event handlers."""
        pass
    
    @abstractmethod
    def activate(self, app: Flask) -> None:
        """Create database tables and initialize state."""
        pass
    
    @abstractmethod
    def deactivate(self, app: Flask) -> None:
        """Cleanup. Tables are NOT dropped on deactivation."""
        pass
    
    def get_dashboard_widgets(self) -> list[dict]:
        """Optional: return widget definitions for the main dashboard."""
        return []
    
    def get_resource_overlays(self) -> dict:
        """Optional: return data overlays for existing resource pages.
        
        Example: Kubecost plugin adds cost column to pod/namespace tables.
        """
        return {}
```

### Plugin Discovery

```python
# kubedash-ui/plugins/__init__.py

def discover_plugins(app: Flask) -> list[BasePlugin]:
    """Discover all available plugins.
    
    Sources:
    1. Internal: kubedash-ui/plugins/*/plugin.py
    2. External: pip packages with entry_points group 'kubedash.plugins'
    3. Local: plugins/ directory at project root
    """
    plugins = []
    
    # 1. Internal plugins
    internal_dir = Path(__file__).parent
    for plugin_dir in internal_dir.iterdir():
        if plugin_dir.is_dir() and (plugin_dir / "plugin.py").exists():
            plugins.append(load_plugin_module(plugin_dir / "plugin.py"))
    
    # 2. External entry points
    for ep in importlib.metadata.entry_points(group="kubedash.plugins"):
        plugins.append(ep.load()())
    
    # 3. Local plugin directory
    local_dir = Path(app.root_path).parent / "plugins"
    if local_dir.exists():
        for plugin_dir in local_dir.iterdir():
            if plugin_dir.is_dir() and (plugin_dir / "plugin.py").exists():
                plugins.append(load_plugin_module(plugin_dir / "plugin.py"))
    
    return plugins
```

### Plugin ↔ Menu Integration

All plugins appear exclusively under the **Plugins** sidebar menu:

```python
class CertManagerPlugin(BasePlugin):
    name = "cert_manager"
    menu_icon = "cil-shield-alt"
    menu_order = 50               # Sort order within Plugins menu

class HelmPlugin(BasePlugin):
    name = "helm"
    menu_icon = "cil-layers"
    menu_order = 10
```

### Plugin Database Tables

When a plugin is **activated**, its tables are created with the `plugin_` prefix:

```python
class HelmPlugin(BasePlugin):
    def activate(self, app):
        with app.app_context():
            # Creates: plugin_helm_releases, plugin_helm_repositories
            self.Base.metadata.create_all(db.engine)
            
            # Record activation
            PluginState.query.filter_by(plugin_name=self.name).update({
                "is_enabled": True,
                "db_tables_created": True
            })
            db.session.commit()
```

---

## 10. Caching Strategy

### Cache Layers

```
┌─────────┐     ┌─────────────┐     ┌──────────────────┐
│ Browser  │     │   Redis     │     │ Kubernetes API   │
│ (JS)     │────▶│   Cache     │────▶│ Server           │
│ 5-30s    │     │ 30-300s TTL │     │ (source of truth)│
└─────────┘     └─────────────┘     └──────────────────┘
```

### Cache Key Strategy

```python
# Pattern: kubedash:{resource}:{namespace}:{user_hash}
CACHE_KEYS = {
    "namespaces":   "kubedash:ns:list:{user}",
    "pods":         "kubedash:pods:{ns}:{user}",
    "deployments":  "kubedash:deploy:{ns}:{user}",
    "nodes":        "kubedash:nodes:{user}",
    "events":       "kubedash:events:{ns}:latest50",
    "metrics":      "kubedash:metrics:{ns}:{user}",
}
```

### Cache TTLs

| Resource | TTL | Rationale |
|----------|-----|-----------|
| Namespace list | 60s | Rarely changes |
| Node list/metrics | 30s | Changes with scale events |
| Pod list | 15s | Frequent changes |
| Events | 10s | Near-real-time |
| Deployments | 30s | Moderate change frequency |
| Config values | 300s | Rarely changes at runtime |
| Plugin data | 60s | Plugin-specific |

### Cache Invalidation

```python
# kubedash-ui/core/cache.py

class CacheService:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def get_or_fetch(self, key: str, fetch_fn: Callable, 
                     ttl: int = 60) -> Any:
        """Cache-aside pattern."""
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        
        data = fetch_fn()
        self.redis.setex(key, ttl, json.dumps(data, default=str))
        return data
    
    def invalidate_pattern(self, pattern: str):
        """Invalidate all keys matching pattern.
        
        Used when a write operation occurs (e.g., scale deployment).
        """
        for key in self.redis.scan_iter(match=pattern):
            self.redis.delete(key)
```

---

## 11. API Architecture

### URL Structure

```
/api/v1/                          # API root
├── auth/
│   ├── POST   login              # Local login
│   ├── POST   logout             # Logout
│   ├── GET    oidc/login         # OIDC redirect
│   ├── GET    oidc/callback      # OIDC callback
│   └── GET    me                 # Current user info
├── users/                        # User management
│   ├── GET    /                  # List users
│   ├── POST   /                  # Create user
│   ├── GET    /{id}              # Get user
│   ├── PUT    /{id}              # Update user
│   └── DELETE /{id}              # Delete user
├── groups/                       # Group management
├── namespaces/
│   ├── GET    /                  # List namespaces
│   ├── GET    /{name}            # Get namespace detail
│   ├── POST   /{name}/scale-down # Scale down namespace
│   └── POST   /{name}/scale-up  # Scale up namespace
├── workloads/
│   ├── GET    /pods              # List pods
│   ├── GET    /pods/{ns}/{name}  # Get pod detail
│   ├── GET    /pods/{ns}/{name}/logs    # Get pod logs
│   ├── GET    /deployments       # List deployments
│   ├── PATCH  /deployments/{ns}/{name}  # Update deployment
│   ├── GET    /statefulsets
│   ├── GET    /daemonsets
│   └── GET    /replicasets
├── networking/
│   ├── GET    /services
│   ├── GET    /ingresses
│   ├── GET    /ingress-classes
│   ├── GET    /gateways
│   └── GET    /gateway-classes
├── storage/
│   ├── GET    /persistent-volumes
│   ├── GET    /persistent-volume-claims
│   ├── GET    /storage-classes
│   ├── GET    /volume-snapshots
│   ├── GET    /volume-snapshot-classes
│   └── GET    /configmaps
├── security/
│   ├── GET    /secrets
│   ├── GET    /secrets/{ns}/{name}       # With blurred content
│   ├── POST   /secrets/{ns}/{name}/reveal # Reveal secret
│   ├── GET    /network-policies
│   └── GET    /limit-ranges
├── cluster/
│   ├── GET    /nodes
│   ├── GET    /nodes/{name}
│   ├── GET    /service-accounts
│   ├── GET    /roles
│   ├── GET    /cluster-roles
│   ├── GET    /role-bindings
│   └── GET    /cluster-role-bindings
├── other-resources/
│   ├── GET    /hpas
│   ├── GET    /pod-disruption-budgets
│   ├── GET    /priority-classes
│   ├── GET    /resource-quotas
│   └── GET    /crds
├── settings/
│   ├── GET    /config              # Get app config
│   ├── PUT    /config              # Update app config
│   ├── GET    /plugins             # List plugins
│   ├── PUT    /plugins/{name}      # Enable/disable plugin
│   ├── GET    /auth-providers      # Auth configuration
│   ├── PUT    /auth-providers      # Update auth config
│   ├── GET    /cluster-config      # K8s cluster config
│   ├── PUT    /cluster-config      # Update cluster config
│   └── GET    /kubeconfig/download # Download kubectl config
└── health/
    ├── GET    /live               # Liveness probe
    └── GET    /ready              # Readiness probe
```

### API Response Format

```json
{
  "data": [...],
  "metadata": {
    "total": 150,
    "page": 1,
    "per_page": 50,
    "namespace": "default"
  }
}
```

### Error Response Format

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "User does not have access to namespace 'kube-system'",
    "details": {
      "namespace": "kube-system",
      "required_permission": "get"
    }
  }
}
```

### flask-smorest API Definition

```python
# kubedash-ui/api/v1/workloads.py

from flask_smorest import Blueprint, abort
from kubedash.schemas.workloads import PodSchema, PodListSchema

workloads_blp = Blueprint(
    "workloads", __name__,
    url_prefix="/api/v1/workloads",
    description="Kubernetes workload resources"
)

@workloads_blp.route("/pods")
class PodList(MethodView):
    @workloads_blp.arguments(PaginationSchema, location="query")
    @workloads_blp.response(200, PodListSchema)
    @login_required
    def get(self, pagination):
        """List pods in the selected namespace."""
        namespace = request.args.get("namespace", "default")
        pods = k8s_service.list_pods(current_user, namespace)
        return {"data": pods, "metadata": {...}}
```

---

## 12. Frontend Architecture

### Template Hierarchy

```
templates/
├── base.html                    # HTML head, scripts, global styles
├── layouts/
│   ├── dashboard.html           # CoreUI sidebar + header + content area
│   └── auth.html                # Centered card layout for login
├── partials/
│   ├── navbar.html              # Top navigation bar
│   │   └── namespace_selector   # Namespace dropdown (always visible)
│   ├── sidebar.html             # Left sidebar menu (dynamic)
│   └── footer.html              # Footer with version info
├── components/
│   ├── resource_table.html      # Reusable DataTables table
│   ├── metric_card.html         # Metric display card
│   ├── event_list.html          # Event stream component
│   ├── terminal.html            # xterm.js terminal component
│   ├── yaml_viewer.html         # highlight.js YAML display
│   └── confirm_modal.html       # Action confirmation dialog
└── pages/
    ├── dashboard/
    │   └── index.html           # Main dashboard
    ├── workloads/
    │   ├── pods.html            # Pod list
    │   ├── pod_detail.html      # Pod detail + logs + exec tabs
    │   ├── deployments.html
    │   ├── statefulsets.html
    │   ├── daemonsets.html
    │   └── replicasets.html
    └── ...
```

### JavaScript Data Flow

```
┌──────────────┐     ┌───────────────┐     ┌──────────────────┐
│  Page Load   │────▶│  Jinja2       │────▶│  HTML rendered   │
│  (GET /pods) │     │  renders page │     │  skeleton ready  │
└──────────────┘     └───────────────┘     └────────┬─────────┘
                                                     │
                                              ┌──────▼──────────┐
                                              │  JS: fetch()    │
                                              │  /api/v1/pods   │
                                              └──────┬──────────┘
                                                     │
                                              ┌──────▼──────────┐
                                              │  DataTables      │
                                              │  renders data    │
                                              │  with links      │
                                              └──────┬──────────┘
                                                     │
                                              ┌──────▼──────────┐
                                              │  Socket.IO       │
                                              │  connects for    │
                                              │  real-time       │
                                              └─────────────────┘
```

### Dark Mode Implementation

CoreUI provides built-in dark mode support via:

```html
<!-- base.html -->
<html data-coreui-theme="dark">
```

Theme toggle is stored in `localStorage` and synced via JavaScript:

```javascript
// static/js/theme.js
const theme = localStorage.getItem("kubedash-theme") || "dark";
document.documentElement.setAttribute("data-coreui-theme", theme);
```

### Namespace Selector (Global)

The namespace dropdown appears in the top navbar and affects ALL data views:

```javascript
// static/js/namespace.js
const namespaceSelector = document.getElementById("namespace-select");

namespaceSelector.addEventListener("change", (e) => {
    const ns = e.target.value;
    // Store selection
    sessionStorage.setItem("kubedash-namespace", ns);
    // Reload current page data
    reloadPageData(ns);
    // Update Socket.IO rooms
    socketio.emit("switch_namespace", { namespace: ns });
});
```

---

## 13. Multi-Replica Architecture

### Session Management

```
Browser ──▶ Replica 1 ──▶ Redis (session store)
                              ▲
Browser ──▶ Replica 2 ────────┘
```

All replicas share session state through Redis:

```python
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = redis.Redis.from_url(REDIS_URL)
app.config["SESSION_KEY_PREFIX"] = "kubedash:session:"
```

### Critical: SECRET_KEY

```python
# WRONG: Generates unique key per replica
SECRET_KEY = os.urandom(32)

# CORRECT: Shared key across replicas
SECRET_KEY = os.environ["KUBEDASH_SECRET_KEY"]  # Set in K8s Secret
```

### Socket.IO Across Replicas

Socket.IO uses Redis as a message queue, so events emitted from any replica reach clients connected to any other replica:

```python
socketio = SocketIO(
    message_queue="redis://redis:6379/0",
    channel="kubedash-socketio"
)
```

### Database Connection Pooling

```python
# Production config
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_size": 10,
    "pool_recycle": 300,
    "max_overflow": 20,
    "pool_pre_ping": True,
}
```

---

## 14. Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────┐
│  Layer 1: Transport Security (TLS)          │
│  - HTTPS enforced via Ingress/LB            │
│  - Strict-Transport-Security header         │
├─────────────────────────────────────────────┤
│  Layer 2: Authentication                    │
│  - Session-based (Redis-backed)             │
│  - OIDC token validation                    │
│  - CSRF protection on all POST/PUT/DELETE   │
├─────────────────────────────────────────────┤
│  Layer 3: Authorization                     │
│  - KubeDash RBAC (Role + Permission)        │
│  - K8s RBAC (per-user token)                │
│  - Namespace-scoped access control          │
├─────────────────────────────────────────────┤
│  Layer 4: Data Protection                   │
│  - Secrets blurred by default               │
│  - OIDC tokens encrypted at rest            │
│  - Audit logging for sensitive actions      │
├─────────────────────────────────────────────┤
│  Layer 5: Input Validation                  │
│  - Marshmallow schema validation on all API │
│  - XSS prevention in templates (Jinja2 auto)│
│  - SQL injection prevention (SQLAlchemy)    │
└─────────────────────────────────────────────┘
```

### Audit Logging

All sensitive operations are logged:

```python
# kubedash-ui/core/audit.py

def audit_log(action: str, resource_type: str, 
              resource_name: str, namespace: str = None,
              details: dict = None):
    """Record an audit entry for sensitive operations."""
    log = AuditLog(
        user_id=current_user.id,
        action=action,           # "reveal_secret", "exec_pod", "delete"
        resource_type=resource_type,
        resource_name=resource_name,
        namespace=namespace,
        details=details,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
```

---

## 15. Multi-Cluster Architecture (Optional)

### Cluster Registry

```
┌──────────────┐
│  KubeDash    │
│  Instance    │
└──────┬───────┘
       │
       ├──────────▶ Cluster A (primary)
       ├──────────▶ Cluster B (staging)
       └──────────▶ Cluster C (production)
```

### Design

- `ClusterConfig` model stores multiple cluster connections
- Cluster selector in UI (alongside namespace selector)
- All K8s operations include cluster context
- Federation view: aggregate resources across clusters

```python
# Multi-cluster K8s client
def get_k8s_client(user: User, cluster: ClusterConfig):
    """Create client scoped to user + cluster."""
    configuration = kubernetes.client.Configuration()
    configuration.host = cluster.api_server_url
    configuration.ssl_ca_cert = cluster.ca_cert_path
    
    if user.is_admin:
        configuration.api_key = {"authorization": f"Bearer {cluster.sa_token}"}
    else:
        configuration.api_key = {"authorization": f"Bearer {user.oidc_token}"}
    
    return kubernetes.client.ApiClient(configuration)
```

---

## 16. Error Handling

### Error Handler Registration

```python
# kubedash-ui/core/errors.py

def register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api/"):
            return jsonify(error={"code": "FORBIDDEN", "message": str(e)}), 403
        return render_template("errors/403.html"), 403
    
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify(error={"code": "NOT_FOUND", "message": str(e)}), 404
        return render_template("errors/404.html"), 404
    
    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal server error")
        if request.path.startswith("/api/"):
            return jsonify(error={"code": "INTERNAL_ERROR", "message": "Internal server error"}), 500
        return render_template("errors/500.html"), 500
    
    @app.errorhandler(KubernetesApiException)
    def k8s_error(e):
        """Handle Kubernetes API errors gracefully."""
        status_code = e.status or 500
        if request.path.startswith("/api/"):
            return jsonify(error={
                "code": "K8S_API_ERROR",
                "message": e.reason,
                "details": {"status": e.status}
            }), status_code
        flash(f"Kubernetes error: {e.reason}", "danger")
        return redirect(request.referrer or url_for("dashboard.index"))
```

---

## 17. Observability (OpenTelemetry + Jaeger)

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  KubeDash Application (instrumented with OpenTelemetry)      │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐ │
│  │ Flask WSGI  │  │ SQLAlchemy  │  │  K8s Client          │ │
│  │ middleware  │  │ integration │  │  instrumentation     │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬───────────┘ │
│         └────────────────┼─────────────────────┘             │
│                   ┌──────▼──────┐                            │
│                   │  OTel SDK   │                            │
│                   │  (traces,   │                            │
│                   │   metrics,  │                            │
│                   │   logs)     │                            │
│                   └──────┬──────┘                            │
└──────────────────────────┼───────────────────────────────────┘
                           │ OTLP (gRPC :4317 or HTTP :4318)
                    ┌──────▼──────┐
                    │  Jaeger     │
                    │  Collector  │
                    │  (:4317)    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Jaeger UI  │
                    │  (:16686)   │
                    └─────────────┘
```

### OTel Initialization

```python
# kubedash-ui/core/telemetry.py

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

def init_telemetry(app):
    """Initialize OpenTelemetry tracing, metrics, and auto-instrumentation."""
    if not app.config.get("TELEMETRY_ENABLED", False):
        app.logger.info("Telemetry disabled")
        return
    
    resource = Resource.create({
        SERVICE_NAME: app.config.get("TELEMETRY_SERVICE_NAME", "kubedash"),
        "service.version": app.config.get("VERSION", "1.0.0"),
        "deployment.environment": app.config.get("ENV", "development"),
    })
    
    otlp_endpoint = app.config.get("TELEMETRY_OTLP_ENDPOINT", "http://localhost:4317")
    
    # --- Traces ---
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True))
    )
    trace.set_tracer_provider(tracer_provider)
    
    # --- Metrics ---
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True),
            export_interval_millis=30000,
        )]
    )
    metrics.set_meter_provider(meter_provider)
    
    # --- Auto-instrumentation ---
    FlaskInstrumentor().instrument_app(app)              # HTTP request spans
    SQLAlchemyInstrumentor().instrument(engine=db.engine) # DB query spans
    RequestsInstrumentor().instrument()                   # Outbound HTTP (K8s API)
    RedisInstrumentor().instrument()                      # Redis operations
    
    app.logger.info(f"Telemetry enabled → exporting to {otlp_endpoint}")
```

### Custom Spans

For business-logic-specific tracing:

```python
from opentelemetry import trace

tracer = trace.get_tracer("kubedash.services")

class K8sService:
    def list_pods(self, user, namespace):
        with tracer.start_as_current_span(
            "k8s.list_pods",
            attributes={
                "k8s.namespace": namespace,
                "kubedash.user": user.username,
            }
        ) as span:
            pods = self._fetch_pods(user, namespace)
            span.set_attribute("k8s.pod_count", len(pods))
            return pods
```

### Custom Metrics

```python
meter = metrics.get_meter("kubedash")

# Counters
k8s_api_calls = meter.create_counter(
    "kubedash.k8s_api_calls",
    description="Total K8s API calls made by KubeDash"
)

# Histograms
k8s_api_duration = meter.create_histogram(
    "kubedash.k8s_api_duration",
    description="K8s API call duration in milliseconds",
    unit="ms"
)

# Gauges (via observable)
active_ws_connections = meter.create_observable_gauge(
    "kubedash.active_websocket_connections",
    callbacks=[lambda: get_active_ws_count()],
    description="Number of active WebSocket connections"
)
```

### Jaeger Deployment

```yaml
# deploy/docker/docker-compose.yml (development)
services:
  jaeger:
    image: jaegertracing/all-in-one:1.62
    ports:
      - "16686:16686"   # Jaeger UI
      - "4317:4317"     # OTLP gRPC
      - "4318:4318"     # OTLP HTTP
    environment:
      - COLLECTOR_OTLP_ENABLED=true
```

```yaml
# deploy/helm/kubedash/values.yaml (production)
telemetry:
  enabled: true
  otlpEndpoint: "http://jaeger-collector.observability.svc:4317"
  serviceName: kubedash
```

### What Gets Traced

| Layer | Traces | Attributes |
|-------|--------|------------|
| HTTP requests | Every Flask route | method, path, status, user |
| Database | Every SQLAlchemy query | query type, table, duration |
| K8s API | Every K8s client call | resource, namespace, verb |
| Redis | Every cache/session op | command, key pattern |
| WebSocket | Exec/logs sessions | pod, container, namespace |
| Plugin ops | Plugin-specific | plugin name, operation |

---

## 18. Application Server (Gunicorn)

### Production Server Configuration

KubeDash uses **Gunicorn** with **eventlet** workers to support both HTTP and WebSocket (Socket.IO) in production.

```python
# gunicorn.conf.py

import multiprocessing

# Worker class: eventlet for Socket.IO + WebSocket support
worker_class = "eventlet"

# Workers: 1 per replica (eventlet is single-threaded, async)
# Scale horizontally via K8s replicas instead of multiple workers
workers = 1

# Binding
bind = "0.0.0.0:5000"

# Timeouts
timeout = 120           # Long timeout for WebSocket connections
keepalive = 5
graceful_timeout = 30

# Logging
accesslog = "-"         # stdout
errorlog = "-"          # stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    # Re-seed random for each worker
    import random
    random.seed()
```

### Running

```bash
# Development
flask run --debug

# Production
gunicorn --config gunicorn.conf.py 'kubedash_ui:create_app()'

# Docker
CMD ["gunicorn", "--config", "gunicorn.conf.py", "kubedash:create_app()"]
```

### Why Gunicorn + Eventlet (Not Uvicorn)

| Factor | Gunicorn + Eventlet | Uvicorn |
|--------|--------------------|---------|
| Flask support | Native WSGI | Requires ASGI wrapper |
| Socket.IO | flask-socketio built-in support | Requires additional config |
| Maturity | Battle-tested with Flask | Designed for async frameworks |
| Worker model | Cooperative async (eventlet) | asyncio-based |

**Note:** Each replica runs 1 eventlet worker. Horizontal scaling is done via K8s replicas (2+ recommended). Socket.IO state is shared across replicas via Redis pub/sub.

---

## 19. Logging Architecture

KubeDash uses a **standardized, structured logging format** across all components: Flask application, Gunicorn server, SQLAlchemy, K8s client, and plugins. Logs can be emitted in **text** or **JSON** format (configurable).

### Log Format

**Text format** (human-readable, default for development):

```
2026-03-29 11:30:00.123 | INFO     | kubedash.services.k8s | list_pods | namespace=default user=admin pods_found=42 request_id=abc-123
```

Pattern: `{timestamp} | {level:8} | {logger} | {function} | {key=value pairs}`

**JSON format** (machine-parseable, recommended for production):

```json
{
  "timestamp": "2026-03-29T11:30:00.123Z",
  "level": "INFO",
  "logger": "kubedash.services.k8s",
  "function": "list_pods",
  "message": "Listed pods",
  "request_id": "abc-123",
  "user": "admin",
  "namespace": "default",
  "pods_found": 42,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

### Log Configuration

```python
# kubedash-ui/core/logging.py

import logging
import json
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production environments."""
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "function": record.funcName,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        
        # Add request context if available
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "user"):
            log_entry["user"] = record.user
        
        # Add OpenTelemetry trace context if present
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx.is_valid:
                log_entry["trace_id"] = format(ctx.trace_id, "032x")
                log_entry["span_id"] = format(ctx.span_id, "016x")
        except Exception:
            pass
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord(
                "", 0, "", 0, "", (), None
            ).__dict__ and key not in log_entry:
                log_entry[key] = value
        
        # Exception info
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }
        
        return json.dumps(log_entry, default=str)


class TextFormatter(logging.Formatter):
    """Standardized text formatter for development environments."""
    
    FORMAT = (
        "{asctime}.{msecs:03.0f} | {levelname:8s} | "
        "{name} | {funcName} | {message}"
    )
    
    def __init__(self):
        super().__init__(
            fmt=self.FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S",
            style="{",
        )


def configure_logging(app):
    """Configure standardized logging for all components."""
    log_level = app.config.get("LOG_LEVEL", "INFO").upper()
    log_format = app.config.get("LOG_FORMAT", "text")  # "text" or "json"
    
    # Choose formatter
    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()
    
    # Root handler — all loggers output to stdout
    root_handler = logging.StreamHandler(sys.stdout)
    root_handler.setFormatter(formatter)
    
    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers = [root_handler]
    
    # Standardize all component loggers
    component_loggers = [
        "kubedash",                # Application
        "kubedash.api",            # API endpoints
        "kubedash.views",          # View routes
        "kubedash.services",       # Business logic
        "kubedash.core",           # Core utilities
        "kubedash.plugins",        # Plugin system
        "sqlalchemy.engine",       # Database queries
        "kubernetes",              # K8s client
        "flask_socketio",          # Socket.IO
        "engineio",                # Engine.IO (Socket.IO transport)
    ]
    
    for logger_name in component_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)
        logger.handlers = [root_handler]
        logger.propagate = False
    
    # Reduce noise from overly verbose libraries
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.DEBUG if log_level == "DEBUG" else logging.WARNING
    )
    logging.getLogger("engineio").setLevel(logging.WARNING)
    
    app.logger.info(
        "Logging configured",
        extra={"log_format": log_format, "log_level": log_level}
    )


class RequestContextFilter(logging.Filter):
    """Inject request context into every log record."""
    
    def filter(self, record):
        from flask import has_request_context, request, g
        
        if has_request_context():
            record.request_id = getattr(g, "request_id", "-")
            record.remote_addr = request.remote_addr
            record.method = request.method
            record.path = request.path
            
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                record.user = current_user.username
            else:
                record.user = "anonymous"
        else:
            record.request_id = "-"
            record.user = "system"
        
        return True
```

### Gunicorn Log Integration

Gunicorn uses the **same formatters** as the Flask application:

```python
# gunicorn.conf.py

import logging
from kubedash.core.logging import JSONFormatter, TextFormatter
import os

# ... (existing gunicorn config) ...

# Logging — use same format as application
log_format = os.environ.get("LOG_FORMAT", "text")

if log_format == "json":
    logconfig_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": "kubedash.core.logging.JSONFormatter"},
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {
            "gunicorn.error": {"handlers": ["console"], "level": "INFO"},
            "gunicorn.access": {"handlers": ["console"], "level": "INFO"},
        },
        "root": {"handlers": ["console"], "level": "INFO"},
    }
else:
    # Text format — Gunicorn default with standardized access log format
    accesslog = "-"
    errorlog = "-"
    loglevel = "info"
    access_log_format = (
        '%(t)s | INFO     | gunicorn.access | - | '
        'method=%(m)s path="%(U)s" status=%(s)s '
        'duration=%(D)sμs size=%(B)s remote=%(h)s'
    )
```

### Request ID Propagation

Every request gets a unique ID, propagated through all components:

```python
# kubedash-ui/core/middleware.py

import uuid
from flask import g, request

def init_request_context(app):
    @app.before_request
    def set_request_id():
        # Use incoming X-Request-ID header or generate one
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    
    @app.after_request
    def add_request_id_header(response):
        response.headers["X-Request-ID"] = g.request_id
        return response
```

### Log Output Example (Production — JSON)

All components produce consistent JSON to stdout, collected by the container runtime:

```
{"timestamp":"2026-03-29T11:30:00.100Z","level":"INFO","logger":"gunicorn.access","message":"GET /api/v1/workloads/pods 200","method":"GET","path":"/api/v1/workloads/pods","status":200,"duration":45200,"request_id":"abc-123"}
{"timestamp":"2026-03-29T11:30:00.110Z","level":"INFO","logger":"kubedash.services.k8s","function":"list_pods","message":"Listed pods","request_id":"abc-123","user":"admin","namespace":"default","pods_found":42,"trace_id":"4bf92f3577b34da6"}
{"timestamp":"2026-03-29T11:30:00.120Z","level":"DEBUG","logger":"sqlalchemy.engine","message":"SELECT audit_log ...","request_id":"abc-123","trace_id":"4bf92f3577b34da6"}
```

---

## 20. Audit Logging

### Overview

KubeDash records an audit trail of security-sensitive and operational actions. Audit logs are stored in the database and viewable through the Settings UI (admin only).

### Audit Events

| Category | Events |
|----------|--------|
| **Authentication** | Login (success/failure), logout, SSO callback, token refresh, password reset |
| **User Management** | User created/updated/deleted, role assigned/removed, group membership changed |
| **Secrets** | Secret value revealed (which key, by whom) |
| **Workload Actions** | Deployment scaled, pod deleted, namespace scale up/down |
| **Configuration** | Settings changed, plugin enabled/disabled, auth provider updated |
| **K8s Write Ops** | Any mutating K8s API call (create, update, patch, delete) |

### Database Model

```python
# kubedash-ui/models/audit.py

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), index=True
    )
    
    # Who
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), index=True
    )
    username: Mapped[str] = mapped_column(String(150))
    remote_addr: Mapped[str] = mapped_column(String(45))  # IPv4/IPv6
    
    # What
    action: Mapped[str] = mapped_column(String(50), index=True)
    # e.g.: "auth.login", "secret.reveal", "deployment.scale",
    #        "user.create", "settings.update", "plugin.enable"
    
    category: Mapped[str] = mapped_column(String(30), index=True)
    # e.g.: "authentication", "security", "workload", "config", "user_mgmt"
    
    # Where
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    resource_name: Mapped[Optional[str]] = mapped_column(String(200))
    namespace: Mapped[Optional[str]] = mapped_column(String(100))
    cluster: Mapped[Optional[str]] = mapped_column(String(100))
    
    # Details
    detail: Mapped[Optional[str]] = mapped_column(Text)  # JSON with extra context
    status: Mapped[str] = mapped_column(String(10))       # "success" | "failure"
    
    # Request context
    request_id: Mapped[Optional[str]] = mapped_column(String(36))
    http_method: Mapped[Optional[str]] = mapped_column(String(10))
    http_path: Mapped[Optional[str]] = mapped_column(String(500))
```

### Audit Service

```python
# kubedash-ui/services/audit_service.py

from kubedash.models.audit import AuditLog
from flask import request, g
from flask_login import current_user

class AuditService:
    """Centralized audit logging. Used by all services and decorators."""
    
    @staticmethod
    def log(action: str, category: str, status: str = "success",
            resource_type: str = None, resource_name: str = None,
            namespace: str = None, detail: dict = None):
        """Record an audit event."""
        entry = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            username=current_user.username if current_user.is_authenticated else "anonymous",
            remote_addr=request.remote_addr if request else "internal",
            action=action,
            category=category,
            resource_type=resource_type,
            resource_name=resource_name,
            namespace=namespace,
            detail=json.dumps(detail) if detail else None,
            status=status,
            request_id=getattr(g, "request_id", None),
            http_method=request.method if request else None,
            http_path=request.path if request else None,
        )
        db.session.add(entry)
        db.session.commit()
        
        # Also emit to application logger for log aggregation
        logger.info(
            f"AUDIT: {action}",
            extra={
                "audit": True,
                "audit_action": action,
                "audit_category": category,
                "audit_status": status,
                "audit_resource": f"{resource_type}/{resource_name}" if resource_type else None,
            }
        )
    
    @staticmethod
    def query(page=1, per_page=50, user_id=None, action=None, 
              category=None, date_from=None, date_to=None):
        """Query audit logs with filters."""
        q = AuditLog.query.order_by(AuditLog.timestamp.desc())
        
        if user_id:
            q = q.filter(AuditLog.user_id == user_id)
        if action:
            q = q.filter(AuditLog.action.like(f"%{action}%"))
        if category:
            q = q.filter(AuditLog.category == category)
        if date_from:
            q = q.filter(AuditLog.timestamp >= date_from)
        if date_to:
            q = q.filter(AuditLog.timestamp <= date_to)
        
        return q.paginate(page=page, per_page=per_page)


# Decorator for easy audit logging on endpoints
def audit_logged(action: str, category: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                AuditService.log(action, category, status="success")
                return result
            except Exception as e:
                AuditService.log(action, category, status="failure",
                                detail={"error": str(e)})
                raise
        return wrapper
    return decorator
```

### Usage Examples

```python
# Secret reveal — manual audit call
@security_blp.route("/secrets/<ns>/<name>/reveal")
class SecretReveal(MethodView):
    @login_required
    def post(self, ns, name):
        data = security_service.reveal_secret(current_user, ns, name)
        AuditService.log(
            action="secret.reveal",
            category="security",
            resource_type="Secret",
            resource_name=name,
            namespace=ns,
            detail={"keys_revealed": list(data.keys())}
        )
        return data

# Login — audit on success/failure
@auth_blp.route("/login")
class Login(MethodView):
    def post(self):
        user = auth_service.authenticate(username, password)
        if user:
            AuditService.log("auth.login", "authentication", status="success")
        else:
            AuditService.log("auth.login", "authentication", status="failure",
                           detail={"username": username})

# Settings — decorator approach
@settings_blp.route("/config")
class ConfigUpdate(MethodView):
    @login_required
    @admin_required
    @audit_logged("settings.update", "config")
    def put(self):
        config_service.update_config(request.json)
        return {"message": "Configuration updated"}
```

### Audit Log Retention

```python
# Configurable retention via kubedash.ini
[audit]
retention_days = 90
max_records = 1000000

# Cleanup task (Celery or scheduled)
def cleanup_old_audit_logs():
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
    db.session.commit()
```

### Admin UI — Audit Log Viewer

Located under **Settings → Audit Logs** (admin-only):

```
┌──────────────────────────────────────────────────────────────┐
│ Settings > Audit Logs                           [Export CSV]  │
├──────────────────────────────────────────────────────────────┤
│ Filters:                                                      │
│ [User ▾] [Category ▾] [Action ________] [From ___] [To ___] │
├──────────────────────────────────────────────────────────────┤
│ DataTable                                                     │
│ ┌──────────┬────────┬──────────┬──────────┬────────┬───────┐ │
│ │ Timestamp│ User   │ Action   │ Resource │ Status │ Detail│ │
│ ├──────────┼────────┼──────────┼──────────┼────────┼───────┤ │
│ │ 11:30:00 │ admin  │ secret   │ Secret/  │ ✅     │ [👁]  │ │
│ │          │        │ .reveal  │ db-pass  │        │       │ │
│ │ 11:29:50 │ jdoe   │ auth     │ —        │ ✅     │ [👁]  │ │
│ │          │        │ .login   │          │        │       │ │
│ │ 11:29:30 │ admin  │ deploy   │ Deploy/  │ ✅     │ [👁]  │ │
│ │          │        │ .scale   │ nginx    │        │       │ │
│ └──────────┴────────┴──────────┴──────────┴────────┴───────┘ │
│ Showing 1-50 of 12,345           [< 1 2 3 ... >]             │
└──────────────────────────────────────────────────────────────┘
```

---

## 21. Automated Testing Strategy

### 21.1 Toolchain

- **Test Runner:** `pytest`
- **Coverage:** `pytest-cov`
- **Linting & Formatting:** `ruff`
- **Type Checking:** `mypy`
- **Security Analysis:** `bandit`
- **Mocking:** `unittest.mock`, `responses`, `factory-boy`

### 21.2 Test Pyramid

KubeDash enforces a strict separation of test types:

1. **Unit Tests (`tests/unit/`)**: Fast, no external network, no real database. 
   - Flask app is mocked or scoped.
   - Kubernetes Python client is entirely patched.
2. **Integration Tests (`tests/integration/`)**: Tests database interactions and Flask route behavior.
   - Uses a real SQLite in-memory database or test PostgreSQL.
   - Uses `FlaskClient` to simulate HTTP requests.
   - Kubernetes calls are still mocked with realistic JSON payloads.
3. **End-to-End Tests (`tests/e2e/`)**: Full stack test against a live local cluster (`kind` or `minikube`).

### 21.3 CI Pipeline Checks

Every PR must pass the following checks:
1. `ruff format --check`
2. `ruff check`
3. `mypy kubedash-ui/`
4. `bandit -c bandit.yaml -r kubedash-ui/`
5. `pytest --cov=kubedash-ui/ --cov-fail-under=80`

---

## Appendix A: Technology Decision Records

### ADR-001: Server-Side Rendering over SPA

**Decision:** Use Flask + Jinja2 for page rendering, with JavaScript for dynamic data updates.

**Rationale:**
- Reduces frontend complexity (no React/Vue build pipeline)
- CoreUI provides pre-built dashboard components
- JavaScript `fetch()` + DataTables handles dynamic content
- SEO not a concern (internal tool)
- Faster initial development cycle

**Trade-off:** Less interactivity than a full SPA, but acceptable for a dashboard tool.

### ADR-002: Per-User K8s Tokens

**Decision:** Every K8s API call uses the authenticated user's token, not a shared service account.

**Rationale:**
- Kubernetes RBAC is enforced at the API server level
- No permission escalation through KubeDash
- Audit trail at K8s level
- SSO users' K8s permissions match their IdP grants

**Trade-off:** More complex client management, but critical for enterprise security.

### ADR-003: Redis for Multi-Replica Support

**Decision:** Use Redis for sessions, cache, and Socket.IO pub/sub.

**Rationale:**
- Single dependency for three cross-replica needs
- Well-supported by Flask ecosystem (Flask-Session, Flask-Caching, Flask-SocketIO)
- Low latency for real-time features

---

## Appendix B: Dependency Map

```
Flask Application
├── flask >= 3.0
├── flask-sqlalchemy >= 3.1
├── flask-migrate >= 4.0
├── flask-smorest >= 0.45
├── flask-session >= 0.8
├── flask-socketio >= 5.4
├── flask-login >= 0.6
├── marshmallow >= 3.20
├── SQLAlchemy >= 2.0
├── kubernetes >= 31.0
├── redis >= 5.0
├── python-dotenv >= 1.0
├── eventlet >= 0.36
├── authlib >= 1.3              (OIDC client)
├── cryptography >= 42           (token encryption)
├── psycopg2-binary >= 2.9       (PostgreSQL driver)
├── gunicorn >= 23               (WSGI server)
├── opentelemetry-api >= 1.27    (OTel API)
├── opentelemetry-sdk >= 1.27    (OTel SDK)
├── opentelemetry-exporter-otlp >= 1.27  (OTLP exporter)
├── opentelemetry-instrumentation-flask >= 0.48  (Flask auto-instrumentation)
├── opentelemetry-instrumentation-sqlalchemy >= 0.48
├── opentelemetry-instrumentation-requests >= 0.48
└── opentelemetry-instrumentation-redis >= 0.48

Dev Dependencies
├── pytest >= 8.0
├── pytest-cov >= 5.0
├── pytest-flask >= 1.3
├── ruff >= 0.6
├── mypy >= 1.11
├── bandit >= 1.7
└── factory-boy >= 3.3
```
