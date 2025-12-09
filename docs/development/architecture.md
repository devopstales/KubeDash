# KubeDash Architecture

This document provides a comprehensive overview of the KubeDash architecture from a software architect's perspective. It covers the system design, component interactions, data flows, and key architectural decisions.

## Table of Contents

- [System Overview](#system-overview)
- [High-Level Architecture](#high-level-architecture)
- [Component Architecture](#component-architecture)
- [Data Flow Architecture](#data-flow-architecture)
- [Database Schema](#database-schema)
- [Plugin System Architecture](#plugin-system-architecture)
- [Security Architecture](#security-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Technology Stack](#technology-stack)

---

## System Overview

KubeDash is a Python-based web application built on Flask that provides a comprehensive dashboard for Kubernetes cluster management. It follows a modular architecture with blueprints for different functional areas and a plugin system for extensibility.

### Key Architectural Principles

1. **Modularity**: Blueprint-based separation of concerns
2. **Extensibility**: Dynamic plugin loading system
3. **Security-First**: Multi-layer authentication and authorization
4. **Observability**: Integrated OpenTelemetry tracing
5. **Scalability**: Redis-based caching and session management

---

## High-Level Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WB[Web Browser]
        KC[Kubectl Client]
        API[API Clients]
    end
    
    subgraph "KubeDash Application"
        subgraph "Web Layer"
            FLASK[Flask Application]
            WSGI[Gunicorn WSGI Server]
            SOCKET[SocketIO WebSocket]
        end
        
        subgraph "Blueprint Layer"
            AUTH[Auth Blueprint]
            DASH[Dashboard Blueprint]
            WORK[Workload Blueprint]
            NET[Network Blueprint]
            STORE[Storage Blueprint]
            SEC[Security Blueprint]
            CLUST[Cluster Blueprint]
            EXTAPI[Extension API Blueprint]
        end
        
        subgraph "Core Services"
            K8SLIB[Kubernetes Library]
            CACHE[Cache Service]
            OTEL[OpenTelemetry]
            PLUGINS[Plugin Manager]
        end
        
        subgraph "Data Layer"
            ORM[SQLAlchemy ORM]
            MODELS[Data Models]
        end
    end
    
    subgraph "External Services"
        K8S[Kubernetes API Server]
        OIDC[OIDC Provider]
        REDIS[(Redis Cache)]
        DB[(PostgreSQL/SQLite)]
        JAEGER[Jaeger Tracing]
    end
    
    WB --> WSGI
    KC --> EXTAPI
    API --> FLASK
    
    WSGI --> FLASK
    FLASK --> AUTH
    FLASK --> DASH
    FLASK --> WORK
    FLASK --> NET
    FLASK --> STORE
    FLASK --> SEC
    FLASK --> CLUST
    FLASK --> EXTAPI
    
    AUTH --> K8SLIB
    DASH --> K8SLIB
    WORK --> K8SLIB
    WORK --> SOCKET
    
    K8SLIB --> K8S
    AUTH --> OIDC
    CACHE --> REDIS
    ORM --> DB
    OTEL --> JAEGER
```

---

## Component Architecture

### Application Initialization Flow

```mermaid
sequenceDiagram
    participant Main as kubedash.py
    participant Init as Initializers
    participant Config as Configuration
    participant DB as Database
    participant Plugins as Plugin Manager
    participant BP as Blueprints
    participant Security as Security Layer
    
    Main->>Init: create_app()
    Init->>Config: initialize_app_configuration()
    Config-->>Init: Config loaded
    
    Init->>Init: initialize_app_logging()
    Init->>Init: initialize_app_tracing()
    Init->>Init: initialize_app_version()
    
    Init->>Plugins: initialize_app_plugins()
    Plugins-->>Init: Plugins registered
    
    Init->>DB: initialize_app_database()
    DB->>DB: Run migrations
    DB->>DB: Create tables
    DB-->>Init: Database ready
    
    Init->>Init: initialize_app_caching()
    Init->>Init: initialize_metrics_scraper()
    Init->>Init: initialize_app_socket()
    
    Init->>BP: initialize_blueprints()
    BP-->>Init: Blueprints registered
    
    Init->>Security: initialize_app_security()
    Security->>Security: Configure CSP
    Security->>Security: Configure CORS
    Security->>Security: Setup Login Manager
    Security-->>Init: Security configured
    
    Init-->>Main: Flask app ready
```

### Blueprint Component Structure

```mermaid
graph LR
    subgraph "Core Blueprints"
        API["/api<br/>API Blueprint"]
        AUTH["/<br/>Auth Blueprint"]
        DASH["/dashboard<br/>Dashboard Blueprint"]
        METRICS["/metrics<br/>Metrics Blueprint"]
    end
    
    subgraph "Resource Blueprints"
        WORK["/workload<br/>Workload Blueprint"]
        NET["/network<br/>Network Blueprint"]
        STORE["/storage<br/>Storage Blueprint"]
        SEC["/security<br/>Security Blueprint"]
        CLUST["/cluster<br/>Cluster Blueprint"]
        PERM["/cluster-permissions<br/>Permissions Blueprint"]
        OTHER["/other<br/>Other Resources"]
    end
    
    subgraph "Management Blueprints"
        USER["/user<br/>User Blueprint"]
        SETTINGS["/settings<br/>Settings Blueprint"]
        HISTORY["/history<br/>History Blueprint"]
    end
    
    subgraph "Extension Blueprints"
        EXTAPI["/apis<br/>Extension API"]
        EXTROOT["/<br/>Extension Root"]
    end
    
    subgraph "Plugin Blueprints"
        HELM["/plugins/helm<br/>Helm Plugin"]
        REG["/plugins/registry<br/>Registry Plugin"]
        CERT["/plugins/cert-manager<br/>Cert Manager Plugin"]
        LB["/plugins/loadbalancer<br/>LoadBalancer Plugin"]
        FLUX["/plugins/flux<br/>Flux Plugin"]
    end
```

---

## Data Flow Architecture

### Authentication Flow

```mermaid
sequenceDiagram
    participant User as User Browser
    participant Auth as Auth Blueprint
    participant SSO as SSO Service
    participant OIDC as OIDC Provider
    participant DB as Database
    participant K8S as Kubernetes API
    
    User->>Auth: GET /
    Auth->>SSO: Check SSO configuration
    SSO->>DB: Query SSOServer
    DB-->>SSO: SSO Config
    
    alt SSO Enabled
        SSO->>OIDC: Get authorization URL
        OIDC-->>SSO: Authorization URL
        Auth-->>User: Render login with SSO button
        
        User->>OIDC: Click SSO Login
        OIDC-->>User: Authenticate
        User->>Auth: Callback with code
        Auth->>OIDC: Exchange code for tokens
        OIDC-->>Auth: Access & ID tokens
        Auth->>DB: Create/Update user
        Auth->>User: Redirect to dashboard
    else Local Auth
        User->>Auth: POST / (credentials)
        Auth->>DB: Verify credentials
        DB-->>Auth: User + Role
        Auth->>User: Set session, redirect
    end
```

### Kubernetes API Interaction Flow

```mermaid
sequenceDiagram
    participant BP as Blueprint Route
    participant K8SLib as K8S Library
    participant Cache as Cache Layer
    participant Config as K8S Config
    participant K8S as Kubernetes API
    
    BP->>K8SLib: Request resource (role, token)
    K8SLib->>Cache: Check cache
    
    alt Cache Hit
        Cache-->>K8SLib: Cached data
        K8SLib-->>BP: Return data
    else Cache Miss
        K8SLib->>Config: k8sClientConfigGet(role, token)
        
        alt Admin Role
            Config->>Config: Load local/incluster config
        else User Role
            Config->>Config: Load OIDC token config
        end
        
        Config-->>K8SLib: Client configured
        K8SLib->>K8S: API request
        K8S-->>K8SLib: Response
        K8SLib->>Cache: Store in cache
        K8SLib-->>BP: Return data
    end
```

### Real-time Log Streaming Flow

```mermaid
sequenceDiagram
    participant Browser as Browser
    participant SocketIO as SocketIO Server
    participant Workload as Workload Blueprint
    participant K8S as Kubernetes API
    
    Browser->>SocketIO: Connect /log namespace
    SocketIO-->>Browser: Connected
    
    Browser->>SocketIO: message(pod_name, container)
    SocketIO->>Workload: Start background task
    Workload->>K8S: Stream pod logs
    
    loop Log Stream
        K8S-->>Workload: Log line
        Workload->>SocketIO: Emit log data
        SocketIO-->>Browser: Display log
    end
    
    Browser->>SocketIO: Disconnect
    SocketIO->>Workload: Stop stream
```

---

## Database Schema

```mermaid
erDiagram
    USERS ||--o{ USERS_ROLES : has
    USERS ||--o{ USERS_KUBECTL : has
    USERS ||--o{ SSO_USER_GROUP_MAPPING : belongs_to
    ROLES ||--o{ USERS_ROLES : assigned_to
    KUBECTL_CONFIG ||--o{ USERS_KUBECTL : linked_to
    SSO_GROUPS ||--o{ SSO_USER_GROUP_MAPPING : contains
    
    USERS {
        int id PK
        string username UK
        string password_hash
        string email UK
        string user_type
        text tokens
    }
    
    ROLES {
        int id PK
        string name UK
    }
    
    USERS_ROLES {
        int id PK
        int user_id FK
        int role_id FK
    }
    
    KUBECTL_CONFIG {
        int id PK
        string name
        string cluster
        text private_key
        text user_certificate
    }
    
    USERS_KUBECTL {
        int id PK
        int user_id FK
        int kubectl_id FK
    }
    
    SSO_GROUPS {
        int id PK
        string name UK
        datetime created
    }
    
    SSO_USER_GROUP_MAPPING {
        int id PK
        int user_id FK
        int group_id FK
    }
    
    K8S_CLUSTER_CONFIG {
        int id PK
        text k8s_server_url UK
        text k8s_context UK
        text k8s_server_ca
    }
    
    SSO_SERVER {
        int id PK
        text oauth_server_uri
        text client_id
        text client_secret
        text oauth_server_ca
    }
    
    SESSIONS {
        string session_id PK
        blob data
        datetime expiry
    }
```

---

## Plugin System Architecture

```mermaid
graph TB
    subgraph "Plugin Discovery"
        SCAN[Scan plugins/ directory]
        CONFIG[Check kubedash.ini]
        ENABLE{Plugin enabled?}
    end
    
    subgraph "Plugin Loading"
        IMPORT[Import plugin module]
        BP[Find blueprint]
        MODEL[Load models]
        REGISTER[Register blueprint]
    end
    
    subgraph "Plugin Types"
        HELM[Helm Plugin<br/>- Chart listing<br/>- Release management]
        REG[Registry Plugin<br/>- Image browsing<br/>- Tag management<br/>- Event tracking]
        CERT[Cert-Manager Plugin<br/>- Certificate viewing<br/>- Issuer management]
        LB[LoadBalancer Plugin<br/>- MetalLB support<br/>- Cilium support]
        FLUX[Flux Plugin<br/>- GitOps visualization<br/>- Source management]
    end
    
    SCAN --> CONFIG
    CONFIG --> ENABLE
    ENABLE -->|Yes| IMPORT
    ENABLE -->|No| SCAN
    IMPORT --> BP
    BP --> MODEL
    MODEL --> REGISTER
    
    REGISTER --> HELM
    REGISTER --> REG
    REGISTER --> CERT
    REGISTER --> LB
    REGISTER --> FLUX
```

### Plugin Interface

Each plugin must follow this structure:

```
plugins/
└── plugin_name/
    ├── __init__.py      # Blueprint definition (plugin_name_bp)
    ├── functions.py     # Business logic
    ├── model.py         # Database models (optional)
    └── templates/       # Jinja2 templates
        └── *.html.j2
```

---

## Security Architecture

```mermaid
graph TB
    subgraph "Authentication Layer"
        LOCAL[Local Authentication<br/>Password + Salt]
        OIDC[OIDC Authentication<br/>OAuth 2.0 Flow]
        TOKEN[Bearer Token Auth<br/>ServiceAccount Tokens]
    end
    
    subgraph "Authorization Layer"
        ROLE[Dashboard Roles<br/>Admin / User]
        K8SRBAC[Kubernetes RBAC<br/>ClusterRole / Role]
        PERM[Permission Checks<br/>Namespace filtering]
    end
    
    subgraph "Security Controls"
        CSP[Content Security Policy]
        CSRF[CSRF Protection]
        CORS[CORS Configuration]
        HSTS[HSTS Headers]
        TALISMAN[Flask-Talisman]
    end
    
    subgraph "Session Security"
        SESS[Server-side Sessions<br/>SQLAlchemy backend]
        COOKIE[Secure Cookies<br/>HttpOnly, SameSite]
        TIMEOUT[Session Timeout<br/>10 minutes]
    end
    
    LOCAL --> ROLE
    OIDC --> ROLE
    TOKEN --> PERM
    ROLE --> K8SRBAC
    
    CSP --> TALISMAN
    CORS --> TALISMAN
    HSTS --> TALISMAN
    
    SESS --> COOKIE
    COOKIE --> TIMEOUT
```

### Security Headers Configuration

| Header | Value | Purpose |
|--------|-------|---------|
| Content-Security-Policy | Strict CSP | Prevent XSS attacks |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-Frame-Options | DENY | Prevent clickjacking |
| Strict-Transport-Security | max-age=31536000 | Force HTTPS |
| Cross-Origin-Embedder-Policy | require-corp | Isolation |
| Cross-Origin-Opener-Policy | same-origin | Isolation |

---

## Deployment Architecture

### Kubernetes Deployment

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        subgraph "KubeDash Namespace"
            SA[ServiceAccount<br/>kubedash-admin]
            DEP[Deployment<br/>kubedash-ui]
            SVC[Service<br/>ClusterIP/LoadBalancer]
            ING[Ingress<br/>HTTPS termination]
        end
        
        subgraph "Optional Components"
            PG[(PostgreSQL<br/>Database)]
            REDIS[(Redis<br/>Cache)]
            JAEGER[Jaeger<br/>Tracing]
        end
        
        subgraph "RBAC"
            CR[ClusterRole<br/>cluster-admin]
            CRB[ClusterRoleBinding]
        end
    end
    
    subgraph "External"
        USER[Users]
        OIDC[OIDC Provider]
    end
    
    USER --> ING
    ING --> SVC
    SVC --> DEP
    DEP --> SA
    SA --> CR
    CR --> CRB
    
    DEP --> PG
    DEP --> REDIS
    DEP --> JAEGER
    DEP --> OIDC
```

### Container Architecture

```mermaid
graph LR
    subgraph "Build Stage"
        PYTHON[Python 3.11 Alpine]
        DEPS[Install Dependencies]
        BUILD[Build Wheels]
    end
    
    subgraph "Runtime Stage"
        BASE[Python 3.11 Alpine]
        COPY[Copy installed packages]
        APP[KubeDash Application]
        ENTRY[Entrypoint Script]
    end
    
    PYTHON --> DEPS
    DEPS --> BUILD
    BUILD --> COPY
    BASE --> COPY
    COPY --> APP
    APP --> ENTRY
```

---

## Technology Stack

### Backend Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Web Framework | Flask | 3.0.2 | Application core |
| WSGI Server | Gunicorn | 23.0.0 | Production server |
| ORM | SQLAlchemy | 2.0.17 | Database abstraction |
| Migration | Alembic/Flask-Migrate | 4.0.5 | Schema migrations |
| Authentication | Flask-Login | 0.6.3 | Session management |
| WebSocket | Flask-SocketIO | 5.5.1 | Real-time communication |
| Caching | Flask-Caching | 2.3.1 | Performance optimization |
| API Documentation | Flask-Smorest | 0.46.1 | OpenAPI/Swagger |
| Kubernetes Client | kubernetes-python | 26.1.0 | K8s API access |

### Observability Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Tracing | OpenTelemetry | Distributed tracing |
| Metrics | Prometheus | Application metrics |
| Logging | Colorlog | Structured logging |
| Export | OTLP HTTP | Trace export to Jaeger |

### Frontend Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| UI Framework | CoreUI + Bootstrap 5 | Responsive design |
| Charts | Chart.js + Plotly | Data visualization |
| Tables | DataTables | Interactive tables |
| Icons | Font Awesome 6 | Icon library |
| Terminal | xterm.js | Terminal emulation |
| Network Graph | PyVis/Cytoscape | Resource mapping |

### Security Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Security Headers | Flask-Talisman | CSP, HSTS, etc. |
| CSRF Protection | Flask-WTF | Form protection |
| Password Hashing | Werkzeug (scrypt) | Secure password storage |
| OAuth 2.0 | Authlib | OIDC integration |

---

## Architectural Decision Records

### ADR-001: Blueprint-Based Modularization

**Context**: Need to organize code for maintainability and scalability.

**Decision**: Use Flask Blueprints to separate concerns by functional domain.

**Consequences**: 
- Improved code organization
- Easier testing of individual components
- Clear separation between UI routes and API endpoints

### ADR-002: SQLAlchemy with Multiple Database Support

**Context**: Need to support both development (SQLite) and production (PostgreSQL) scenarios.

**Decision**: Use SQLAlchemy ORM with configurable database backends.

**Consequences**:
- Seamless development experience
- Production-ready database support
- Migration support through Alembic

### ADR-003: Plugin Architecture

**Context**: Need to extend functionality without modifying core code.

**Decision**: Implement dynamic plugin loading from `plugins/` directory.

**Consequences**:
- Easy addition of new features
- Optional component loading
- Clear plugin interface requirements

### ADR-004: Dual Authentication Modes

**Context**: Support both standalone and enterprise deployments.

**Decision**: Implement local authentication and OIDC SSO.

**Consequences**:
- Flexible deployment options
- Enterprise integration capability
- Kubernetes RBAC integration for OIDC users

### ADR-005: Kubernetes API Abstraction

**Context**: Need consistent interface for Kubernetes operations across authentication modes.

**Decision**: Create `lib/k8s/` abstraction layer with role-based client configuration.

**Consequences**:
- Unified API access pattern
- Transparent admin vs user token handling
- Centralized error handling and caching

---

## Performance Considerations

### Caching Strategy

```mermaid
graph LR
    subgraph "Cache Tiers"
        L1[In-Memory<br/>SimpleCache]
        L2[Distributed<br/>Redis]
        L3[Redis Cluster<br/>High Availability]
    end
    
    subgraph "Cache Keys"
        NS[Namespaces<br/>15 min TTL]
        WL[Workloads<br/>1 min TTL]
        BASE[Templates<br/>Permanent]
    end
    
    L1 -->|Fallback| L2
    L2 -->|Scale| L3
    
    NS --> L2
    WL --> L2
    BASE --> L1
```

### Caching Configuration

| Cache Type | TTL | Use Case |
|------------|-----|----------|
| Short Cache | 60s | Dynamic resources (pods, events) |
| Long Cache | 900s | Semi-static resources (namespaces, CRDs) |
| Template Cache | ∞ | Base templates |

---

## Future Architecture Considerations

1. **Horizontal Scaling**: Multi-instance deployment with shared session store
2. **Event-Driven Architecture**: Kubernetes watch streams for real-time updates
3. **GraphQL API**: Alternative to REST for flexible queries
4. **Multi-Cluster Support**: Managing multiple Kubernetes clusters
5. **Audit Logging**: Comprehensive action logging for compliance

---

*Last Updated: December 2025*
*Version: 4.1.0*
