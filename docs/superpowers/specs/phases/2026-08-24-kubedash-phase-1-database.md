# Phase 1: Database Structure Plan

## Overview
Phase 1 uses PostgreSQL with Flask-SQLAlchemy and Alembic migrations. The database stores user identities, RBAC roles, session state, audit logs, and time-series metrics. Kubernetes resources are **not** persisted — they are queried live from the cluster.

---

## Tables

### 1. sessions
Flask-Session storage for web UI sessions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal row ID |
| session_id | String(255) | Unique, nullable | Flask session identifier |
| data | LargeBinary | nullable | Serialized session data |
| expiry | DateTime | nullable | Session expiration timestamp |

**Indexes:** `session_id` unique index  
**Purpose:** Enables PostgreSQL-backed Flask sessions for web UI authentication  
**Notes:** Created by Flask-Session; managed automatically

---

### 2. users
User accounts for ServiceAccount token authentication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal user ID |
| username | String(80) | Unique, not null | Display name / SA token identifier |
| email | String(120) | Unique, nullable | Contact email |
| user_type | String(20) | not null, default "ServiceAccount" | Authentication type |
| created_at | DateTime | not null, default now | Account creation time |
| updated_at | DateTime | not null, default now on update | Last modification time |

**Indexes:** `username` unique, `email` unique  
**Purpose:** Identify authenticated users for ServiceAccount token auth  
**Notes:** 
- No `password_hash` column in Phase 1 (no local passwords)
- No `tokens` column (tokens never persisted per architecture decision)
- `user_type` is always `"ServiceAccount"` in Phase 1

---

### 3. roles
RBAC roles for authorization.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal role ID |
| name | String(50) | Unique, not null | Role name (e.g., "Admin", "User", "Viewer") |
| description | String(255) | nullable | Human-readable description |

**Indexes:** `name` unique  
**Purpose:** Map users to permission levels  
**Notes:** Seed data: Admin, User, Viewer

---

### 4. users_roles
Many-to-many association between users and roles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal association ID |
| user_id | Integer | FK → users.id, ondelete CASCADE | User reference |
| role_id | Integer | FK → roles.id, ondelete CASCADE | Role reference |

**Indexes:** Composite unique on `(user_id, role_id)`  
**Purpose:** Assign roles to users  
**Notes:** A user can have multiple roles, but typically one primary role

---

### 5. k8s_config
Kubernetes cluster connection configuration.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal config ID |
| k8s_server_url | Text | not null, unique | Kubernetes API server URL |
| k8s_context | Text | not null, unique | Kubeconfig context name |
| k8s_server_ca | Text | nullable | Base64-encoded CA certificate |

**Indexes:** `k8s_context` unique, `k8s_server_url` unique  
**Purpose:** Store cluster connection details for ServiceAccount token validation  
**Notes:** 
- In Phase 1, typically one cluster config
- CA is stored as base64 text for portability

---

### 6. audit_log
Audit trail for compliance and security.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal log ID |
| created_at | DateTime(timezone=True) | not null | Event timestamp |
| trace_id | String(64) | nullable | OpenTelemetry trace ID |
| user_id | String(255) | not null | Username who performed action |
| action | String(64) | not null | Action type (login, project_create, etc.) |
| resource | String(255) | not null | Affected resource |
| result | String(32) | not null | Outcome: success, failure, denied |
| details | JSON | nullable | Additional structured data |
| message | Text | nullable | Human-readable description |

**Indexes:** `created_at`, `user_id`, `action`, `resource`  
**Purpose:** Record security-relevant events for compliance  
**Notes:** Writes are non-blocking via background queue (inspired by v4)

---

### 7. metrics_nodes
Time-series node metrics from Prometheus.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| uid | Integer | PK, auto-increment | Internal metric ID |
| name | String(255) | not null | Node name |
| cpu | Float | not null | CPU usage percentage |
| memory | Float | not null | Memory usage percentage |
| storage | Float | not null | Storage usage percentage |
| time | DateTime | not null, default now UTC | Scrape timestamp |

**Indexes:** `name`, `time`  
**Purpose:** Store historical node metrics for dashboard charts  
**Notes:** Data is time-series; old records can be pruned via TTL policy

---

### 8. metrics_pods
Time-series pod metrics from Prometheus.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| uid | Integer | PK, auto-increment | Internal metric ID |
| name | String(255) | not null | Pod name |
| namespace | String(255) | not null | Pod namespace |
| container | String(255) | not null | Container name |
| cpu | Float | not null | CPU usage (cores or millicores) |
| memory | Float | not null | Memory usage (bytes or MiB) |
| storage | Float | not null | Storage usage (bytes or MiB) |
| time | DateTime | not null, default now UTC | Scrape timestamp |

**Indexes:** `namespace`, `name`, `time`  
**Purpose:** Store historical pod metrics for dashboard charts  
**Notes:** Data is time-series; old records can be pruned via TTL policy

---

### 9. kubectl_config
Kubernetes kubectl configuration fragments for download.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal config ID |
| name | String(50) | not null | Config name (typically username) |
| cluster | String(50) | not null | Cluster context name |
| private_key | Text | nullable | PEM-encoded client private key |
| user_certificate | Text | nullable | PEM-encoded client certificate |

**Indexes:** `name`, `cluster`  
**Purpose:** Store certificate-based kubectl config fragments for local users  
**Notes:** 
- Used for cert-based kubeconfig generation
- For SSO users, kubeconfig is generated on-the-fly from live tokens (not stored)
- For ServiceAccount users in Phase 1, kubeconfig is generated on-the-fly from session token

---

### 10. users_kubectl
Many-to-many association between users and kubectl configs.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | Integer | PK, auto-increment | Internal association ID |
| user_id | Integer | FK → users.id, ondelete CASCADE | User reference |
| kubectl_config_id | Integer | FK → kubectl_config.id, ondelete CASCADE | Kubectl config reference |

**Indexes:** Composite unique on `(user_id, kubectl_config_id)`  
**Purpose:** Link users to their kubectl configurations  
**Notes:** A user can have multiple kubectl configs for different clusters

---

## Entity-Relationship Diagram

```
users (1) ──── (N) users_roles (N) ──── (1) roles
   │
   ├─── (N) users_kubectl (N) ──── (1) kubectl_config
   │
   └─── sessions (via Flask-Session, not FK)
   
k8s_config (standalone, 1 row typically)

audit_log (standalone, references user_id as string)

metrics_nodes (standalone time-series)
metrics_pods (standalone time-series)
```

---

## What is NOT in Phase 1

| Table | Reason | Phase |
|-------|--------|-------|
| `openid` | OIDC/SSO configuration | Phase 2 |
| `sso_groups` | SSO group management | Phase 2 |
| `sso_user_group_mapping` | SSO user-group links | Phase 2 |
| `projects` | Projects computed from namespaces + permissions, not stored | Never (Phase 1-2) |
| Plugin tables (ai_chat, cert_manager, etc.) | Plugin system is Phase 2 | Phase 2+ |

---

## Migration Strategy

1. **Initial migration** (`001_init`) — Creates all 10 tables
2. **No data migration needed** — All tables are empty on fresh deploy
3. **Future migrations** — Add columns/tables as phases progress
4. **Rollback** — `alembic downgrade base` drops all tables

### Migration Commands
```bash
# Generate migration
alembic revision --autogenerate -m "001_init"

# Apply
alembic upgrade head

# Rollback
alembic downgrade base
```

---

## Data Retention Policies

| Table | Retention | Rationale |
|-------|-----------|-----------|
| `sessions` | 30 days | Flask-Session default; expired sessions auto-cleaned |
| `audit_log` | 1 year (configurable) | Compliance requirement; archiving TBD |
| `metrics_nodes` | 7 days | Time-series; older data aggregated/aggregated |
| `metrics_pods` | 7 days | Time-series; older data aggregated/aggregated |
| `users` | Indefinite | User identities persist until deleted |
| `roles` | Indefinite | RBAC configuration |
| `k8s_config` | Indefinite | Cluster configuration |
| `kubectl_config` | Indefinite | Kubectl config fragments |
| `users_kubectl` | Indefinite | User-kubectl config associations |

---

## Indexing Strategy

| Table | Index | Type | Purpose |
|-------|-------|------|---------|
| sessions | session_id | UNIQUE | Fast session lookup |
| users | username | UNIQUE | Fast user lookup |
| users | email | UNIQUE | Fast email lookup |
| roles | name | UNIQUE | Fast role lookup |
| users_roles | (user_id, role_id) | UNIQUE | Prevent duplicates |
| k8s_config | k8s_context | UNIQUE | Fast context lookup |
| k8s_config | k8s_server_url | UNIQUE | Fast URL lookup |
| kubectl_config | name | BTREE | Fast config lookup by user |
| kubectl_config | cluster | BTREE | Fast config lookup by cluster |
| users_kubectl | (user_id, kubectl_config_id) | UNIQUE | Prevent duplicates |
| audit_log | created_at | BTREE | Time-range queries |
| audit_log | user_id | BTREE | User activity lookups |
| audit_log | action | BTREE | Action-type filtering |
| audit_log | resource | BTREE | Resource-type filtering |
| metrics_nodes | name | BTREE | Node lookup |
| metrics_nodes | time | BTREE | Time-range queries |
| metrics_pods | (namespace, name, time) | BTREE | Pod time-series queries |

---

## Seed Data

Phase 1 initial seed data inserted via Alembic migration or CLI command:

```sql
-- Roles
INSERT INTO roles (name, description) VALUES
  ('Admin', 'Full cluster access'),
  ('User', 'Standard user access'),
  ('Viewer', 'Read-only access');
```

---

## PostgreSQL-Specific Considerations

1. **JSON column** — `audit_log.details` uses `db.JSON` for structured audit data
2. **DateTime(timezone=True)** — All timestamps stored as UTC with timezone info
3. **LargeBinary** — Session data stored as binary for efficiency
4. **Connection pooling** — Use `psycopg2-binary` with SQLAlchemy pool settings
5. **Extensions** — No special extensions required for Phase 1

---

## Connection String Format

```
postgresql://kubedash:password@postgres:5432/kubedash
```

Environment variables:
- `DATABASE_URL` — Full connection string
- `DATABASE_HOST` — PostgreSQL host
- `DATABASE_PORT` — PostgreSQL port (default 5432)
- `DATABASE_NAME` — Database name
- `DATABASE_USER` — Username
- `DATABASE_PASSWORD` — Password
