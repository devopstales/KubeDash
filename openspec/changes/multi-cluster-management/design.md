## Context

KubeDash currently maintains a single cluster configuration in the `k8s_cluster_config` table, loaded at application startup via `k8sServerConfigGet()`. All blueprints use this global configuration through `k8sClientConfigGet()`, which loads either in-cluster config, local kubeconfig, or OIDC-based configuration depending on user role.

**Current Architecture:**
```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Blueprints │────▶│ k8sClientConfig  │────▶│ Single K8s   │
│  (all)      │     │ Get()            │     │ Cluster      │
└─────────────┘     └──────────────────┘     └──────────────┘
                           │
                           ▼
                    k8s_cluster_config
                    (single row in DB)
```

**Constraints:**
- Must maintain backward compatibility with single-cluster deployments
- Cannot break existing Extension API consumers
- Must work with existing authentication methods (local, OIDC, ServiceAccount)
- Kubernetes Python client supports multi-context kubeconfig files
- Session-based state management (Flask sessions)

**Stakeholders:**
- Platform teams managing multiple clusters
- SREs needing cross-cluster visibility
- Extension API consumers (kubectl, CI/CD tools)
- Current single-cluster users (must not break)

## Goals / Non-Goals

**Goals:**
- Support unlimited cluster registrations with CRUD operations
- Enable per-user, per-session cluster switching
- Maintain cluster-specific RBAC permissions
- Provide cluster health monitoring and status indicators
- Preserve single-cluster UX for simple deployments
- Enable Extension API to route requests to specific clusters

**Non-Goals:**
- Multi-cluster resource aggregation (e.g., "show all pods across all clusters")
- Cluster federation or control plane synchronization
- Automatic cluster discovery (manual registration required)
- Cross-cluster resource operations (e.g., copy pod from cluster A to B)
- Cluster auto-failover or load balancing

## Decisions

### 1. Cluster State Management: Session-Based vs URL Parameter

**Decision:** Hybrid approach - session-based for UI, URL parameter for API

**Rationale:**
- UI users need persistent cluster context across page navigations
- API consumers (kubectl, scripts) need explicit, stateless cluster specification
- Session storage: `session['current_cluster'] = cluster_name`
- API routing: `?cluster=cluster-name` query parameter or header `X-Cluster-Context`

**Alternatives Considered:**
- URL-only approach: Too verbose for UI, breaks bookmarking
- Session-only approach: Breaks stateless API consumers
- Cookie-based: Security concerns, less flexible than sessions

### 2. Cluster Configuration Storage: Single Table vs Separate Registry

**Decision:** New `cluster_registry` table with migration from existing `k8s_cluster_config`

**Schema:**
```sql
CREATE TABLE cluster_registry (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    api_server_url TEXT NOT NULL,
    ca_certificate TEXT,
    connection_type VARCHAR(50) DEFAULT 'direct',  -- direct, in-cluster, kubeconfig
    kubeconfig_context VARCHAR(255),
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_health_check TIMESTAMP,
    health_status VARCHAR(50) DEFAULT 'unknown'
);
```

**Rationale:**
- Existing table designed for single row only (unique constraints)
- New schema supports multiple clusters with metadata
- Migration preserves existing configuration as `default` cluster

### 3. Client Configuration Loading: Global vs Per-Request

**Decision:** Per-request client configuration with connection pooling

**Implementation:**
```python
def get_k8s_client(cluster_name, user_role, user_token=None):
    """Get Kubernetes client for specific cluster."""
    cluster = ClusterRegistry.get_by_name(cluster_name)
    if not cluster:
        raise ClusterNotFoundError(cluster_name)
    
    # Check connection pool first
    client = connection_pool.get(cluster_name, user_role)
    if client:
        return client
    
    # Load configuration for this specific cluster
    config = cluster.load_client_config(user_role, user_token)
    client = k8s_client.ApiClient(config)
    
    # Cache in pool (with TTL)
    connection_pool.set(cluster_name, user_role, client, ttl=3600)
    return client
```

**Rationale:**
- Global config approach doesn't work with multiple clusters
- Connection pooling prevents excessive re-authentication
- TTL-based cache invalidation handles token expiration
- Per-role clients maintain RBAC isolation

**Alternatives Considered:**
- Global config with reload on switch: Too slow, race conditions
- No caching: Performance degradation, excessive API calls
- Permanent connections: Token expiration issues, memory leaks

### 4. Cluster Switching: Middleware vs Explicit Resolution

**Decision:** Blueprint-level middleware with `@cluster_context` decorator

**Implementation:**
```python
from lib.k8s.context import cluster_context

@workload_bp.route('/pods')
@cluster_context  # Resolves cluster from session/API param
def list_pods(cluster_name):
    client = get_k8s_client(cluster_name, session['user_role'])
    # ... rest of handler
```

**Rationale:**
- Cross-cutting concern deserves centralized handling
- Decorator approach is explicit and testable
- Falls back to default cluster if none specified
- Consistent error handling for cluster-not-found

**Alternatives Considered:**
- Application-level middleware: Too early in request cycle
- Manual resolution in every endpoint: Repetitive, error-prone
- Request object injection: Less explicit, harder to test

### 5. Per-Cluster RBAC: Separate Table vs Extended Claims

**Decision:** Separate `user_cluster_roles` table with foreign keys

**Schema:**
```sql
CREATE TABLE user_cluster_roles (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    cluster_id INTEGER REFERENCES cluster_registry(id),
    role VARCHAR(50) NOT NULL,  -- Admin, User, Viewer, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, cluster_id)
);
```

**Rationale:**
- Decouples global user roles from cluster-specific permissions
- Supports users with different roles in different clusters
- Easy to query: `SELECT role FROM user_cluster_roles WHERE user_id=? AND cluster_id=?`
- Can extend with cluster-specific groups later

**Alternatives Considered:**
- Extend OIDC claims: Requires IdP changes, less flexible
- Single role for all clusters: Too restrictive
- JSON column in users table: Harder to query, no FK constraints

### 6. Cluster Health Monitoring: Active Probing vs Passive Status

**Decision:** Active health checks with background scheduler

**Implementation:**
- APScheduler job runs every 60 seconds
- Probes `/version` endpoint on each active cluster
- Updates `health_status` and `last_health_check` in registry
- Status values: `healthy`, `unhealthy`, `unknown`, `unreachable`

**Rationale:**
- Users need real-time cluster availability information
- Passive detection (wait for user action) creates poor UX
- Lightweight probe minimizes overhead
- Background job prevents request blocking

### 7. Extension API Routing: Path-Based vs Query Parameter

**Decision:** Query parameter for backward compatibility

**API Patterns:**
```
# Current (single cluster) - still works
GET /api/v1/namespaces/default/pods

# Multi-cluster (explicit)
GET /api/v1/namespaces/default/pods?cluster=cluster-name
GET /apis/kubedash.io/v1/clusters/cluster-name/namespaces/default/pods
```

**Rationale:**
- Query parameter is backward compatible
- Path-based routing clearer but breaks existing clients
- Extension API can support both patterns during transition
- Header-based (`X-Cluster-Context`) alternative for programmatic access

## Risks / Trade-offs

### [Risk] Connection Pool Memory Growth

**Mitigation:**
- LRU eviction policy with max pool size (configurable, default 100)
- TTL-based expiration (1 hour default)
- Monitor pool size via metrics endpoint
- Alert on pool exhaustion

### [Risk] Session Desynchronization

**Scenario:** User switches cluster, opens new tab, expects same context

**Mitigation:**
- Session-based cluster context is user-specific, not tab-specific
- Consider localStorage for tab-specific cluster context (future enhancement)
- Clear UX indicating current cluster at all times

### [Risk] RBAC Confusion

**Scenario:** User has Admin role in cluster-A, Viewer in cluster-B

**Mitigation:**
- UI clearly shows current cluster and effective role
- Cluster switcher displays role badge per cluster
- Audit logs include both user and cluster context

### [Risk] Migration Data Loss

**Scenario:** Migration fails, existing cluster config lost

**Mitigation:**
- Backup `k8s_cluster_config` before migration
- Idempotent migration script (can retry safely)
- Rollback procedure documented
- Test migration on staging first

### [Risk] Performance Degradation

**Scenario:** Multiple clusters increase latency

**Mitigation:**
- Connection pooling reduces repeated auth overhead
- Lazy loading: only connect to selected cluster
- Health check runs asynchronously
- Cache cluster list (5-minute TTL)

### [Trade-off] No Cross-Cluster Aggregation

**Decision:** Explicitly out of scope for this change

**Rationale:**
- Adds significant complexity (data merging, conflict resolution)
- Different use case (monitoring vs management)
- Can be added as separate capability later
- Focus on core multi-cluster management first

### [Trade-off] Manual Cluster Registration

**Decision:** No automatic cluster discovery in initial implementation

**Rationale:**
- Discovery mechanisms vary (DNS, service mesh, custom)
- Security concerns with auto-discovery in enterprise
- Can add plugins for specific discovery mechanisms later
- Manual registration is explicit and auditable

## Migration Plan

### Phase 1: Database Migration
```sql
-- Create new tables
CREATE TABLE cluster_registry (...);
CREATE TABLE user_cluster_roles (...);

-- Migrate existing config
INSERT INTO cluster_registry (name, api_server_url, ca_certificate, is_default, is_active)
SELECT 'default', k8s_server_url, k8s_server_ca, TRUE, TRUE
FROM k8s_cluster_config;

-- Preserve old table for rollback
ALTER TABLE k8s_cluster_config RENAME TO k8s_cluster_config_backup;
```

### Phase 2: Code Deployment
1. Deploy new `lib/k8s/context.py` module (cluster resolution logic)
2. Deploy updated `lib/k8s/server.py` (multi-cluster client loading)
3. Deploy `blueprint/cluster/registry.py` (cluster management UI)
4. Update all resource blueprints with `@cluster_context` decorator
5. Deploy cluster switcher component to base template

### Phase 3: Data Migration
1. Run migration script (automated via Alembic/Flask-Migrate)
2. Verify default cluster created from existing config
3. Test cluster switching with default cluster
4. Enable health check scheduler

### Rollback Strategy
1. Stop application
2. Restore `k8s_cluster_config` from backup
3. Revert code to previous version
4. Restart application
5. Verify single-cluster functionality

## Open Questions

1. **Cluster Naming Constraints:** Should cluster names have restrictions (DNS-1123, length limits)? 
   - Leaning toward: DNS-1123 subdomain format (lowercase alphanumeric, `-`, max 253 chars)

2. **Default Cluster Behavior:** What if default cluster is unhealthy?
   - Leaning toward: Show health warning, but still use as default; allow user to switch

3. **Extension API Versioning:** Should multi-cluster support trigger API version bump?
   - Leaning toward: No, backward compatible; document cluster parameter in existing API docs

4. **Cluster Deletion:** What happens to resources when cluster is deleted?
   - Leaning toward: Soft delete (`is_active=FALSE`), prevent deletion if user roles exist

5. **Concurrent Cluster Access:** Should we support viewing multiple clusters simultaneously (multi-tab)?
   - Leaning toward: Out of scope for initial implementation; session-based is single-cluster-per-user
