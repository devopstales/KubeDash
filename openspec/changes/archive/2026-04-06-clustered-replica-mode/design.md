## Context

KubeDash currently operates as a single-replica StatefulSet with the following architecture:

```
┌─────────────────────────────────────────────────────────┐
│                   Single Replica                         │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐      ┌──────────────┐                │
│  │  Flask App   │      │  APScheduler │                │
│  │              │      │  (all tasks)  │                │
│  │  Sessions →  │─────▶│  SQLAlchemy   │                │
│  │  (in DB)     │      │  Backend      │                │
│  └──────────────┘      └──────────────┘                │
│                          │                              │
│                          ▼                              │
│                   ┌─────────────┐                       │
│                   │  SQLite /   │                       │
│                   │  PostgreSQL │                       │
│                   └─────────────┘                       │
└─────────────────────────────────────────────────────────┘
```

**Problems with current approach:**
- Single point of failure (no HA)
- Cannot scale horizontally for increased load
- All background tasks run on every replica (wasteful, potential conflicts)
- Session affinity required if scaling without shared storage

**Constraints:**
- Must support existing SQLite deployments (single-replica only)
- Redis already optional in Helm chart; can be made required for HA
- Kubernetes Python client already available
- APScheduler already in use for background jobs
- Flask-Session supports Redis backend out of the box

**Stakeholders:**
- Platform teams needing HA for production deployments
- Users experiencing downtime during pod restarts/updates
- Operations teams requiring horizontal scalability

## Goals / Non-Goals

**Goals:**
- Enable 2+ replica deployments with shared session state
- Implement leader election for background task coordination
- Maintain backward compatibility with single-replica SQLite deployments
- Provide clear upgrade path from single to multi-replica
- Add observability for leader status and elections

**Non-Goals:**
- Database replication (PostgreSQL HA handled externally)
- LiteFS integration for SQLite replication (future enhancement)
- Cross-replica caching beyond session storage
- Automatic scaling based on custom metrics (use standard HPA)
- Distributed task queue (Celery-style) - out of scope

## Decisions

### 1. Session Backend: Redis vs. PostgreSQL vs. Memcached

**Decision:** Redis for multi-replica, PostgreSQL fallback, in-memory for single-replica

**Rationale:**
- Redis already integrated in Helm chart (optional)
- Sub-millisecond latency for session operations
- Built-in TTL support for session expiration
- Redis pub/sub can enable future real-time features
- PostgreSQL already used for main database but slower for session access
- Memcached adds another dependency without significant benefit

**Configuration:**
```python
# Single replica (default)
SESSION_TYPE = "sqlalchemy"  # Uses main database

# Multi-replica (Redis required)
SESSION_TYPE = "redis"
SESSION_REDIS = "redis://<host>:6379/0"
SESSION_KEY_PREFIX = "kubedash:session:"
```

**Alternatives Considered:**
- PostgreSQL for sessions: Simpler (one DB), but connection pool contention, slower
- Memcached: No persistence, no TTL flexibility, additional dependency
- Client-side sessions (JWT): Stateless but large tokens, revocation complexity

### 2. Leader Election: Kubernetes Leases vs. Redis Locks vs. Database Locks

**Decision:** Kubernetes Leases API

**Rationale:**
- Native Kubernetes primitive designed for leader election
- No external dependencies beyond cluster access
- Automatic cleanup when leader pod terminates
- Visible via `kubectl get leases` for debugging
- RBAC-controlled access
- Works with any database backend (SQLite, PostgreSQL)

**Implementation:**
```python
from kubernetes.client import CoordinationV1Api

class LeaderElector:
    lease_name = "kubedash-leader"
    namespace = pod_namespace  # From downward API
    identity = pod_name        # Unique per pod
    
    # Timing (tunable via config)
    lease_duration = 15  # seconds
    renew_deadline = 10  # seconds
    retry_period = 2     # seconds
```

**Alternatives Considered:**
- Redis distributed lock (SET NX EX): Requires Redis, more complex renewal logic
- Database advisory locks: PostgreSQL-only, doesn't work with SQLite
- Etcd directly: Adds dependency, duplicates Kubernetes control plane

### 3. Leader Election Timing Parameters

**Decision:** 15s lease duration, 10s renew deadline, 2s retry period

**Rationale:**
- 15s lease: Balance between fast failover and API server load
- 10s renew: 5-second window for renewal attempts
- 2s retry: Frequent enough to catch expiration, not excessive

**Trade-offs:**
```
Faster failover (10s lease) ↔ More API server pressure
Stability (30s lease) ↔ Slower failover
```

**Configuration:**
```yaml
leaderElection:
  leaseDurationSeconds: 15
  renewDeadlineSeconds: 10
  retryPeriodSeconds: 2
```

### 4. Task Classification: Leader-Only vs. All-Replica

**Decision:** Explicit decorator-based classification

**Implementation:**
```python
from lib.leader_tasks import leader_only

@leader_only
def check_cluster_health():
    """Run only on leader replica."""
    ...

@app.scheduler.scheduled_job('interval', seconds=60)
def cleanup_expired_sessions():
    """Run on all replicas (local cache cleanup)."""
    ...
```

**Task Categories:**

| Task Type | Example | Execution |
|-----------|---------|-----------|
| Leader-Only | Cluster health checks | Single replica |
| Leader-Only | Periodic DB sync | Single replica |
| Leader-Only | Token refresh | Single replica |
| All-Replica | Request logging | Every replica |
| All-Replica | Local cache cleanup | Every replica |
| All-Replica | Metrics collection | Every replica |

**Rationale:**
- Explicit is better than implicit (clear intent)
- Prevents duplicate external API calls
- Reduces database write conflicts
- Some tasks must run on all replicas (local state)

### 5. Replica Mode Detection: Automatic vs. Explicit

**Decision:** Explicit configuration with automatic validation

**Configuration:**
```ini
[cluster]
replicas_mode = cluster  # or 'single'
replicas_count = 3       # informational, not enforced
```

**Validation:**
```python
def validate_replica_config():
    if config.mode == 'cluster' and not redis_enabled:
        raise ConfigError("Cluster mode requires Redis")
    if config.mode == 'single' and replicas > 1:
        raise ConfigError("Single mode cannot scale beyond 1 replica")
```

**Rationale:**
- Explicit mode prevents accidental misconfiguration
- Automatic validation catches errors early
- Mode affects task scheduling, session backend, health checks

### 6. Deployment: StatefulSet vs. Deployment

**Decision:** Remain on StatefulSet for now

**Rationale:**
- Stable pod identities useful for debugging
- Ordered deployment/rollback (safety)
- Can migrate to Deployment once fully stateless
- No strong requirement for stable network identities

**Future:** Could migrate to Deployment when:
- No local state whatsoever
- Session storage fully external
- Leader election uses pod name (stable via hostname)

### 7. Graceful Shutdown: Release Leadership

**Decision:** SIGTERM handler releases lease before exit

**Implementation:**
```python
import signal

def shutdown_handler(signum, frame):
    if leader_elector.is_leader:
        leader_elector.release()  # Delete or clear lease
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
```

**Rationale:**
- Faster failover (new leader elected immediately)
- Clean handover vs. waiting for lease expiration
- Prevents "ghost leader" scenario

### 8. Database Strategy for Multi-Replica

**Decision:** PostgreSQL recommended, SQLite single-replica only, LiteFS future

**Recommendations:**
```yaml
# Production HA
replicas: 3
postgresql:
  enabled: true  # Or externalDatabase.enabled: true
redis:
  enabled: true

# Development / Testing
replicas: 1
sqlite: true  # Built-in
redis:
  enabled: false  # Optional
```

**LiteFS Evaluation:**
- **Pros**: SQLite replication, automatic failover, familiar SQLite ops
- **Cons**: Requires FUSE, sidecar container, additional complexity
- **Status**: Future enhancement (not in initial scope)

**Rationale:**
- PostgreSQL battle-tested for HA
- SQLite sufficient for single-replica dev/test
- LiteFS adds complexity; evaluate after core HA implemented

## Risks / Trade-offs

### [Risk] Redis Single Point of Failure

**Scenario:** Redis goes down, all replicas lose session storage

**Mitigation:**
- Deploy Redis in HA mode (redis-operator, sentinel, or cluster)
- Helm chart already supports Redis HA configuration
- Graceful degradation: sessions fail to in-memory (sticky sessions required)

### [Risk] Leader Election Split-Brain

**Scenario:** Network partition causes multiple leaders

**Mitigation:**
- Kubernetes Leases API prevents true split-brain (atomic updates)
- Short lease duration (15s) limits window
- `leaseTransitions` counter for monitoring/detection
- Quorum-based Kubernetes API ensures consistency

### [Risk] Increased Kubernetes API Load

**Scenario:** Frequent lease renewals pressure API server

**Mitigation:**
- 2s retry period = 30 renewals/hour per replica (acceptable)
- Use API server caching proxies if needed
- Monitor `apiserver_request_total` for impact

### [Risk] Session Migration Complexity

**Scenario:** Users lose sessions when upgrading to Redis backend

**Mitigation:**
- Rolling upgrade: enable Redis, drain old sessions, switch backend
- Document re-login requirement in upgrade notes
- Future: dual-write sessions during migration

### [Risk] Leader Pod Overload

**Scenario:** Leader replica handles all background tasks plus user traffic

**Mitigation:**
- Background tasks designed to be lightweight
- Separate leader-only tasks from heavy operations
- Future: dedicated leader pod for background jobs only
- Monitor leader CPU/memory vs. followers

### [Trade-off] StatefulSet vs. Full Statelessness

**Decision:** Keep StatefulSet, accept minor complexity

**Rationale:**
- Easier rollback with ordered deployment
- Stable pod names simplify debugging
- Can migrate to Deployment later
- Minimal operational difference

### [Trade-off] No Automatic Mode Detection

**Decision:** Require explicit `mode = cluster` configuration

**Rationale:**
- Prevents accidental HA without Redis
- Clear intent in configuration
- Easier to validate and debug

## Migration Plan

### Phase 1: Preparation (Single-Replica)
1. Enable Redis in Helm chart (optional, no traffic yet)
2. Deploy leader election RBAC (harmless if not used)
3. Add observability (metrics, logs) for future debugging

### Phase 2: Code Deployment
1. Deploy code with Redis session support (behind feature flag)
2. Deploy leader election framework (disabled by default)
3. Test leader election in staging with 2 replicas

### Phase 3: Enable Multi-Replica
1. Set `replicas: 2` in Helm values
2. Set `redis.enabled: true`
3. Set `replicas.mode: cluster`
4. Enable leader election: `leaderElection.enabled: true`

### Phase 4: Validation
1. Verify sessions shared across replicas
2. Confirm only leader runs health checks
3. Test failover (kill leader pod, verify election)
4. Scale to 3+ replicas, validate stability

### Phase 5: Production Rollout
1. Update production Helm chart
2. Scale from 1 → 2 replicas
3. Monitor leader elections, session hit rate
4. Enable HPA if needed

### Rollback Strategy
1. Scale back to 1 replica
2. Disable leader election
3. Revert to SQLAlchemy sessions (automatic)
4. Redis can remain deployed (no harm)

## Open Questions

1. **HPA Integration:** Should leader election influence HPA (min 1 leader always)?
   - Leaning toward: No, HPA scales replicas; leader election adapts automatically

2. **Leader Pod Priority:** Should leader get priority in scheduling/preemption?
   - Leaning toward: No, adds complexity; all replicas equally capable

3. **Session Stickiness:** Should ingress use sticky sessions despite Redis?
   - Leaning toward: No, Redis enables true load balancing; stickiness limits benefit

4. **LiteFS Timeline:** Should LiteFS support be prioritized for SQLite users?
   - Leaning toward: After core HA stable; PostgreSQL sufficient for production

5. **Metrics Exposure:** Should leader status be exposed via Prometheus AND health endpoint?
   - Leaning toward: Both; Prometheus for monitoring, endpoint for quick checks
