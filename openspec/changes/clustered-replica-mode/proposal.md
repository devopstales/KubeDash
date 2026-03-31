## Why

KubeDash currently runs as a single-replica StatefulSet with SQLite or PostgreSQL database and SQLAlchemy-backed sessions stored in the same database. This architecture prevents horizontal scaling for high availability and creates a single point of failure. Running multiple replicas requires solving distributed coordination challenges: shared session storage, database write conflicts, and leader election for background tasks.

## What Changes

- **Shared Session Storage**: Migrate from SQLAlchemy database-backed sessions to Redis-backed sessions for multi-replica session sharing
- **Leader Election Framework**: Implement Kubernetes Leases-based leader election for background jobs (health checks, schedulers, cleanup tasks)
- **Database Mode Detection**: Add configuration for `database.mode` (single vs. cluster) with appropriate behavior per mode
- **Leader-Only Tasks**: Mark specific background tasks as leader-only (health monitoring, cache cleanup, periodic sync)
- **Stateless Replica Design**: Refactor application to be stateless except for Redis session/ cache layer
- **Helm Chart Updates**: Support multiple replicas with Redis requirement, leader election RBAC, horizontal pod autoscaling

**BREAKING**: 
- Existing SQLite deployments cannot scale beyond 1 replica without migrating to PostgreSQL or LiteFS
- Session data migrates to Redis; users may need to re-login after upgrade if Redis not previously enabled
- Background task execution changes from "all replicas" to "leader only" for certain jobs

## Capabilities

### New Capabilities
- `redis-session-backend`: Redis-backed Flask-Session storage for multi-replica session sharing
- `leader-election`: Kubernetes Leases-based leader election for background task coordination
- `leader-only-tasks`: Framework for marking and executing tasks only on leader replica
- `cluster-mode-detection`: Runtime detection and configuration for single vs. multi-replica modes

### Modified Capabilities
- `database-configuration`: Add multi-replica mode support, PostgreSQL recommended for HA
- `background-scheduler`: APScheduler tasks split into leader-only and all-replica categories
- `health-check-scheduler`: Cluster health checks run only on leader replica

## Impact

**Code Changes**:
- `lib/config.py`: Add `REDIS_SESSION_ENABLED` configuration, session backend detection
- `lib/initializers/database.py`: Session initialization conditional on backend type
- `lib/k8s/health.py`: Wrap health check scheduler with leader election guard
- New `lib/leader_election.py`: Leader election framework using Kubernetes Leases API
- New `lib/leader_tasks.py`: Decorator and framework for leader-only task registration
- All APScheduler jobs: Review and mark as leader-only or all-replica
- `lib/prometheus.py`: Add leader status metric, election transition counters

**Database**:
- No schema changes required
- Redis becomes required dependency for multi-replica deployments
- SQLite limited to single-replica; PostgreSQL recommended for HA
- Optional: LiteFS support for SQLite replication (future enhancement)

**APIs**:
- New endpoint: `/api/v1/leader/status` - current leader identity and lease info
- New endpoint: `/api/v1/replicas/status` - replica count and leader status per pod
- Health endpoints return leader status in response metadata

**Dependencies**:
- Redis already enabled in Helm chart (optional); becomes required for `replicas > 1`
- Kubernetes Python client already present; Leases API available via `CoordinationV1Api`
- APScheduler already in use; no new dependencies for leader election

**Infrastructure**:
- Helm chart: `replicas` can exceed 1 only with Redis enabled
- New Role/RoleBinding for Leases access (get, create, update)
- HorizontalPodAutoscaler support for auto-scaling based on CPU/memory
- Pod disruption budget recommended for HA deployments

**Deployment**:
- StatefulSet remains (needed for stable pod identities); can migrate to Deployment if fully stateless
- Environment variable `LEADER_ELECTION_ENABLED=true` for multi-replica mode
- Pod name and namespace used for leader identity (via downward API)
- Graceful shutdown releases leadership before termination

**Observability**:
- Metrics: `kubedash_leader_election_is_leader` gauge (1/0)
- Metrics: `kubedash_leader_election_transitions_total` counter
- Logs: Leader acquisition/loss events with lease details
- Tracing: Leader election spans include identity and lease duration
