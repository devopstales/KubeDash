## 1. Redis Session Backend Implementation

- [x] 1.1 Add Redis dependency to pyproject.toml (flask-session[redis])
- [x] 1.2 Create `lib/session.py` module for session backend configuration
- [x] 1.3 Implement `configure_session_backend(app)` function with Redis/SQLAlchemy detection
- [x] 1.4 Add Redis connection configuration from environment variables
- [x] 1.5 Update `lib/initializers/database.py` to call session configuration before Flask-Session init
- [x] 1.6 Add Redis connectivity health check on startup
- [x] 1.7 Implement graceful fallback to in-memory sessions on Redis failure
- [x] 1.8 Add session backend logging on startup
- [x] 1.9 Update `lib/config.py` with Redis session configuration options
- [x] 1.10 Add SESSION_REDIS_URL, SESSION_KEY_PREFIX configuration

## 2. Leader Election Framework

- [x] 2.1 Create `lib/leader_election.py` module
- [x] 2.2 Implement `LeaderElector` class with Kubernetes Leases API
- [x] 2.3 Implement `try_acquire()` method for lease acquisition
- [x] 2.4 Implement `_create_lease()` method for new lease creation
- [x] 2.5 Implement `_renew_lease()` method for lease renewal
- [x] 2.6 Implement `_is_expired()` method for expiration check
- [x] 2.7 Implement `run()` loop with background thread for continuous election
- [x] 2.8 Add callback support for `on_started_leading` and `on_stopped_leading`
- [x] 2.9 Implement graceful shutdown with leadership release
- [x] 2.10 Add leader election configuration from environment variables
- [x] 2.11 Implement pod identity detection from downward API (POD_NAME, POD_NAMESPACE)
- [x] 2.12 Add leader election error handling and retry logic
- [x] 2.13 Implement lease timing configuration (duration, renew deadline, retry period)

## 3. Leader-Only Task Framework

- [x] 3.1 Create `lib/leader_tasks.py` module
- [x] 3.2 Implement `@leader_only` decorator for task marking
- [x] 3.3 Implement `LeaderTaskRegistry` for task tracking
- [x] 3.4 Add task execution wrapper that checks leader status
- [x] 3.5 Implement task skipping logic for follower replicas
- [x] 3.6 Add logging for leader-only task execution/skipping
- [x] 3.7 Review all APScheduler jobs and categorize as leader-only or all-replica
- [x] 3.8 Mark cluster health checks as leader-only
- [x] 3.9 Mark session cleanup as leader-only
- [x] 3.10 Mark local cache cleanup as all-replica
- [x] 3.11 Mark metrics collection as all-replica
- [x] 3.12 Update task registration to use new framework
- [x] 3.13 Add task execution history tracking

## 4. Cluster Mode Detection and Configuration

- [x] 4.1 Add `REPLICA_MODE` configuration option (single/cluster)
- [x] 4.2 Implement mode validation on startup
- [x] 4.3 Add `REPLICA_COUNT` configuration (informational)
- [x] 4.4 Create `lib/replica_mode.py` module for mode detection
- [x] 4.5 Implement `get_replica_mode()` function
- [x] 4.6 Implement `validate_replica_config()` function
- [x] 4.7 Add mode-dependent feature flags
- [x] 4.8 Implement mode logging on startup
- [x] 4.9 Add configuration validation errors and warnings
- [x] 4.10 Update documentation with mode configuration examples
- [x] 4.11 Enforce PostgreSQL requirement for cluster mode (no SQLite)
- [x] 4.12 Add warning for missing Redis in cluster mode
- [x] 4.13 Validate Pod identity detection from Kubernetes downward API

## 5. API Endpoints for Leader and Replica Status

- [x] 5.1 Create `/api/v1/leader/status` endpoint
- [x] 5.2 Implement leader status response (identity, lease duration, renew time, transitions)
- [x] 5.3 Create `/api/v1/replicas/self` endpoint
- [x] 5.4 Implement local replica status response (identity, is_leader, uptime)
- [x] 5.5 Create `/api/v1/cluster/mode` endpoint
- [x] 5.6 Implement cluster mode response (mode, replica_count, feature_flags)
- [x] 5.7 Create `/api/v1/tasks` endpoint for task list
- [x] 5.8 Implement task list response (name, scope, last_execution, status)
- [x] 5.9 Add authentication to all new endpoints
- [x] 5.10 Add leader-only task manual trigger endpoint
- [x] 5.11 Update health endpoint to include replica_mode in metadata
- [x] 5.12 Create `/api/cluster/status` endpoint for deployment mode and leader info
- [x] 5.13 Implement cluster status UI in settings page (`/settings/cluster-status`)
- [x] 5.14 Add cluster status auto-refresh in UI (10 second interval)

## 6. Observability and Metrics

- [x] 6.1 Add `kubedash_leader_election_is_leader` gauge metric
- [x] 6.2 Add `kubedash_leader_election_transitions_total` counter metric
- [x] 6.3 Add `kubedash_leader_election_renewals_total` counter metric
- [x] 6.4 Add `kubedash_session_operations_total` counter metric (labels: operation)
- [x] 6.5 Add `kubedash_session_redis_errors_total` counter metric
- [x] 6.6 Add `kubedash_leader_tasks_executed_total` counter metric (labels: task_name)
- [x] 6.7 Add `kubedash_leader_task_duration_seconds` histogram metric
- [x] 6.8 Add `kubedash_leader_tasks_skipped_total` counter metric
- [x] 6.9 Add `kubedash_replica_mode_info` gauge metric
- [x] 6.10 Add `kubedash_replica_desired` gauge metric
- [x] 6.11 Update Prometheus metrics documentation
- [x] 6.12 Add leader election log events (acquisition, loss, renewal)
- [x] 6.13 Add structured logging for leader election with trace IDs

## 7. RBAC and Kubernetes Manifests

- [x] 7.1 Create Role manifest for leader election (leases get/create/update)
- [x] 7.2 Create RoleBinding manifest for leader election
- [x] 7.3 Update Helm chart templates with leader election RBAC
- [x] 7.4 Add downward API env vars (POD_NAME, POD_NAMESPACE) to deployment
- [x] 7.5 Update Helm chart with leader election configuration values
- [x] 7.6 Add `leaderElection` section to values.yaml
- [x] 7.7 Add `replicas.mode` configuration to values.yaml
- [x] 7.8 Update Helm chart validation for replica mode requirements
- [x] 7.9 Add HorizontalPodAutoscaler template for auto-scaling
- [x] 7.10 Add PodDisruptionBudget template for HA
- [x] 7.11 Update Helm chart README with replica mode documentation

## 8. Helm Chart Updates

- [x] 8.1 Make Redis required for `replicas > 1`
- [x] 8.2 Add Redis HA configuration options (sentinel, cluster)
- [x] 8.3 Update replicas default to 1 with clear upgrade path
- [x] 8.4 Add `replicaCount` validation in Helm templates
- [x] 8.5 Add Redis session configuration environment variables
- [x] 8.6 Add leader election environment variables
- [x] 8.7 Update ConfigMap with new configuration options
- [x] 8.8 Add Helm lint rules for replica mode validation
- [x] 8.9 Update values.yaml with comprehensive replica mode examples
- [x] 8.10 Add NOTES.txt guidance for multi-replica deployment
- [x] 8.11 Grafana dashboard for replication
- [x] 8.12 Alert for replication

## 9. Database and Migration Considerations

- [x] 9.1 Document PostgreSQL recommendation for multi-replica
- [x] 9.2 Add database mode validation (SQLite single-replica only)
- [x] 9.3 Create migration guide from SQLite to PostgreSQL
- [x] 9.4 Add database connection pool tuning for multi-replica
- [x] 9.5 Update database configuration documentation
- [x] 9.6 Add database health check for multi-replica mode

## 10. Graceful Shutdown and Lifecycle

- [x] 10.1 Implement SIGTERM signal handler
- [x] 10.2 Add leadership release on shutdown
- [x] 10.3 Implement graceful APScheduler shutdown
- [x] 10.4 Add session cleanup on shutdown
- [x] 10.5 Update container lifecycle hooks in Helm chart
- [x] 10.6 Add preStop hook for graceful leadership release
- [x] 10.7 Update terminationGracePeriodSeconds in Helm chart
- [x] 10.8 Test shutdown behavior with leader pod

## 11. Testing

- [x] 11.1 Write unit tests for LeaderElector class
- [x] 11.2 Write unit tests for leader_only decorator
- [x] 11.3 Write unit tests for session backend configuration
- [x] 11.4 Write integration tests for leader election with mock Kubernetes API
- [x] 11.5 Write integration tests for Redis session sharing
- [x] 11.6 Write E2E tests for multi-replica deployment (2+ pods)
- [x] 11.7 Test leader failover (kill leader pod, verify election)
- [x] 11.8 Test session sharing across replicas
- [x] 11.9 Test leader-only task execution (only on leader)
- [x] 11.10 Test graceful shutdown and leadership release
- [x] 11.11 Test Helm chart with replicas > 1
- [x] 11.12 Test RBAC permissions for leader election
- [x] 11.13 Performance test Redis session backend under load
- [x] 11.14 Test split-brain prevention (network partition simulation)
- [x] 11.15 Write multi-replica mode integration tests
- [x] 11.16 Test cluster status endpoint (`/api/cluster/status`)
- [x] 11.17 Test single-replica always reports as_leader=true
- [x] 11.18 Test cluster status UI in settings page

## 12. Documentation

- [x] 12.1 Update installation guide with multi-replica section
- [x] 12.2 Create multi-replica deployment guide
- [x] 12.3 Document replica mode configuration (single vs. cluster)
- [x] 12.4 Document Redis session backend configuration
- [x] 12.5 Document leader election configuration and tuning
- [x] 12.6 Create migration guide from single to multi-replica
- [x] 12.7 Update Helm chart README with replica examples
- [x] 12.8 Add troubleshooting guide for leader election issues
- [x] 12.9 Add FAQ for multi-replica deployments
- [x] 12.10 Update architecture diagrams with multi-replica flow
- [x] 12.11 Document observability (metrics, logs, dashboards)
- [x] 12.12 Add runbook for leader election troubleshooting

## 13. Deployment and Operations

- [x] 13.1 Create staging environment for multi-replica testing
- [x] 13.2 Test upgrade path from single to multi-replica
- [x] 13.3 Document rollback procedure (multi to single)
- [x] 13.4 Create monitoring dashboard for leader election (Grafana)
- [x] 13.5 Create alerting rules for leader election failures
- [x] 13.6 Document HPA configuration for auto-scaling
- [x] 13.7 Document PDB configuration for HA
- [x] 13.8 Test Redis HA configuration
- [x] 13.9 Document PostgreSQL HA recommendation
- [x] 13.10 Create operational runbook for multi-replica deployments
- [x] 13.11 Add leader election to incident response procedures
- [x] 13.12 Test and document backup/restore for multi-replica setup

## 14. Development and Local Testing

- [x] 14.1 Add multi-replica startup option to src/kubedash/run.sh (REPLICAS env variable)
- [x] 14.2 Support multiple gunicorn processes per replica for local testing
- [x] 14.3 Auto-configure REPLICA_MODE=cluster when REPLICAS > 1
- [x] 14.4 Auto-validate PostgreSQL requirement in multi-replica mode
- [x] 14.5 Auto-warn if Redis is not configured in multi-replica mode
- [x] 14.6 Set unique pod names (kubedash-0, kubedash-1, etc.) for local replicas
- [x] 14.7 Disable Flask auto-reload in multi-replica mode for stability
