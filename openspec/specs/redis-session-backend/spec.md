## ADDED Requirements

### Requirement: System supports Redis-backed session storage
The system SHALL allow Flask-Session to use Redis as the session backend for multi-replica deployments.

#### Scenario: Redis session backend enabled
- **WHEN** `SESSION_TYPE=redis` and Redis is available
- **THEN** system stores all user sessions in Redis with configurable TTL

#### Scenario: Session shared across replicas
- **WHEN** user logs in via replica A and makes next request to replica B
- **THEN** replica B retrieves session from Redis and user remains authenticated

#### Scenario: Session key prefix isolation
- **WHEN** system stores session in Redis
- **THEN** keys use prefix `kubedash:session:<session_id>` for namespace isolation

#### Scenario: Session TTL configuration
- **WHEN** session created or accessed
- **THEN** Redis TTL set to `PERMANENT_SESSION_LIFETIME` (default 31 days)

#### Scenario: Redis connection failure fallback
- **WHEN** Redis unavailable and `SESSION_TYPE=redis`
- **THEN** system logs error and falls back to in-memory sessions with warning

### Requirement: System maintains backward compatibility with SQLAlchemy sessions
The system SHALL support SQLAlchemy-backed sessions for single-replica deployments.

#### Scenario: SQLAlchemy session backend default
- **WHEN** `SESSION_TYPE` not specified
- **THEN** system defaults to `sqlalchemy` backend using main database

#### Scenario: Single-replica deployment works without Redis
- **WHEN** `replicas.mode=single` and Redis not configured
- **THEN** system operates normally with SQLAlchemy sessions

#### Scenario: Session backend logged on startup
- **WHEN** application initializes
- **THEN** logs show "Session backend: redis" or "Session backend: sqlalchemy"

### Requirement: System validates Redis configuration for cluster mode
The system SHALL validate Redis connectivity before allowing cluster mode operation.

#### Scenario: Redis connectivity check on startup
- **WHEN** `replicas.mode=cluster` and Redis configured
- **THEN** system pings Redis and validates connection before accepting traffic

#### Scenario: Cluster mode without Redis rejected
- **WHEN** `replicas.mode=cluster` but Redis not configured
- **THEN** system fails startup with error "Cluster mode requires Redis configuration"

#### Scenario: Redis health check
- **WHEN** Redis backend enabled
- **THEN** system periodically checks Redis connectivity and logs warnings on failure

### Requirement: System provides session metrics for Redis backend
The system SHALL expose observability metrics for Redis session operations.

#### Scenario: Session read metric
- **WHEN** session retrieved from Redis
- **THEN** system increments `kubedash_session_operations_total{operation="get"}` counter

#### Scenario: Session write metric
- **WHEN** session saved to Redis
- **THEN** system increments `kubedash_session_operations_total{operation="set"}` counter

#### Scenario: Session Redis error metric
- **WHEN** Redis operation fails
- **THEN** system increments `kubedash_session_redis_errors_total` counter

#### Scenario: Redis connection pool metric
- **WHEN** Redis connection pool used
- **THEN** system exposes `kubedash_redis_pool_size` gauge for active connections

### Requirement: System supports Redis connection configuration
The system SHALL allow configuration of Redis connection parameters.

#### Scenario: Redis host and port configuration
- **WHEN** `REDIS_HOST` and `REDIS_PORT` environment variables set
- **THEN** system connects to specified Redis instance

#### Scenario: Redis password authentication
- **WHEN** `REDIS_PASSWORD` environment variable set
- **THEN** system authenticates to Redis using provided password

#### Scenario: Redis database selection
- **WHEN** `REDIS_DB` environment variable set
- **THEN** system uses specified Redis database number (default 0)

#### Scenario: Redis SSL/TLS support
- **WHEN** `REDIS_SSL=true` environment variable set
- **THEN** system connects to Redis using SSL/TLS

### Requirement: System handles session migration gracefully
The system SHALL support migration from SQLAlchemy to Redis sessions.

#### Scenario: Dual-session support during migration
- **WHEN** migration mode enabled
- **THEN** system writes to both backends and reads from Redis with SQLAlchemy fallback

#### Scenario: Session backend switch requires re-login
- **WHEN** session backend changes from sqlalchemy to redis
- **THEN** existing sessions invalidated and users must re-login

#### Scenario: Migration documentation provided
- **WHEN** upgrading to multi-replica mode
- **THEN** documentation includes session migration steps and re-login notice
