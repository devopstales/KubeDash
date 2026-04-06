## ADDED Requirements

### Requirement: System implements Kubernetes Leases-based leader election
The system SHALL use Kubernetes Leases API to elect a single leader replica for coordinated task execution.

#### Scenario: Leader election on startup
- **WHEN** replica starts and `LEADER_ELECTION_ENABLED=true`
- **THEN** replica attempts to acquire lease `kubedash-leader` in pod namespace

#### Scenario: Leader acquires lease
- **WHEN** lease does not exist or is expired
- **THEN** replica creates/updates lease with own identity as `holderIdentity`

#### Scenario: Follower detects existing leader
- **WHEN** lease exists with valid `renewTime` and different `holderIdentity`
- **THEN** replica remains follower and does not attempt to acquire

#### Scenario: Leader renews lease
- **WHEN** replica is current leader
- **THEN** replica renews lease every `retryPeriodSeconds` (default 2s) by updating `renewTime`

#### Scenario: Leader lease expires
- **WHEN** leader fails to renew within `leaseDurationSeconds` (default 15s)
- **THEN** lease considered expired and followers can attempt acquisition

#### Scenario: New leader elected after expiration
- **WHEN** lease expired and follower attempts acquisition
- **THEN** follower becomes new leader, updates `holderIdentity` and increments `leaseTransitions`

### Requirement: System provides leader election configuration
The system SHALL allow configuration of leader election parameters.

#### Scenario: Lease name configuration
- **WHEN** `LEADER_ELECTION_LEASE_NAME` set
- **THEN** system uses specified name (default `kubedash-leader`)

#### Scenario: Lease duration configuration
- **WHEN** `LEADER_ELECTION_LEASE_DURATION` set
- **THEN** system uses specified duration in seconds (default 15)

#### Scenario: Renew deadline configuration
- **WHEN** `LEADER_ELECTION_RENEW_DEADLINE` set
- **THEN** system attempts renewal within specified seconds before expiration (default 10)

#### Scenario: Retry period configuration
- **WHEN** `LEADER_ELECTION_RETRY_PERIOD` set
- **THEN** system retries acquisition every specified seconds (default 2)

### Requirement: System exposes leader identity via pod metadata
The system SHALL use Kubernetes downward API to determine unique leader identity.

#### Scenario: Pod name as identity
- **WHEN** leader election initializes
- **THEN** system reads `POD_NAME` environment variable for unique identity

#### Scenario: Namespace discovery
- **WHEN** leader election initializes
- **THEN** system reads `POD_NAMESPACE` environment variable for lease namespace

#### Scenario: Identity format
- **WHEN** pod name not available
- **THEN** system generates unique identity using hostname and process ID

### Requirement: System provides leader election observability
The system SHALL expose metrics and logs for leader election monitoring.

#### Scenario: Leader status metric
- **WHEN** leader election active
- **THEN** system exposes `kubedash_leader_election_is_leader` gauge (1=leader, 0=follower)

#### Scenario: Leadership transitions metric
- **WHEN** leadership changes
- **THEN** system increments `kubedash_leader_election_transitions_total` counter

#### Scenario: Lease renewal metric
- **WHEN** leader successfully renews lease
- **THEN** system increments `kubedash_leader_election_renewals_total` counter

#### Scenario: Leader acquisition log event
- **WHEN** replica becomes leader
- **THEN** system logs "Acquired leadership" with lease name and identity

#### Scenario: Leader loss log event
- **WHEN** replica loses leadership
- **THEN** system logs "Lost leadership" with lease name and identity

### Requirement: System handles graceful leadership release
The system SHALL release leadership gracefully on shutdown.

#### Scenario: SIGTERM triggers leadership release
- **WHEN** leader receives SIGTERM signal
- **THEN** leader clears `holderIdentity` from lease before shutdown

#### Scenario: Leadership release on crash
- **WHEN** leader crashes without graceful shutdown
- **THEN** lease expires naturally and new leader elected within `leaseDurationSeconds`

#### Scenario: Follower becomes leader on shutdown
- **WHEN** leader shuts down gracefully
- **THEN** one follower acquires lease within `retryPeriodSeconds`

### Requirement: System provides leader election API endpoints
The system SHALL expose HTTP endpoints for leader status inspection.

#### Scenario: Get leader status
- **WHEN** client requests `/api/v1/leader/status`
- **THEN** system returns JSON with leader identity, lease duration, renew time, and transitions count

#### Scenario: Get local replica status
- **WHEN** client requests `/api/v1/replicas/self`
- **THEN** system returns JSON with pod identity, is_leader flag, and uptime

#### Scenario: Leader endpoint requires authentication
- **WHEN** unauthenticated request made to leader endpoint
- **THEN** system returns 401 Unauthorized

### Requirement: System requires RBAC permissions for leader election
The system SHALL document and validate required Kubernetes RBAC permissions.

#### Scenario: Lease get permission
- **WHEN** leader election initializes
- **THEN** system verifies `get` permission on `leases` in `coordination.k8s.io` API group

#### Scenario: Lease create permission
- **WHEN** leader election initializes
- **THEN** system verifies `create` permission on `leases` in `coordination.k8s.io` API group

#### Scenario: Lease update permission
- **WHEN** leader election initializes
- **THEN** system verifies `update` permission on `leases` in `coordination.k8s.io` API group

#### Scenario: Missing RBAC permissions error
- **WHEN** required permissions not granted
- **THEN** system logs error "Missing RBAC permissions for leader election" and disables election

### Requirement: System handles split-brain prevention
The system SHALL guarantee single leader at any time through atomic lease operations.

#### Scenario: Atomic lease update
- **WHEN** multiple followers attempt simultaneous acquisition
- **THEN** Kubernetes API ensures only one succeeds (409 Conflict for others)

#### Scenario: Resource version check
- **WHEN** follower updates lease
- **THEN** system uses `resourceVersion` for optimistic locking

#### Scenario: Lease transition monitoring
- **WHEN** `leaseTransitions` increases unexpectedly
- **THEN** system logs warning about potential network instability

### Requirement: System supports leader election for multiple use cases
The system SHALL support different leader election scopes for different task categories.

#### Scenario: Single lease for all leader-only tasks
- **WHEN** leader election enabled
- **THEN** all leader-only tasks run on same leader replica

#### Scenario: Future: Separate leases for different task types
- **WHEN** configured with multiple lease names
- **THEN** system can elect different leaders for different task categories (future enhancement)
