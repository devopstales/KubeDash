## ADDED Requirements

### Requirement: System provides decorator for leader-only task marking
The system SHALL provide a Python decorator to mark tasks as leader-only.

#### Scenario: Leader-only decorator application
- **WHEN** developer applies `@leader_only` decorator to function
- **THEN** function only executes when replica is current leader

#### Scenario: Leader-only task skipped on follower
- **WHEN** follower replica attempts to run leader-only task
- **THEN** task skipped with debug log "Skipping leader-only task on follower replica"

#### Scenario: Leader-only task executes on leader
- **WHEN** leader replica runs leader-only task
- **THEN** task executes normally

#### Scenario: Decorator with custom error handling
- **WHEN** leader-only task raises exception
- **THEN** exception logged and does not affect leader election status

### Requirement: System categorizes background tasks by execution scope
The system SHALL classify all background tasks as leader-only or all-replica.

#### Scenario: Cluster health checks marked leader-only
- **WHEN** cluster health check scheduler runs
- **THEN** only leader replica executes health checks against Kubernetes API

#### Scenario: Cache cleanup marked all-replica
- **WHEN** local cache cleanup task runs
- **THEN** all replicas execute cleanup for their local cache

#### Scenario: Session cleanup marked leader-only
- **WHEN** expired session cleanup task runs
- **THEN** only leader replica executes cleanup to prevent duplicate work

#### Scenario: Metrics collection marked all-replica
- **WHEN** Prometheus metrics endpoint scraped
- **THEN** all replicas collect and expose their own metrics

### Requirement: System provides task registration framework
The system SHALL provide framework for registering and categorizing scheduled tasks.

#### Scenario: Task registration with scope
- **WHEN** task registered with `@scheduled_task(scope='leader')`
- **THEN** system tracks task scope and executes accordingly

#### Scenario: Task list exposure
- **WHEN** admin queries `/api/v1/tasks`
- **THEN** system returns list of all registered tasks with scope and last execution time

#### Scenario: Task execution history
- **WHEN** task completes execution
- **THEN** system logs execution time, duration, and result (success/failure)

### Requirement: System handles leader transition for running tasks
The system SHALL handle task execution during leader transitions.

#### Scenario: Task interruption on leader loss
- **WHEN** leader loses leadership while task running
- **THEN** task completes current execution but not scheduled again on this replica

#### Scenario: New leader starts tasks
- **WHEN** new leader elected
- **THEN** new leader starts executing leader-only tasks within one scheduling interval

#### Scenario: Task double-execution prevention
- **WHEN** leader transition occurs during task execution
- **THEN** system ensures task not executed simultaneously on old and new leader

### Requirement: System provides leader-only task observability
The system SHALL expose metrics for leader-only task execution.

#### Scenario: Leader-only task execution metric
- **WHEN** leader-only task executes
- **THEN** system increments `kubedash_leader_tasks_executed_total{task_name="..."}` counter

#### Scenario: Leader-only task duration metric
- **WHEN** leader-only task completes
- **THEN** system records `kubedash_leader_task_duration_seconds{task_name="..."}` histogram

#### Scenario: Leader-only task error metric
- **WHEN** leader-only task fails
- **THEN** system increments `kubedash_leader_task_errors_total{task_name="..."}` counter

#### Scenario: Skipped task metric on follower
- **WHEN** follower skips leader-only task
- **THEN** system increments `kubedash_leader_tasks_skipped_total` counter

### Requirement: System validates leader-only task configuration
The system SHALL validate that leader-only tasks are properly configured.

#### Scenario: Leader-only task without leader election
- **WHEN** leader-only task registered but `LEADER_ELECTION_ENABLED=false`
- **THEN** system logs warning "Leader-only task registered but leader election disabled"

#### Scenario: All-replica task count validation
- **WHEN** all-replica task registered
- **THEN** system logs task count per replica for monitoring

#### Scenario: Task scope documentation
- **WHEN** task registered
- **THEN** documentation includes task scope (leader vs. all-replica)

### Requirement: System provides manual task trigger for admins
The system SHALL allow administrators to manually trigger leader-only tasks.

#### Scenario: Manual trigger for leader-only task
- **WHEN** admin POSTs to `/api/v1/tasks/{task_name}/trigger`
- **THEN** system executes task immediately if replica is leader

#### Scenario: Manual trigger on follower rejected
- **WHEN** admin triggers leader-only task on follower replica
- **THEN** system returns 409 Conflict with message "Not the leader replica"

#### Scenario: Manual trigger response includes leader identity
- **WHEN** manual trigger requested
- **THEN** response includes current leader identity and suggestion to retry on leader
