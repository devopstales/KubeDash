## ADDED Requirements

### Requirement: System performs periodic cluster health checks
The system SHALL automatically check health of all active clusters at regular intervals.

#### Scenario: Scheduled health check execution
- **WHEN** 60 seconds have elapsed since last health check
- **THEN** system runs health check job for all active clusters

#### Scenario: Health check probes Kubernetes API
- **WHEN** system performs health check on cluster
- **THEN** system sends GET request to `/version` endpoint with configured CA certificate

#### Scenario: Health check timeout
- **WHEN** cluster does not respond within 10 seconds
- **THEN** system marks health status as "unreachable" and logs timeout error

#### Scenario: Health check success updates timestamp
- **WHEN** health check receives valid response
- **THEN** system updates `health_status='healthy'` and `last_health_check=NOW()`

#### Scenario: Health check failure updates status
- **WHEN** health check receives error response (4xx, 5xx, timeout)
- **THEN** system updates `health_status` to appropriate error state

### Requirement: System exposes cluster health status via API
The system SHALL provide API endpoints to query cluster health status.

#### Scenario: Get health status for single cluster
- **WHEN** client requests `/api/v1/clusters/{name}/health`
- **THEN** system returns JSON with status, last_check, kubernetes_version, node_count

#### Scenario: Get health status for all clusters
- **WHEN** client requests `/api/v1/clusters/health`
- **THEN** system returns JSON array with health status for all active clusters

#### Scenario: Health status includes metadata
- **WHEN** health status is retrieved
- **THEN** response includes kubernetes_version, platform, node_count, namespace_count

#### Scenario: Health endpoint requires authentication
- **WHEN** unauthenticated request made to health endpoint
- **THEN** system returns 401 Unauthorized

### Requirement: System displays cluster health dashboard
The system SHALL provide a visual dashboard showing health of all clusters.

#### Scenario: Dashboard shows all clusters
- **WHEN** admin navigates to cluster health dashboard
- **THEN** dashboard displays card for each active cluster with health status

#### Scenario: Healthy cluster indicator
- **WHEN** cluster health_status is "healthy"
- **THEN** dashboard shows green status indicator with checkmark

#### Scenario: Unhealthy cluster indicator
- **WHEN** cluster health_status is "unhealthy" or "unreachable"
- **THEN** dashboard shows red status indicator with error icon

#### Scenario: Unknown status indicator
- **WHEN** cluster health_status is "unknown" (never checked)
- **THEN** dashboard shows gray status indicator with question mark

#### Scenario: Cluster card shows details
- **WHEN** cluster card is displayed
- **THEN** card shows API URL, Kubernetes version, node count, last check time

#### Scenario: Stale health check warning
- **WHEN** last_health_check is older than 5 minutes
- **THEN** dashboard shows warning icon with "Health check stale" tooltip

### Requirement: System triggers health check on cluster changes
The system SHALL immediately validate cluster health after configuration changes.

#### Scenario: Health check after cluster creation
- **WHEN** admin creates new cluster
- **THEN** system runs immediate health check before returning success response

#### Scenario: Health check after cluster update
- **WHEN** admin updates cluster API URL or CA certificate
- **THEN** system runs immediate health check with new configuration

#### Scenario: Health check result affects creation response
- **WHEN** new cluster health check fails
- **THEN** system returns warning "Cluster created but unreachable" with health details

### Requirement: System exposes health check metrics
The system SHALL provide observability metrics for health check operations.

#### Scenario: Health check duration metric
- **WHEN** health check completes
- **THEN** system records `kubedash_cluster_health_check_duration_seconds` histogram

#### Scenario: Health check result metric
- **WHEN** health check completes
- **THEN** system increments `kubedash_cluster_health_check_total` counter with status label

#### Scenario: Cluster health gauge
- **WHEN** health check updates status
- **THEN** system sets `kubedash_cluster_health_status` gauge (1=healthy, 0=unhealthy) per cluster

### Requirement: System handles health check scheduler lifecycle
The system SHALL manage health check scheduler startup and shutdown.

#### Scenario: Scheduler starts on application startup
- **WHEN** KubeDash application starts
- **THEN** health check scheduler initializes and runs first check after 10 seconds

#### Scenario: Scheduler handles no active clusters
- **WHEN** no active clusters exist in registry
- **THEN** scheduler skips check cycle without error

#### Scenario: Scheduler continues after individual failure
- **WHEN** health check fails for cluster A
- **THEN** scheduler continues to check cluster B without interruption

#### Scenario: Graceful scheduler shutdown
- **WHEN** application receives SIGTERM
- **THEN** scheduler completes in-flight health checks before shutdown
