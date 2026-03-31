## ADDED Requirements

### Requirement: Admin can register new cluster
The system SHALL allow administrators to register new Kubernetes clusters with connection details including API server URL, CA certificate, and optional kubeconfig context.

#### Scenario: Successful cluster registration
- **WHEN** admin provides valid cluster name, API server URL, and CA certificate
- **THEN** system creates cluster entry with status "unknown" and initiates health check

#### Scenario: Duplicate cluster name rejection
- **WHEN** admin attempts to register cluster with existing name
- **THEN** system rejects request with error "Cluster with name '{name}' already exists"

#### Scenario: Invalid API server URL rejection
- **WHEN** admin provides malformed or unreachable API server URL
- **THEN** system rejects request with error "Invalid API server URL" and does not create cluster entry

#### Scenario: CA certificate validation
- **WHEN** admin provides invalid CA certificate format
- **THEN** system rejects request with error "Invalid CA certificate format"

#### Scenario: Connection test on registration
- **WHEN** admin registers new cluster
- **THEN** system attempts connection test and updates health status accordingly

### Requirement: Admin can update cluster configuration
The system SHALL allow administrators to modify registered cluster configurations including API server URL, CA certificate, and activation status.

#### Scenario: Successful cluster update
- **WHEN** admin updates cluster API server URL
- **THEN** system updates configuration and re-runs health check

#### Scenario: Cluster deactivation
- **WHEN** admin sets cluster `is_active` to false
- **THEN** system marks cluster as inactive and excludes from cluster switcher

#### Scenario: Default cluster change
- **WHEN** admin sets a cluster as default
- **THEN** system sets previous default to non-default and new cluster as default

### Requirement: Admin can delete cluster
The system SHALL allow administrators to delete registered clusters with appropriate safeguards.

#### Scenario: Successful cluster deletion
- **WHEN** admin deletes cluster with no associated user roles
- **THEN** system removes cluster from registry

#### Scenario: Cluster deletion with user roles
- **WHEN** admin attempts to delete cluster with existing user_cluster_roles
- **THEN** system rejects deletion with error "Cannot delete cluster with associated user roles" and suggests removing roles first

#### Scenario: Last cluster deletion prevention
- **WHEN** admin attempts to delete the last active cluster
- **THEN** system rejects deletion with error "Cannot delete last active cluster"

### Requirement: System validates cluster connectivity
The system SHALL validate cluster connectivity before allowing operations.

#### Scenario: Connection test success
- **WHEN** system tests connection to healthy cluster
- **THEN** system receives valid Kubernetes API response and updates health status to "healthy"

#### Scenario: Connection test failure - unreachable
- **WHEN** system tests connection to unreachable cluster
- **THEN** system times out and updates health status to "unreachable"

#### Scenario: Connection test failure - auth error
- **WHEN** system tests connection with invalid credentials
- **THEN** system receives 401/403 response and updates health status to "unhealthy"

### Requirement: System stores cluster metadata
The system SHALL automatically discover and store cluster metadata upon successful connection.

#### Scenario: Kubernetes version discovery
- **WHEN** system successfully connects to cluster
- **THEN** system queries `/version` endpoint and stores gitVersion, platform, goVersion

#### Scenario: Node count discovery
- **WHEN** system successfully connects to cluster
- **THEN** system queries `/api/v1/nodes` and stores node count

#### Scenario: Namespace count discovery
- **WHEN** system successfully connects to cluster
- **THEN** system queries `/api/v1/namespaces` and stores namespace count

### Requirement: System supports multiple connection types
The system SHALL support different cluster connection methods.

#### Scenario: Direct connection type
- **WHEN** cluster configured with `connection_type='direct'`
- **THEN** system connects directly to API server using provided URL and CA

#### Scenario: In-cluster connection type
- **WHEN** cluster configured with `connection_type='in-cluster'`
- **THEN** system uses Kubernetes service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`

#### Scenario: Kubeconfig context connection type
- **WHEN** cluster configured with `connection_type='kubeconfig'` and `kubeconfig_context`
- **THEN** system loads kubeconfig file and uses specified context
