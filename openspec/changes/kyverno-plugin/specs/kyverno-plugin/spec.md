## ADDED Requirements

### Requirement: Kyverno Plugin Infrastructure

The system SHALL provide a Kyverno plugin that integrates with the KubeDash plugin architecture. The plugin SHALL register a Flask blueprint at `/plugins/kyverno` for UI routes and an API blueprint at `/api/v1/plugins/kyverno/` for REST endpoints. The plugin SHALL be enabled/disabled via the `[plugin_settings]` section in `kubedash.ini`. The plugin SHALL use the existing Kubernetes client infrastructure (CustomObjectsApi) to access Kyverno CRDs.

#### Scenario: Plugin discovery and registration
- **WHEN** KubeDash starts and the plugin directory exists
- **THEN** the plugin SHALL be discovered and registered if `kyverno = true` in configuration

#### Scenario: Plugin disabled via configuration
- **WHEN** `kyverno = false` in `[plugin_settings]`
- **THEN** the plugin SHALL NOT register any routes or appear in navigation

#### Scenario: Kyverno CRDs not present
- **WHEN** Kyverno is not installed in the cluster (CRDs missing)
- **THEN** the plugin SHALL display a friendly message offering installation instructions
- **AND** the plugin SHALL NOT attempt to fetch Kyverno resources

### Requirement: Kyverno CRD Client Wrappers

The plugin SHALL implement K8s client wrapper functions for all Kyverno resources: ClusterPolicy, Policy, PolicyException, ClusterPolicyReport, and PolicyReport. The wrappers SHALL use CustomObjectsApi with proper error handling for 404 (CRD not found), 403 (permission denied), and timeout scenarios. The wrappers SHALL support namespace-scoped and cluster-scoped resource fetching.

#### Scenario: Fetch ClusterPolicy list
- **WHEN** user requests cluster-wide policies
- **THEN** the system SHALL call `k8sClusterPolicyListGet()` and return all ClusterPolicy resources

#### Scenario: Fetch Policy list for namespace
- **WHEN** user selects a specific namespace
- **THEN** the system SHALL call `k8sPolicyListGet(namespace)` and return namespaced Policy resources

#### Scenario: CRD not found error
- **WHEN** Kyverno CRDs are not installed
- **THEN** the wrapper SHALL return empty list with warning log (not error)

#### Scenario: Permission denied
- **WHEN** user lacks RBAC permissions for Kyverno resources
- **THEN** the wrapper SHALL return 403 error with message "Insufficient permissions to view policies"

### Requirement: Kyverno Resource List Views

The plugin SHALL provide list views for each Kyverno resource type with sortable columns, namespace filtering, search by name, and status indicators (Ready, Error, Suspended). The list views SHALL use DataTables with server-side pagination for performance. Each row SHALL show key metadata: name, namespace (if applicable), status, creation timestamp, and rule count.

#### Scenario: View ClusterPolicy list
- **WHEN** user navigates to `/plugins/kyverno/cluster-policies`
- **THEN** the system SHALL display all ClusterPolicies in a sortable table

#### Scenario: Filter by namespace
- **WHEN** user selects namespace from dropdown
- **THEN** the Policy list SHALL update to show only policies in that namespace

#### Scenario: Search by name
- **WHEN** user types in search box
- **THEN** the list SHALL filter to show only matching resources (client-side for current page)

#### Scenario: Status indicator display
- **WHEN** a policy has Ready=True condition
- **THEN** the status column SHALL show green checkmark with "Ready" tooltip

### Requirement: Kyverno Resource Detail Views

The plugin SHALL provide detail views for each Kyverno resource showing full YAML, conditions, rules, and related resources. The detail view SHALL use tabs: Overview, Rules, YAML, and Related (for policies: violations; for reports: failed resources). The YAML viewer SHALL use Monaco editor with syntax highlighting and read-only mode for non-Admin users.

#### Scenario: View ClusterPolicy details
- **WHEN** user clicks on a ClusterPolicy name
- **THEN** the system SHALL navigate to detail view showing all tabs

#### Scenario: View policy rules
- **WHEN** user clicks "Rules" tab
- **THEN** the system SHALL display each rule with match/exclude conditions and validation/mutation/generation spec

#### Scenario: View YAML source
- **WHEN** user clicks "YAML" tab
- **THEN** the system SHALL show full resource YAML in Monaco editor (read-only for Users)

#### Scenario: View policy violations
- **WHEN** user clicks "Violations" tab on a Policy detail
- **THEN** the system SHALL show resources violating this policy (from PolicyReport)
