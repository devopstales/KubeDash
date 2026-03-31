## ADDED Requirements

### Requirement: Cost Optimization Plugin Infrastructure

The system SHALL provide a Cost Optimization plugin that integrates with the KubeDash plugin architecture. The plugin SHALL register a Flask blueprint at `/plugins/cost-optimization` for UI routes and an API blueprint at `/api/v1/plugins/cost-optimization/` for REST endpoints. The plugin SHALL be enabled/disabled via the `[plugin_settings]` section in `kubedash.ini`. The plugin SHALL use OpenCost/Kubecost API for cost data retrieval.

#### Scenario: Plugin discovery and registration
- **WHEN** KubeDash starts and the plugin directory exists
- **THEN** the plugin SHALL be discovered and registered if `cost_optimization = true` in configuration

#### Scenario: Plugin disabled via configuration
- **WHEN** `cost_optimization = false` in `[plugin_settings]`
- **THEN** the plugin SHALL NOT register any routes or appear in navigation

#### Scenario: Cost backend not available
- **WHEN** OpenCost/Kubecost API is unreachable
- **THEN** the plugin SHALL display a friendly message with setup instructions
- **AND** the plugin SHALL NOT attempt to fetch cost data

### Requirement: OpenCost/Kubecost API Client

The plugin SHALL implement an API client that supports both OpenCost and Kubecost endpoints. The client SHALL detect the backend type via feature detection (Kubecost-specific endpoints). The client SHALL support authentication via API key (optional, for Kubecost Enterprise). The client SHALL implement connection timeout (10s) and retry logic (3 attempts with exponential backoff).

#### Scenario: Detect OpenCost backend
- **WHEN** API client connects to OpenCost
- **THEN** the client SHALL detect OpenCost via `/allocation/summary` endpoint availability

#### Scenario: Detect Kubecost backend
- **WHEN** API client connects to Kubecost
- **THEN** the client SHALL detect Kubecost via `/recommendations` endpoint availability

#### Scenario: API key authentication
- **WHEN** API key is configured
- **THEN** the client SHALL include `Authorization: Bearer <key>` header in all requests

#### Scenario: Connection timeout
- **WHEN** cost backend does not respond within 10 seconds
- **THEN** the client SHALL retry up to 3 times with exponential backoff

### Requirement: Cost Data Caching

The plugin SHALL implement two-tier caching for cost data: in-memory cache (60s TTL) for recent queries, Redis cache (5min TTL) for aggregated data. Cache keys SHALL include namespace and time range parameters. The cache SHALL be invalidated when time range changes. Cache misses SHALL trigger background refresh.

#### Scenario: In-memory cache hit
- **WHEN** same cost query is made within 60 seconds
- **THEN** the system SHALL return cached data without API call

#### Scenario: Redis cache for aggregated data
- **WHEN** daily cost totals are requested
- **THEN** the system SHALL cache results in Redis for 5 minutes

#### Scenario: Cache key includes parameters
- **WHEN** different namespaces are queried
- **THEN** each namespace SHALL have separate cache entry

### Requirement: Cost Resource List Views

The plugin SHALL provide list views for cost data with sortable columns, namespace filtering, and time range selection. The list views SHALL use DataTables with server-side pagination. Each row SHALL show: resource name, namespace, CPU cost, memory cost, storage cost, total cost, and efficiency score.

#### Scenario: View cost by namespace
- **WHEN** user navigates to `/plugins/cost-optimization/namespaces`
- **THEN** the system SHALL display all namespaces with cost breakdown in sortable table

#### Scenario: Filter by time range
- **WHEN** user selects "7d" time range
- **THEN** the cost data SHALL update to show only past 7 days

#### Scenario: Sort by total cost
- **WHEN** user clicks "Total Cost" column header
- **THEN** the table SHALL sort descending by cost

### Requirement: Cost Detail Views

The plugin SHALL provide detail views for individual resources (namespace, deployment, pod) showing cost breakdown by component (CPU, memory, storage), historical cost trend, and efficiency metrics. The detail view SHALL use tabs: Overview, Cost Breakdown, Trend, Recommendations.

#### Scenario: View namespace cost details
- **WHEN** user clicks on a namespace name
- **THEN** the system SHALL navigate to detail view showing all tabs

#### Scenario: View cost breakdown by component
- **WHEN** user clicks "Cost Breakdown" tab
- **THEN** the system SHALL display donut chart with CPU/memory/storage cost distribution

#### Scenario: View historical trend
- **WHEN** user clicks "Trend" tab
- **THEN** the system SHALL show line chart with daily cost over selected time range
