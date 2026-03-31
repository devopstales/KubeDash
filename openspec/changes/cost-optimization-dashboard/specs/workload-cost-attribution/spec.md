## ADDED Requirements

### Requirement: Deployment Cost Breakdown

The system SHALL display cost breakdown per Deployment with columns: Deployment Name, Namespace, Replicas, CPU Cost, Memory Cost, Storage Cost, Total Cost, Cost per Replica. The list SHALL be sortable by any cost column. Clicking a deployment SHALL navigate to detailed cost view with pod-level breakdown.

#### Scenario: View deployment cost list
- **WHEN** user navigates to `/plugins/cost-optimization/deployments`
- **THEN** the system SHALL display all deployments with cost breakdown in sortable table

#### Scenario: Sort by total cost
- **WHEN** user clicks "Total Cost" header
- **THEN** the table SHALL sort deployments descending by total cost

#### Scenario: Navigate to pod-level detail
- **WHEN** user clicks on a deployment name
- **THEN** the system SHALL navigate to detail view showing cost per pod

### Requirement: Pod-Level Cost Attribution

The system SHALL display cost breakdown per Pod within a deployment showing: Pod Name, Node, CPU Request vs Usage, Memory Request vs Usage, CPU Cost, Memory Cost, Total Cost, Efficiency Score. The view SHALL highlight pods with efficiency < 50% in yellow.

#### Scenario: View pod cost breakdown
- **WHEN** user views deployment detail
- **THEN** the system SHALL show table with cost per pod

#### Scenario: Highlight inefficient pods
- **WHEN** a pod has efficiency score < 50%
- **THEN** the row SHALL show yellow background with efficiency warning icon

#### Scenario: Show request vs usage
- **WHEN** user views pod detail
- **THEN** the system SHALL show bar chart comparing requested vs actual CPU/memory usage

### Requirement: Container-Level Cost Allocation

The system SHALL display cost breakdown per Container within a pod showing: Container Name, Image, CPU Request/Limit/Usage, Memory Request/Limit/Usage, CPU Cost, Memory Cost, Total Cost. The view SHALL support multi-container pods (sidecars, init containers).

#### Scenario: View container cost breakdown
- **WHEN** user clicks on a pod name
- **THEN** the system SHALL show cost allocation per container

#### Scenario: Multi-container pod support
- **WHEN** pod has multiple containers
- **THEN** each container SHALL show separate cost breakdown

#### Scenario: Show cost per resource
- **WHEN** user views container detail
- **THEN** the system SHALL show CPU cost and memory cost separately

### Requirement: Historical Cost Tracking per Workload

The system SHALL track historical cost data per workload (deployment, statefulset, daemonset) with daily granularity. The historical data SHALL be retained for 90 days. The system SHALL display cost trend chart for selected workload with 7d/30d/90d time ranges.

#### Scenario: View deployment cost history
- **WHEN** user views deployment detail and selects "30d" range
- **THEN** the system SHALL show line chart with daily cost for past 30 days

#### Scenario: Compare workload cost over time
- **WHEN** user enables comparison
- **THEN** the system SHALL show current period vs previous period on same chart

#### Scenario: 90-day data retention
- **WHEN** user requests 90d historical data
- **THEN** the system SHALL return data up to 90 days old

### Requirement: Cost Aggregation by Label

The system SHALL support cost aggregation by Kubernetes labels (e.g., `app`, `team`, `environment`). The user SHALL select a label key, and the system SHALL group costs by label values. This enables cost allocation by team, project, or environment.

#### Scenario: Aggregate cost by team label
- **WHEN** user selects "team" as aggregation label
- **THEN** the system SHALL show cost grouped by team label values

#### Scenario: Multi-label aggregation
- **WHEN** user selects multiple labels (team, environment)
- **THEN** the system SHALL show nested grouping (team -> environment)

#### Scenario: Label not present handling
- **WHEN** resources don't have the selected label
- **THEN** the system SHALL group them as "Uncategorized"

### Requirement: Workload Cost Export

The system SHALL provide export functionality for workload cost data in CSV and PDF formats. CSV export SHALL include all columns visible in the table. PDF export SHALL generate formatted report with summary, charts, and detailed breakdown.

#### Scenario: Export deployment costs to CSV
- **WHEN** user clicks "Export CSV" on deployments view
- **THEN** the system SHALL download CSV with all deployment cost data

#### Scenario: Export detailed PDF report
- **WHEN** user clicks "Export PDF" on deployment detail
- **THEN** the system SHALL generate PDF with cost breakdown and trend charts

#### Scenario: Export respects current filters
- **WHEN** user has namespace filter active and clicks "Export"
- **THEN** the export SHALL include only filtered data
