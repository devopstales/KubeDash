## ADDED Requirements

### Requirement: PolicyReport List View

The system SHALL display a list of PolicyReport and ClusterPolicyReport resources with columns: Name, Namespace (or Cluster-wide), Scope (policies evaluated), Pass, Fail, Warn, Skip, Last Updated. The list SHALL support filtering by namespace, policy name, and status (has failures). The list SHALL default to showing reports with failures first.

#### Scenario: View PolicyReport list
- **WHEN** user navigates to `/plugins/kyverno/reports`
- **THEN** the system SHALL display all PolicyReports in sortable table

#### Scenario: Filter by namespace
- **WHEN** user selects namespace from dropdown
- **THEN** the list SHALL show only reports in that namespace

#### Scenario: Filter to reports with failures
- **WHEN** user checks "Show failures only"
- **THEN** the list SHALL show only reports where fail > 0

### Requirement: PolicyReport Detail View

The system SHALL provide detail view for individual PolicyReport showing summary statistics (pass/fail/warn/skip counts as donut chart), list of policies evaluated, and list of failed resources with violation messages. The detail view SHALL group results by policy name with expandable sections showing affected resources.

#### Scenario: View report summary
- **WHEN** user opens PolicyReport detail
- **THEN** the system SHALL show donut chart with pass/fail/warn/skip distribution

#### Scenario: View policies evaluated
- **WHEN** user clicks "Policies" tab
- **THEN** the system SHALL list all policies in the report with per-policy results

#### Scenario: View failed resources
- **WHEN** user clicks "Failed Resources" tab
- **THEN** the system SHALL show table of resources with violations, policy name, and message

### Requirement: Resource-Level Violation Drill-Down

The system SHALL allow drilling down from PolicyReport to individual resource violations. Clicking a failed resource SHALL navigate to the resource detail view (if built-in K8s resource) or show resource YAML in modal. The violation message SHALL include the policy rule name and validation failure message.

#### Scenario: View failed resource details
- **WHEN** user clicks on a failed resource name
- **THEN** the system SHALL show resource YAML with violation message overlay

#### Scenario: Navigate to built-in resource
- **WHEN** user clicks "View Resource" for a Pod
- **THEN** the system SHALL navigate to `/workload/pods/<namespace>/<name>`

#### Scenario: View violation message
- **WHEN** user hovers over violation icon
- **THEN** the system SHALL show tooltip with full validation failure message

### Requirement: PolicyReport Export

The system SHALL provide export functionality for PolicyReport data in CSV and PDF formats. CSV export SHALL include all results with columns: Resource Name, Namespace, Policy Name, Rule Name, Status, Message, Category, Severity. PDF export SHALL generate formatted report with executive summary, charts, and violation list.

#### Scenario: Export to CSV
- **WHEN** user clicks "Export CSV"
- **THEN** the system SHALL download CSV file with all report results

#### Scenario: Export to PDF
- **WHEN** user clicks "Export PDF"
- **THEN** the system SHALL generate and download PDF report with summary and violations

#### Scenario: Export filtered results
- **WHEN** user has active filters and clicks "Export"
- **THEN** the system SHALL export only filtered results (not all)

### Requirement: Historical Trend Analysis

The system SHALL show historical trend of PolicyReport results over time using line chart with pass/fail/warn counts. The trend SHALL support 7d/30d/90d time ranges. The trend SHALL update when namespace filter changes. Historical data SHALL be sourced from PolicyReport `results` timestamps aggregated daily.

#### Scenario: View 30-day trend
- **WHEN** user selects "30d" time range
- **THEN** the system SHALL show line chart with daily pass/fail/warn counts for 30 days

#### Scenario: Compare time periods
- **WHEN** user enables "Compare with previous period"
- **THEN** the system SHALL show dashed line for previous period on same chart

### Requirement: PolicyReport Aggregation by Category

The system SHALL aggregate PolicyReport results by policy category (from `kyverno.io/category` label). The aggregation SHALL show total resources evaluated, pass rate, and failure count per category. Categories SHALL be displayed as horizontal bar chart sorted by failure count descending.

#### Scenario: View results by category
- **WHEN** user views reports list
- **THEN** the system SHALL show bar chart with failure counts grouped by category

#### Scenario: Filter by category
- **WHEN** user clicks on a category bar
- **THEN** the reports list SHALL filter to show only policies in that category
