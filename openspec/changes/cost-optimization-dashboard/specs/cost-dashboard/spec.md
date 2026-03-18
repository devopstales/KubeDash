## ADDED Requirements

### Requirement: Cluster-Wide Cost Dashboard

The system SHALL display a cluster-wide cost dashboard showing total daily/monthly spend, cost breakdown by namespace (bar chart), cost trend over time (line chart), and efficiency score (gauge). The dashboard SHALL update every 60 seconds via background refresh. The dashboard SHALL support time range selection: 24h, 7d, 30d, 90d.

#### Scenario: Display current daily spend
- **WHEN** user opens cost dashboard
- **THEN** the system SHALL calculate and display current daily cost in USD

#### Scenario: Display monthly projected spend
- **WHEN** user views dashboard
- **THEN** the system SHALL show projected monthly cost based on current daily rate

#### Scenario: Cost breakdown by namespace
- **WHEN** user views dashboard
- **THEN** the system SHALL show horizontal bar chart with cost per namespace, sorted descending

#### Scenario: Background refresh
- **WHEN** 60 seconds have elapsed since last fetch
- **THEN** the system SHALL refresh cost data without user action

### Requirement: Cost Efficiency Score

The system SHALL calculate and display an efficiency score as `(actual_usage / requested_resources) * 100` averaged across all workloads. The score SHALL be shown as a gauge chart with color coding: green (>=70%), yellow (40-69%), red (<40%). The score SHALL be accompanied by a rating: Efficient, Moderate, or Wasteful.

#### Scenario: Display efficiency score
- **WHEN** user views dashboard
- **THEN** the system SHALL show efficiency score as percentage with gauge visualization

#### Scenario: Efficiency score color coding
- **WHEN** efficiency score is >= 70%
- **THEN** the gauge SHALL display in green with "Efficient" rating

#### Scenario: Low efficiency warning
- **WHEN** efficiency score is < 40%
- **THEN** the gauge SHALL display in red with "Wasteful" rating and link to recommendations

### Requirement: Cost Trend Visualization

The system SHALL display cost trend over time using a line chart with daily granularity for 30d+ ranges and hourly granularity for 24h ranges. The chart SHALL show total cost with optional breakdown by namespace (stacked area). The chart SHALL support zoom and pan for detailed analysis.

#### Scenario: Display 7-day cost trend
- **WHEN** user selects "7d" time range
- **THEN** the system SHALL show line chart with daily cost values for past 7 days

#### Scenario: Hourly granularity for 24h
- **WHEN** user selects "24h" time range
- **THEN** the chart SHALL show hourly cost data points

#### Scenario: Stacked area by namespace
- **WHEN** user enables "Show breakdown"
- **THEN** the chart SHALL display stacked area chart with cost per namespace

### Requirement: Namespace Cost Filter

The dashboard SHALL provide namespace filter dropdown with "All Namespaces" as default. Selecting a namespace SHALL filter all dashboard components (totals, charts, efficiency) to that namespace only. The filter SHALL persist in URL for bookmarking and sharing.

#### Scenario: Filter to single namespace
- **WHEN** user selects namespace from dropdown
- **THEN** all dashboard data SHALL update to show only that namespace's costs

#### Scenario: All namespaces view
- **WHEN** user selects "All Namespaces"
- **THEN** the dashboard SHALL show cluster-wide aggregated data

#### Scenario: Filter persists in URL
- **WHEN** user selects a namespace and copies URL
- **THEN** the URL SHALL include namespace parameter for sharing

### Requirement: Cost Comparison with Previous Period

The dashboard SHALL provide option to compare current period cost with previous period (e.g., "This week vs last week"). The comparison SHALL show percentage change with color coding: green (cost decreased), red (cost increased). The trend chart SHALL show both periods as overlapping lines (solid for current, dashed for previous).

#### Scenario: Enable period comparison
- **WHEN** user checks "Compare with previous period"
- **THEN** the system SHALL fetch and display previous period data

#### Scenario: Show percentage change
- **WHEN** comparison is enabled
- **THEN** the system SHALL show "+15% vs last week" or "-8% vs last week" badge

#### Scenario: Visual comparison on chart
- **WHEN** comparison is enabled
- **THEN** the trend chart SHALL show dashed line for previous period

### Requirement: Cost Dashboard Export

The dashboard SHALL provide export functionality for cost data in CSV format. The export SHALL include all visible data (totals, namespace breakdown, daily costs). The export SHALL respect current filters (namespace, time range).

#### Scenario: Export to CSV
- **WHEN** user clicks "Export CSV" button
- **THEN** the system SHALL download CSV file with all cost data

#### Scenario: Export respects filters
- **WHEN** user has namespace filter active and clicks "Export"
- **THEN** the CSV SHALL include only filtered namespace data
