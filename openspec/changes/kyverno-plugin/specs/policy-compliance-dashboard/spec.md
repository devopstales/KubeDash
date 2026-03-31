## ADDED Requirements

### Requirement: Compliance Score Dashboard

The system SHALL display a cluster-wide compliance score calculated as `(pass / (pass + fail)) * 100` based on PolicyReport results. The score SHALL be shown as a gauge chart with color coding: green (>=90%), yellow (70-89%), red (<70%). The dashboard SHALL show score trend over 7d/30d periods using a line chart. The score SHALL update every 60 seconds via background refresh.

#### Scenario: Display current compliance score
- **WHEN** user opens the compliance dashboard
- **THEN** the system SHALL calculate and display current compliance score as percentage

#### Scenario: Score color coding
- **WHEN** compliance score is >= 90%
- **THEN** the gauge SHALL display in green

#### Scenario: Score trend visualization
- **WHEN** user selects "7d" time range
- **THEN** the system SHALL show line chart with daily score values for past 7 days

#### Scenario: Background refresh
- **WHEN** 60 seconds have elapsed since last fetch
- **THEN** the system SHALL refresh compliance data without user action

### Requirement: Violations by Namespace Chart

The system SHALL display a bar chart showing violation counts grouped by namespace. The chart SHALL show only namespaces with violations, sorted descending by count. Clicking a namespace bar SHALL filter the violations table to that namespace. The chart SHALL update when namespace filter changes.

#### Scenario: Display violations by namespace
- **WHEN** user views compliance dashboard
- **THEN** the system SHALL show horizontal bar chart with violation counts per namespace

#### Scenario: Click to filter
- **WHEN** user clicks on a namespace bar
- **THEN** the violations table SHALL filter to show only that namespace's violations

#### Scenario: Empty namespaces excluded
- **WHEN** a namespace has zero violations
- **THEN** it SHALL NOT appear in the chart

### Requirement: Violations by Category Chart

The system SHALL display a pie chart showing violation distribution by policy category (Security, Operations, Governance, Custom). Categories SHALL be determined by policy labels (`kyverno.io/category`), defaulting to "Uncategorized" if not labeled. The chart SHALL show percentage and count for each category.

#### Scenario: Display violations by category
- **WHEN** user views compliance dashboard
- **THEN** the system SHALL show pie chart with violation breakdown by category

#### Scenario: Uncategorized policies
- **WHEN** a policy has no category label
- **THEN** violations SHALL be grouped as "Uncategorized"

#### Scenario: Category legend click
- **WHEN** user clicks a category in the legend
- **THEN** the violations table SHALL filter to show only that category

### Requirement: Violations Hotspot Table

The system SHALL display a sortable table showing top violated resources with columns: Resource, Namespace, Policy, Category, Violation Count, Last Violation. The table SHALL default to showing top 10 resources sorted by violation count descending. The table SHALL support export to CSV.

#### Scenario: Display top violations
- **WHEN** user views compliance dashboard
- **THEN** the system SHALL show table with top 10 most-violated resources

#### Scenario: Sort by violation count
- **WHEN** user clicks "Violation Count" column header
- **THEN** the table SHALL sort descending by count

#### Scenario: Export to CSV
- **WHEN** user clicks "Export CSV" button
- **THEN** the system SHALL download CSV file with all violations (not just top 10)

### Requirement: Compliance Time Range Selection

The dashboard SHALL provide time range selector with presets: 24h, 7d, 30d, 90d. The selector SHALL update all charts (score trend, violations by namespace, violations by category) to show data within selected range. Historical data SHALL be sourced from PolicyReport `results` timestamps.

#### Scenario: Select 7d time range
- **WHEN** user selects "7d" from time range dropdown
- **THEN** all charts SHALL update to show data from past 7 days only

#### Scenario: Default time range
- **WHEN** user first opens dashboard
- **THEN** the default time range SHALL be 7d
