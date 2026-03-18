## ADDED Requirements

### Requirement: Idle Resource Detection

The system SHALL detect idle resources based on usage patterns over 24 hours. Idle pods SHALL be identified as having CPU usage < 5% of request AND memory usage < 10% of request for 24 consecutive hours. Idle LoadBalancers SHALL be identified as having zero active connections. Idle PVCs SHALL be identified as unmounted (no pod volume reference) for 7 days.

#### Scenario: Detect idle pods
- **WHEN** a pod has CPU usage < 5% and memory usage < 10% for 24 hours
- **THEN** the system SHALL mark it as "Idle" and show in waste dashboard

#### Scenario: Detect idle LoadBalancers
- **WHEN** a LoadBalancer service has zero active connections for 24 hours
- **THEN** the system SHALL mark it as "Idle" with estimated monthly waste

#### Scenario: Detect unmounted PVCs
- **WHEN** a PVC has no pod volume reference for 7 days
- **THEN** the system SHALL mark it as "Orphaned" with storage cost shown

### Requirement: Over-Provisioning Detection

The system SHALL detect over-provisioned workloads where requests exceed actual usage. A workload SHALL be marked over-provisioned if: CPU request > 3x p95 usage OR memory request > 3x p95 usage over 7 days. The system SHALL calculate wasted cost as `(request - recommended) * price_per_unit`.

#### Scenario: Detect CPU over-provisioning
- **WHEN** deployment CPU request is > 3x p95 actual usage over 7 days
- **THEN** the system SHALL mark it as "Over-Provisioned (CPU)" with waste estimate

#### Scenario: Detect memory over-provisioning
- **WHEN** deployment memory request is > 3x p95 actual usage over 7 days
- **THEN** the system SHALL mark it as "Over-Provisioned (Memory)" with waste estimate

#### Scenario: Calculate wasted cost
- **WHEN** workload is over-provisioned
- **THEN** the system SHALL show "Wasted: $X/month" based on pricing

### Requirement: Waste Dashboard

The system SHALL provide a centralized waste dashboard showing all detected waste categories: Idle Resources, Over-Provisioned Workloads, Orphaned Storage/LoadBalancers. The dashboard SHALL show total estimated monthly waste at the top. Each waste item SHALL show: Resource Name, Namespace, Waste Type, Estimated Monthly Waste, Action (Delete/Right-size/Ignore).

#### Scenario: View waste summary
- **WHEN** user navigates to `/plugins/cost-optimization/waste`
- **THEN** the system SHALL show total estimated monthly waste at top of page

#### Scenario: Filter by waste type
- **WHEN** user selects "Idle Resources" filter
- **THEN** the dashboard SHALL show only idle resource waste

#### Scenario: Sort by waste amount
- **WHEN** user clicks "Monthly Waste" column
- **THEN** the table SHALL sort descending by waste amount

### Requirement: Savings Estimation

The system SHALL calculate estimated monthly savings for each waste item. For idle resources: savings = current_cost * 30 days. For over-provisioned: savings = (current_request - recommended_request) * price * 30 days. For orphaned: savings = storage_cost * 30 days. Savings SHALL be displayed in USD with cloud provider pricing.

#### Scenario: Calculate idle resource savings
- **WHEN** pod is identified as idle
- **THEN** the system SHALL show "Save $X/month by deleting this resource"

#### Scenario: Calculate right-sizing savings
- **WHEN** workload is over-provisioned
- **THEN** the system SHALL show "Save $X/month by reducing requests"

#### Scenario: Show pricing source
- **WHEN** user hovers over savings amount
- **THEN** the system SHALL show tooltip with pricing calculation details

### Requirement: Waste Action Recommendations

For each waste item, the system SHALL provide actionable recommendations: "Delete" for idle/orphaned resources, "Right-size" for over-provisioned workloads, "Ignore" to dismiss the recommendation. Clicking "Delete" SHALL navigate to resource deletion flow. Clicking "Right-size" SHALL open resource editor with recommended values pre-filled.

#### Scenario: Recommend deletion for idle pod
- **WHEN** user views idle pod waste item
- **THEN** the system SHALL show "Delete" button with confirmation dialog

#### Scenario: Recommend right-sizing for over-provisioned deployment
- **WHEN** user views over-provisioned deployment
- **THEN** the system SHALL show "Right-size" button that opens editor with recommended requests

#### Scenario: Dismiss waste recommendation
- **WHEN** user clicks "Ignore"
- **THEN** the system SHALL mark recommendation as dismissed and hide from dashboard

### Requirement: Waste Trend Analysis

The system SHALL track waste trends over time showing total waste per day/week. The trend chart SHALL show waste reduction progress when users act on recommendations. The chart SHALL support 30d/90d time ranges with comparison to previous period.

#### Scenario: View waste trend over 30 days
- **WHEN** user views waste dashboard and selects "30d" range
- **THEN** the system SHALL show line chart with daily waste amounts

#### Scenario: Show waste reduction progress
- **WHEN** user has acted on waste recommendations
- **THEN** the trend chart SHALL show decreasing waste over time

#### Scenario: Compare waste with previous period
- **WHEN** user enables comparison
- **THEN** the chart SHALL show current vs previous period waste trends
