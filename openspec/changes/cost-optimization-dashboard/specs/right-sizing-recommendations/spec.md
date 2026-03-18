## ADDED Requirements

### Requirement: Right-Sizing Recommendation Engine

The system SHALL generate right-sizing recommendations for CPU and memory requests/limits based on historical usage data. The engine SHALL use p50 (median) usage for recommended requests and p95 usage for recommended limits. The engine SHALL require minimum 7 days of historical data for recommendations. Recommendations SHALL include confidence score based on data quality.

#### Scenario: Generate CPU request recommendation
- **WHEN** deployment has 7+ days of usage data
- **THEN** the system SHALL recommend CPU request at p50 actual usage

#### Scenario: Generate CPU limit recommendation
- **WHEN** deployment has usage data
- **THEN** the system SHALL recommend CPU limit at p95 actual usage

#### Scenario: Insufficient data handling
- **WHEN** deployment has < 7 days of data
- **THEN** the system SHALL show "Insufficient data" instead of recommendation

### Requirement: Recommendation Display UI

The system SHALL display recommendations in a dedicated view with columns: Resource Name, Namespace, Current Request, Recommended Request, Current Limit, Recommended Limit, Potential Savings, Confidence. The view SHALL support filtering by resource type (Deployment, StatefulSet, DaemonSet) and namespace. Recommendations SHALL be sortable by potential savings.

#### Scenario: View all recommendations
- **WHEN** user navigates to `/plugins/cost-optimization/recommendations`
- **THEN** the system SHALL display all right-sizing recommendations in sortable table

#### Scenario: Filter by namespace
- **WHEN** user selects namespace from dropdown
- **THEN** the list SHALL show only recommendations for that namespace

#### Scenario: Sort by potential savings
- **WHEN** user clicks "Potential Savings" column
- **THEN** the table SHALL sort descending by savings amount

### Requirement: Potential Savings Calculation

The system SHALL calculate potential savings for each recommendation as `(current_request - recommended_request) * price_per_unit * 30 days`. Savings SHALL be displayed in USD per month. The system SHALL show total potential savings if all recommendations are applied.

#### Scenario: Calculate CPU savings
- **WHEN** CPU request recommendation is generated
- **THEN** the system SHALL show monthly savings from CPU reduction

#### Scenario: Calculate memory savings
- **WHEN** memory request recommendation is generated
- **THEN** the system SHALL show monthly savings from memory reduction

#### Scenario: Show total potential savings
- **WHEN** user views recommendations list
- **THEN** the system SHALL show "Total Potential Savings: $X/month" at top

### Requirement: Confidence Score for Recommendations

The system SHALL assign a confidence score (High/Medium/Low) to each recommendation based on: data age (recent data = higher confidence), data variance (low variance = higher confidence), workload stability (stable replica count = higher confidence). High confidence SHALL be shown in green, Medium in yellow, Low in gray.

#### Scenario: High confidence recommendation
- **WHEN** recommendation has 30+ days of stable data with low variance
- **THEN** the system SHALL show "High" confidence with green indicator

#### Scenario: Low confidence recommendation
- **WHEN** recommendation has high variance or unstable workload
- **THEN** the system SHALL show "Low" confidence with gray indicator

#### Scenario: Show confidence details
- **WHEN** user hovers over confidence indicator
- **THEN** the system SHALL show tooltip explaining confidence factors

### Requirement: Apply Recommendation Flow

The system SHALL provide "Apply" action for each recommendation that opens resource editor with recommended values pre-filled. The user SHALL review and confirm changes before applying. After apply, the system SHALL track actual savings achieved vs estimated.

#### Scenario: Apply recommendation
- **WHEN** user clicks "Apply" on a recommendation
- **THEN** the system SHALL open deployment editor with recommended values pre-filled

#### Scenario: Review before apply
- **WHEN** editor opens
- **THEN** the user SHALL confirm changes before deployment is updated

#### Scenario: Track actual savings
- **WHEN** recommendation is applied
- **THEN** the system SHALL track and display actual savings achieved after 7 days

### Requirement: Recommendation Dismissal

The system SHALL allow users to dismiss recommendations with optional reason (Not applicable, Testing workload, Will address later, Other). Dismissed recommendations SHALL be hidden from main view but accessible in "Dismissed" tab. Dismissed recommendations SHALL be re-evaluated after 30 days.

#### Scenario: Dismiss recommendation
- **WHEN** user clicks "Dismiss" and selects reason
- **THEN** the recommendation SHALL be hidden from main view

#### Scenario: View dismissed recommendations
- **WHEN** user clicks "Dismissed" tab
- **THEN** the system SHALL show all dismissed recommendations with reasons

#### Scenario: Re-evaluate dismissed recommendations
- **WHEN** 30 days have passed since dismissal
- **THEN** the system SHALL re-evaluate and potentially re-show recommendation

### Requirement: Bulk Actions on Recommendations

The system SHALL support bulk selection and actions on multiple recommendations. Users SHALL select multiple recommendations and apply "Apply Selected", "Dismiss Selected", or "Export Selected". Bulk apply SHALL show summary of all changes before confirmation.

#### Scenario: Select multiple recommendations
- **WHEN** user checks multiple recommendation checkboxes
- **THEN** the system SHALL show bulk action buttons

#### Scenario: Bulk apply recommendations
- **WHEN** user clicks "Apply Selected"
- **THEN** the system SHALL show summary dialog with all changes before confirmation

#### Scenario: Bulk export recommendations
- **WHEN** user clicks "Export Selected"
- **THEN** the system SHALL download CSV with selected recommendations

### Requirement: Recommendation Impact Analysis

The system SHALL show impact analysis before applying recommendations including: estimated monthly savings, performance risk assessment (low/medium/high based on current headroom), affected pods count. For high-risk recommendations (current usage close to limits), the system SHALL show warning.

#### Scenario: Show impact analysis
- **WHEN** user views a recommendation
- **THEN** the system SHALL show savings, risk level, and affected resources

#### Scenario: Warn on high-risk recommendation
- **WHEN** current usage is within 20% of recommended limit
- **THEN** the system SHALL show warning "High risk: usage close to limit"

#### Scenario: Show affected pods
- **WHEN** user views deployment recommendation
- **THEN** the system SHALL show number of pods that will be affected by change
