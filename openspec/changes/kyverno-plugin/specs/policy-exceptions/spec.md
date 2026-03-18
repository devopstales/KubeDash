## ADDED Requirements

### Requirement: PolicyException List View

The system SHALL display a list of PolicyException and ClusterPolicyException resources with columns: Name, Namespace (or Cluster-wide), Policy Name, Rule Names, Expiration (if set), Age, Created By (from annotation). The list SHALL highlight exceptions that are expiring soon (< 7 days) with yellow indicator. Expired exceptions SHALL show red indicator with "Expired" status.

#### Scenario: View PolicyException list
- **WHEN** user navigates to `/plugins/kyverno/exceptions`
- **THEN** the system SHALL display all PolicyExceptions in sortable table

#### Scenario: Highlight expiring exceptions
- **WHEN** an exception expires in less than 7 days
- **THEN** the row SHALL show yellow background with "Expiring Soon" badge

#### Scenario: Show expired exceptions
- **WHEN** an exception has expired (expiration date in past)
- **THEN** the row SHALL show red background with "Expired" status

### Requirement: PolicyException Creation with Justification

The system SHALL provide a form to create PolicyException requiring fields: Exception Name, Policy Name (dropdown of existing policies), Rule Names (multi-select from policy rules), Resources (namespace/name pattern), Expiration Date (optional), and Justification (required text field, min 50 characters). The justification SHALL be stored in `metadata.annotations["kyverno.io/justification"]`.

#### Scenario: Create exception with justification
- **WHEN** user submits valid exception form
- **THEN** the system SHALL create PolicyException with justification in annotation

#### Scenario: Justification required
- **WHEN** user submits form with justification < 50 characters
- **THEN** the system SHALL show error "Please provide detailed justification (minimum 50 characters)"

#### Scenario: Select policy and rules
- **WHEN** user selects a policy
- **THEN** the system SHALL auto-populate available rules from that policy for selection

### Requirement: PolicyException Approval Workflow

The system SHALL record the approver (from current user session) in `metadata.annotations["kyverno.io/approver"]` and approval timestamp in `metadata.annotations["kyverno.io/approved-at"]`. The approval information SHALL be displayed in the exception list and detail views. Creating an exception SHALL require Admin role.

#### Scenario: Record approver
- **WHEN** user creates an exception
- **THEN** the system SHALL set approver annotation to current username

#### Scenario: User role cannot create exceptions
- **WHEN** User role attempts to create exception
- **THEN** the system SHALL show "Access Denied - Admin role required"

### Requirement: PolicyException Audit Trail

The system SHALL log all PolicyException CRUD operations to the KubeDash audit log with event type "policy-exception-create", "policy-exception-update", or "policy-exception-delete". The audit log SHALL include: exception name, policy name, rules, resources, expiration, justification, approver, and timestamp. The audit log SHALL be accessible from the exception detail view.

#### Scenario: Log exception creation
- **WHEN** user creates a PolicyException
- **THEN** the system SHALL write audit event with full exception details

#### Scenario: View audit trail
- **WHEN** user clicks "Audit Trail" tab in exception detail
- **THEN** the system SHALL show chronological list of all changes to this exception

### Requirement: PolicyException Expiration Handling

The system SHALL display a warning banner for exceptions that have expired or are expiring within 7 days. The banner SHALL offer "Renew Exception" action that opens edit form with new expiration date. Expired exceptions SHALL be highlighted in red with recommendation to either renew or remove.

#### Scenario: Show expiration warning
- **WHEN** exception expires in < 7 days
- **THEN** the system SHALL show yellow warning banner at top of detail view

#### Scenario: Renew exception
- **WHEN** user clicks "Renew Exception"
- **THEN** the system SHALL open edit form with expiration date field pre-populated

### Requirement: PolicyException Impact Analysis

The system SHALL show which violations would be excluded by this exception (for exceptions on active policies). The impact analysis SHALL query recent PolicyReport results and show: number of current violations that would be excluded, affected resources list, and policies impacted. The analysis SHALL update in real-time as exception rules are modified in the form.

#### Scenario: View impact before create
- **WHEN** user fills out exception form
- **THEN** the system SHALL show "This exception will exclude X violations across Y resources"

#### Scenario: No matching violations
- **WHEN** exception has no matching current violations
- **THEN** the system SHALL show message "No current violations match this exception criteria"

### Requirement: PolicyException Search and Filter

The system SHALL provide search functionality to find exceptions by: policy name, resource name, namespace, approver, or justification text (full-text search). The system SHALL provide filters: expiring soon, expired, by policy, by namespace, by approver. Filters SHALL be combinable and persist in URL for bookmarking.

#### Scenario: Search by justification
- **WHEN** user searches for "security"
- **THEN** the system SHALL show exceptions with "security" in justification text

#### Scenario: Filter by approver
- **WHEN** user selects approver from dropdown
- **THEN** the system SHALL show only exceptions approved by that user

#### Scenario: Combine filters
- **WHEN** user applies multiple filters (e.g., expiring soon + namespace: production)
- **THEN** the system SHALL show results matching all filters
