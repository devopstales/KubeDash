## ADDED Requirements

### Requirement: Policy Creation from Template

The system SHALL provide a template library with pre-built policy templates categorized by use case (Security, Operations, Governance). The template library SHALL include at least 15 templates covering common patterns: require-labels, forbid-privileged-containers, require-resource-limits, require-probes, forbid-host-network, require-readonly-rootfs, and image-tag-latest. Selecting a template SHALL pre-populate the policy editor with template YAML.

#### Scenario: Browse template library
- **WHEN** user clicks "Create from Template"
- **THEN** the system SHALL display categorized template grid with descriptions

#### Scenario: Preview template
- **WHEN** user clicks on a template card
- **THEN** the system SHALL show template YAML preview with description and use cases

#### Scenario: Apply template
- **WHEN** user clicks "Use Template"
- **THEN** the system SHALL open policy editor with template YAML pre-populated

### Requirement: Policy YAML Editor

The system SHALL provide Monaco YAML editor with syntax highlighting, schema validation, and auto-completion for Kyverno policy structure. The editor SHALL support both visual form mode (for simple policies) and YAML mode (for advanced policies). The editor SHALL validate YAML syntax in real-time and show errors inline.

#### Scenario: Edit policy in YAML mode
- **WHEN** user selects "YAML Editor" tab
- **THEN** the system SHALL display Monaco editor with full policy YAML

#### Scenario: Syntax validation
- **WHEN** user enters invalid YAML
- **THEN** the editor SHALL show red squiggly underline and error message on hover

#### Scenario: Switch between modes
- **WHEN** user switches from Visual to YAML mode
- **THEN** the system SHALL preserve current content and show in YAML format

### Requirement: Policy Visual Form Builder

The system SHALL provide a visual form builder for common policy patterns with fields: Name, Namespace (for Policy), Scope (Cluster/Namespace), Rules (name, match resources, exclude resources, validation pattern). The form builder SHALL generate valid Kyverno policy YAML from form inputs. The form builder SHALL support add/remove multiple rules.

#### Scenario: Create policy from visual form
- **WHEN** user fills out visual form and clicks "Generate YAML"
- **THEN** the system SHALL generate valid Kyverno policy YAML from form inputs

#### Scenario: Add multiple rules
- **WHEN** user clicks "Add Rule"
- **THEN** the system SHALL add a new rule section with name, match, exclude, and validation fields

#### Scenario: Validate form before generate
- **WHEN** user clicks "Generate YAML" with required fields empty
- **THEN** the system SHALL highlight missing fields and show error message

### Requirement: Policy Create/Update/Delete Operations

The system SHALL provide CRUD operations for ClusterPolicy and Policy resources. Create SHALL validate YAML before applying to cluster. Update SHALL show diff between current and new YAML before confirmation. Delete SHALL require confirmation with policy name typed to prevent accidental deletion. All operations SHALL require Admin role.

#### Scenario: Create new policy
- **WHEN** user submits valid policy YAML via create form
- **THEN** the system SHALL apply policy to cluster and redirect to detail view

#### Scenario: Update existing policy
- **WHEN** user edits and submits policy update
- **THEN** the system SHALL show diff view before confirmation

#### Scenario: Delete policy with confirmation
- **WHEN** user clicks "Delete Policy"
- **THEN** the system SHALL require typing policy name to confirm deletion

#### Scenario: User role cannot delete
- **WHEN** User role attempts to delete policy
- **THEN** the system SHALL show "Access Denied" message

### Requirement: Policy Clone

The system SHALL provide "Clone Policy" functionality that creates a copy of an existing policy with editable name and namespace. The clone SHALL preserve all rules, match conditions, and parameters from the source policy. The clone SHALL append "-clone" to the original name (editable by user).

#### Scenario: Clone ClusterPolicy
- **WHEN** user clicks "Clone" on a ClusterPolicy detail view
- **THEN** the system SHALL open create form with policy YAML pre-populated and name editable

#### Scenario: Modify cloned policy name
- **WHEN** user changes the name in clone form
- **THEN** the system SHALL use the new name for the cloned policy

### Requirement: Policy Suspend/Resume Enforcement

The system SHALL provide suspend/resume toggle for policies that sets `spec.validationFailureAction` to "Audit" (suspend) or "Enforce" (resume). The toggle SHALL show current state with visual indicator. Suspend SHALL require confirmation with reason field (logged to audit trail).

#### Scenario: Suspend policy enforcement
- **WHEN** user clicks "Suspend" and provides reason
- **THEN** the system SHALL set validationFailureAction to "Audit" and log to audit trail

#### Scenario: Resume policy enforcement
- **WHEN** user clicks "Resume"
- **THEN** the system SHALL set validationFailureAction to "Enforce"

### Requirement: Policy Validation Before Apply

The system SHALL validate policy YAML against Kyverno schema before applying to cluster. Validation SHALL check for required fields (apiVersion, kind, metadata.name, spec.rules), valid JMESPath expressions, and semantic errors (e.g., match without validation). Validation errors SHALL be displayed with line numbers referencing the YAML editor.

#### Scenario: Validate required fields
- **WHEN** user submits policy missing required fields
- **THEN** the system SHALL show error listing missing fields

#### Scenario: Validate JMESPath syntax
- **WHEN** user enters invalid JMESPath expression
- **THEN** the system SHALL show error with expression and suggested fix

#### Scenario: Block apply on validation failure
- **WHEN** validation fails
- **THEN** the system SHALL NOT apply the policy to cluster
