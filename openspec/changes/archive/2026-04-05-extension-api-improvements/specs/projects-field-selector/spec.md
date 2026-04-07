## ADDED Requirements

### Requirement: List projects supports fieldSelector

The system SHALL accept a `fieldSelector` query parameter on the list projects endpoint. The server SHALL filter the list so that only projects matching the selector are returned. Supported fields SHALL include at least: `metadata.name` (equality), `spec.protected` (equality to true/false), `status.phase` (equality). The selector MAY support comma-separated multiple requirements (AND semantics). Unsupported field names or operators MAY be rejected with 400 or ignored as defined by implementation; behavior SHALL be documented.

#### Scenario: Filter by metadata.name

- **WHEN** client sends GET list projects with `fieldSelector=metadata.name=my-project`
- **THEN** the server returns only the project whose name is `my-project` (if the user has access and it exists in the allowed set)

#### Scenario: Filter by spec.protected

- **WHEN** client sends GET list projects with `fieldSelector=spec.protected=true`
- **THEN** the server returns only projects whose spec.protected is true

#### Scenario: Filter by status.phase

- **WHEN** client sends GET list projects with `fieldSelector=status.phase=Active`
- **THEN** the server returns only projects whose status.phase is Active

#### Scenario: Field selector applied after permission and label filter

- **WHEN** client sends GET list projects with labelSelector and fieldSelector
- **THEN** the server first applies permission and label filtering, then applies fieldSelector to the resulting list; the system SHALL NOT expose existence of projects the user cannot see
