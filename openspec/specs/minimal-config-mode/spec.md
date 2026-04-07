# minimal-config-mode Specification

## Purpose
TBD - created by archiving change minimal-config-startup. Update Purpose after archive.
## Requirements
### Requirement: Automatic minimal-config mode fallback

When `kubedash.ini` is not found at any configured search path, the system SHALL automatically enter minimal-config mode instead of failing or requiring manual intervention.

#### Scenario: No config file found
- **WHEN** KubeDash starts and no `kubedash.ini` file exists at any search path
- **THEN** the system enters minimal-config mode and logs a clear message indicating the fallback

#### Scenario: Config file found
- **WHEN** KubeDash starts and a `kubedash.ini` file exists
- **THEN** the system uses full configuration from the file as before, with no behavioral change

### Requirement: SQLite default database in minimal mode

In minimal-config mode, the system SHALL configure SQLite as the database engine with a deterministic default path.

#### Scenario: XDG_DATA_HOME available
- **WHEN** `$XDG_DATA_HOME` is set and writable
- **THEN** the system uses `$XDG_DATA_HOME/kubedash/kubedash.sqlite` as the database path

#### Scenario: XDG_DATA_HOME not available
- **WHEN** `$XDG_DATA_HOME` is not set
- **THEN** the system uses `~/.local/share/kubedash/kubedash.sqlite` as the database path

#### Scenario: Default path cannot be created
- **WHEN** the default SQLite file path cannot be created due to permissions or read-only filesystem
- **THEN** the system fails startup with a clear error message explaining the problem and how to override the DB path via environment variable

### Requirement: Safe security defaults in minimal mode

In minimal-config mode, the system SHALL NOT use insecure default credentials or grant anonymous full access.

#### Scenario: No default admin credentials
- **WHEN** KubeDash starts in minimal-config mode
- **THEN** no hardcoded admin username or password is created

#### Scenario: Authentication uses existing flows
- **WHEN** a user attempts to access the dashboard in minimal-config mode
- **THEN** the system uses existing authentication flows (e.g., Kubernetes auth via current kubeconfig) without inventing new insecure shortcuts

### Requirement: Advanced features disabled in minimal mode

In minimal-config mode, features requiring explicit configuration SHALL be disabled: OIDC, external integrations, cluster/leader election, and Redis sessions.

#### Scenario: OIDC disabled
- **WHEN** KubeDash runs in minimal-config mode
- **THEN** OIDC authentication is not available regardless of any pre-existing OIDC environment variables

#### Scenario: Cluster mode disabled
- **WHEN** KubeDash runs in minimal-config mode
- **THEN** replica mode defaults to `single`; leader election is disabled

### Requirement: Clear logging of minimal-config mode

The system SHALL log a clear message when entering minimal-config mode, including which defaults were applied.

#### Scenario: Startup log message
- **WHEN** KubeDash enters minimal-config mode
- **THEN** a log message indicates the mode and lists key defaults (database path, security posture, disabled features)

### Requirement: Health endpoint indicates config mode

The health endpoint SHALL expose a `config_mode` field in its response, with value `"minimal"` or `"full"`.

#### Scenario: Health check in minimal mode
- **WHEN** a client GETs `/api/health` while running in minimal-config mode
- **THEN** the response includes `"config_mode": "minimal"` in the metadata

#### Scenario: Health check in full mode
- **WHEN** a client GETs `/api/health` while running with a `kubedash.ini` file
- **THEN** the response includes `"config_mode": "full"` in the metadata

