## Context

KubeDash currently requires a `kubedash.ini` file to be present on disk before startup. The config loading flow (`lib/initializers/config.py`) reads the ini file and sets configuration values for database, security, caching, and integrations. If the file is missing, the app logs a warning and falls back to defaults, but the database initializer still expects to be configured with a valid database type and connection URI.

The app already supports SQLite (via SQLAlchemy), PostgreSQL, and Redis for sessions. The existing session module (`lib/session.py`) has a Redis fallback to filesystem sessions.

## Goals / Non-Goals

**Goals:**
- KubeDash starts and serves the dashboard with zero config files
- SQLite is used automatically when no `kubedash.ini` is present
- Security defaults are safe (no hardcoded admin passwords, no anonymous full access)
- Minimal-config mode is clearly indicated in logs
- Existing deployments with `kubedash.ini` are completely unaffected

**Non-Goals:**
- No new configuration file format or config generator
- No wizard or interactive setup on first run
- No changes to Kubernetes/Helm deployment paths (those already use ConfigMaps/env vars)
- No automatic config file creation

## Decisions

### Decision: Use SQLite with XDG_DATA_HOME path

**Rationale:** SQLite is already supported by SQLAlchemy. The default DB path follows `$XDG_DATA_HOME/kubedash/kubedash.sqlite` (typically `~/.local/share/kubedash/kubedash.sqlite`). If XDG is not available, fall back to the application directory (`./kubedash.sqlite`). This avoids collisions between different users on shared systems and works in containers where `$HOME` may be `/`.

**Alternatives considered:**
- Fixed `/tmp/kubedash.sqlite` — lost on reboot, not ideal
- In-memory SQLite (`sqlite:///:memory:`) — stateless, loses data between restarts
- Config file generator — defeats the purpose of zero-config startup

### Decision: Disable advanced features in minimal mode

**Rationale:** In minimal-config mode, advanced features requiring explicit configuration (OIDC, external integrations, cluster mode/leader election, Redis sessions) are disabled by default. Only features that work safely with SQLite and local auth are enabled.

### Decision: Reuse existing auth flows, no admin shortcut

**Rationale:** The existing authentication flows (Kubernetes auth via kubeconfig, local DB auth) work with SQLite. We do not introduce a default admin user or password. Users authenticate via their existing Kubernetes credentials or create users through the normal flow once authenticated.

### Decision: Single health endpoint field for observability

**Rationale:** The existing health endpoint (`/api/health`) already returns metadata. We add a `config_mode` field (`"minimal"` vs `"full"`) to make programmatic detection easy without introducing new endpoints.

## Risks / Trade-offs

- **[Risk]** SQLite doesn't support concurrent writes → **Mitigation:** Minimal mode only enables single-replica operation; cluster mode requires `kubedash.ini` with PostgreSQL
- **[Risk]** Users may accidentally run production workloads in minimal mode → **Mitigation:** Clear startup log warning; `config_mode: minimal` in health endpoint; documentation
- **[Risk]** Migration path from SQLite to PostgreSQL is manual → **Mitigation:** Documented migration steps; this is acceptable since minimal mode targets dev/experimentation
