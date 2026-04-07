## 1. Startup & Config Detection

- [x] 1.1 Update config loading (`lib/initializers/config.py`) to detect absence of `kubedash.ini` and enter minimal-config mode instead of failing
- [x] 1.2 Add `MINIMAL_CONFIG` flag to `app.config` when fallback is triggered
- [x] 1.3 Define and document effective configuration precedence in minimal-config mode (built-in defaults vs environment variables)

## 2. SQLite Minimal Database Mode

- [x] 2.1 Add `get_minimal_db_path()` function that resolves `$XDG_DATA_HOME/kubedash/kubedash.sqlite` with fallback to `~/.local/share/kubedash/kubedash.sqlite`
- [x] 2.2 Update `lib/initializers/database.py` to use SQLite in minimal-config mode
- [x] 2.3 Ensure directory creation for default DB path with clear error on failure
- [x] 2.4 Verify migrations and schema initialization work correctly against SQLite in minimal mode

## 3. Security Hardening

- [x] 3.1 Review and disable OIDC/external auth in minimal-config mode
- [x] 3.2 Ensure no default admin credentials are created
- [x] 3.3 Disable cluster/leader election mode (force single-replica)
- [x] 3.4 Disable Redis session backend in minimal mode (fall back to SQLAlchemy)

## 4. Observability

- [x] 4.1 Add clear startup log message listing minimal-config mode, DB path, and disabled features
- [x] 4.2 Add `config_mode` field (`"minimal"` vs `"full"`) to `/api/health` endpoint response
- [x] 4.3 Add `kubedash_config_mode` gauge metric to Prometheus endpoint

## 5. Documentation

- [x] 5.1 Update README with minimal-config mode description and quickstart instructions
- [x] 5.2 Document limitations of minimal-config mode (SQLite single-replica, no Redis, no OIDC)
- [x] 5.3 Document how to transition from minimal to full `kubedash.ini` configuration
