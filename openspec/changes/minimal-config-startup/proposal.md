## Why

Today KubeDash requires a `kubedash.ini` file to be present and correctly configured before the app can start. This creates friction for:
- New contributors trying KubeDash for the first time
- Quick local experiments without crafting a config file
- Ephemeral or containerized environments that need extra bootstrapping

We want KubeDash to start in a safe, minimal, "batteries-included" mode without a `kubedash.ini`, so users can get to a running dashboard quickly.

## What Changes

- KubeDash will **start successfully without `kubedash.ini`** present on disk.
- When no config file is found, the app enters **minimal-config mode** with built-in defaults.
- SQLite is used as the default database engine in minimal-config mode.
- No insecure default credentials; existing authentication flows are reused.
- Clear logging indicates minimal-config mode and its limitations.

## Capabilities

### New Capabilities
- `minimal-config-mode`: Automatic fallback to built-in defaults when `kubedash.ini` is absent, including SQLite database, safe security defaults, and clear startup messaging.

### Modified Capabilities
<!-- No existing specs are modified — this is purely additive fallback behavior -->

## Impact

- `lib/initializers/config.py` — config loading logic with fallback
- `lib/initializers/database.py` — SQLite initialization in minimal mode
- `lib/initializers/security.py` — safe default security posture
- `lib/session.py` — session backend fallback behavior
- Startup logs and health endpoint — indicate minimal-config state
- Backward compatible: existing `kubedash.ini` deployments are unaffected
