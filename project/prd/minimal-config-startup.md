### PRD: Minimal Config Startup (No `kubedash.ini`)

**OpenSpec change**: `openspec/changes/minimal-config-startup/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

Today KubeDash expects a `kubedash.ini` file to be present and correctly configured before the app can start.

- This makes it harder to try KubeDash quickly (e.g. `pip install` + `kubedash` on a laptop).
- Containerized or ephemeral environments need extra bootstrapping just to generate a minimal config file.
- For local experimentation, requiring users to understand all config options up‑front is unnecessary friction.

We want KubeDash to be able to **start in a safe, minimal, “batteries‑included” mode** without a `kubedash.ini` file, so users can get to a running dashboard quickly.

#### Goals

- Allow KubeDash to **start successfully without `kubedash.ini`** present on disk.
- In this mode, **use an embedded SQLite database** with a sensible default path.
- Keep the “minimal config” mode **safe by default** (no insecure default admin credentials, no unintended network exposure).
- Make it clear to operators (via logs and docs) that they are running in minimal mode and what the limitations are.

#### Functional Requirements

- **Config discovery and fallback**
  - On startup, KubeDash MUST:
    - Look for `kubedash.ini` in the existing search paths (current behavior).
    - If no config file is found, automatically enter **minimal‑config mode** instead of failing.
  - When entering minimal‑config mode:
    - Log a clear message that `kubedash.ini` was not found and KubeDash is starting with built‑in defaults.
    - Expose a way to detect this state programmatically (e.g. an internal flag, metric, or health detail) for future observability work.

- **Database: SQLite by default**
  - In minimal‑config mode, the application MUST:
    - Use SQLite as the backing database engine.
    - Choose a deterministic default DB file path, for example:
      - An application data directory (e.g. `$XDG_DATA_HOME/kubedash/kubedash.sqlite`) or
      - A path under the working directory (e.g. `./kubedash.sqlite`) if no better location is available.
  - If the default SQLite file cannot be created (permissions, read‑only FS, etc.):
    - Fail startup with a clear error message that explains the problem and how to override the DB path.

- **Minimal configuration surface**
  - In minimal‑config mode, KubeDash SHOULD:
    - Derive basic settings from environment variables only where strictly necessary (e.g. Kubernetes API address, authentication mode), with sane defaults when safe.
    - Avoid enabling optional or advanced features that require explicit configuration (e.g. external auth providers, integrations) unless the corresponding env vars are present.
  - The behavior MUST be deterministic: the same environment MUST lead to the same effective configuration every time.

- **Security and safety**
  - Minimal‑config mode MUST:
    - Avoid insecure default credentials (no hardcoded admin password or anonymous full‑access UI).
    - Reuse existing authentication flows where possible (e.g. Kubernetes auth, OIDC) rather than inventing a new insecure shortcut.
    - Refuse to start if security‑critical inputs are missing and no safe fallback exists.
  - Logs MUST clearly indicate:
    - That KubeDash is running in minimal‑config mode.
    - Any assumptions or defaults applied that may impact security (e.g. binding only to `127.0.0.1` in this mode).

#### Non‑Functional Requirements

- **Developer experience**
  - A new contributor SHOULD be able to:
    - Install KubeDash and run it locally (e.g. `kubedash run`) without first crafting a `kubedash.ini`.
    - Point it at a cluster in a minimal way (e.g. using current kubeconfig discovery) and see a basic dashboard.

- **Backward compatibility**
  - Existing deployments that provide `kubedash.ini` MUST behave exactly as before; minimal‑config mode is only used when no config file is found.
  - Any defaults introduced for minimal mode MUST NOT silently override values provided in `kubedash.ini` or via existing environment variables.

- **Observability**
  - Minimal‑config mode SHOULD be visible via:
    - Logs on startup.
    - Optionally, a basic metric or health‑check field indicating “minimal” vs “full” config mode to aid debugging.

---

### Implementation Tasks (from OpenSpec)

> The detailed implementation plan lives in the OpenSpec change; this section summarizes the key tasks for product tracking.

#### 1. Startup & Config Detection

- [ ] 1.1 Update config loading to detect absence of `kubedash.ini` and switch to minimal‑config mode instead of failing.
- [ ] 1.2 Define and document the effective configuration precedence in minimal‑config mode (built‑ins vs environment variables).

#### 2. SQLite Minimal Database Mode

- [ ] 2.1 Add a SQLite default configuration for minimal‑config mode, including default DB file path selection.
- [ ] 2.2 Ensure migrations and schema initialization run correctly against SQLite in this mode.

#### 3. Security & UX Hardening

- [ ] 3.1 Review authentication and authorization behavior in minimal‑config mode to avoid insecure defaults.
- [ ] 3.2 Add clear logging and documentation describing minimal‑config mode, its limitations, and how to transition to a full `kubedash.ini` configuration.

