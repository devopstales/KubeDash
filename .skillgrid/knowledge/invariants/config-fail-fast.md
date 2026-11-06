---
type: InvariantContract
title: "Configuration fails fast at boot: INI > env, no hard-coded default for identities or credentials"
description: "kubedash.ini (via the KUBEDASH_HOME anchor) is the primary config source, KUBEDASH_* env overrides it, and a missing required identity/credential raises ini_config.ConfigError at boot instead of falling back to a code default. (ADR-0028.)"
tags: [config, fail-fast, ini, adr-0028]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/core/ini_config.py
      all_of: ['class ConfigError(Exception)', 'missing required config', 'kubedash_jwt_secret']
    - path: backend/tests/test_ini_config.py
      all_of: ['test_required_key_missing_fails_fast']
claims:
  - subject: fail-fast error type
    literal: 'class ConfigError(Exception)'
  - subject: fail-fast message
    literal: 'missing required config'
  - subject: required identity/credential keys
    literal: 'kubedash_jwt_secret'
---

# Configuration fails fast at boot

A configuration value comes from the INI or the environment — never from
a hard-coded in-code default for identities or credentials.

**The contract.**

- Resolution per key: `kubedash.ini` (located as
  `<KUBEDASH_HOME>/kubedash.ini`; `KUBEDASH_HOME` is the single location
  anchor — the INI, the static dir `<KUBEDASH_HOME>/static`, and other
  home-relative paths are derived from it) → `KUBEDASH_*` env override →
  **no in-code default for operator values**. A required key absent from
  both raises `ini_config.ConfigError` with the message
  `missing required config '<field>' (INI [section] key or env)`.
- The required set (`ini_config.py`) is
  `{"kubedash_jwt_secret", "kubedash_secret_key", "admin_kubeconfig"}` —
  the JWT signing key, the AES-256-GCM kubeconfig-encryption key
  (ADR-0002 one-way-door), and the admin cluster source.
- In-code defaults are allowed for **mode/behavior knobs only**:
  `cookie_secure` (fail-closed `"true"`), `kubedash_role` (`"worker"`),
  `app_mode` (`"development"`), timeouts (`first_paint_backstop "5m"`,
  `namespace_list_timeout "5s"`) — never for identities/credentials.
- The INI is read with `configparser` (interpolation off); the 4.1
  `[k8s]` section is ignored, not ported (the registry is the
  multi-cluster surface).

**Known nuance (recorded 2026-11-06).** `admin_kubeconfig` is in the
required set but its field row carries an empty-string default, and
`resolve()` returns a present default before reaching the required
check — so today only the two keys actually raise. The intent (all three
are operator values, none may silently default) is recorded here so the
gap is visible, not re-discovered.

**Why.** "Looks configured but is really a default" is the bug class this
codebase already fails closed elsewhere (`cookie_secure`); boot-time
failure names the exact missing key.

**Pinned by.** `backend/tests/test_ini_config.py` —
`test_required_key_missing_fails_fast` (asserts the `ConfigError` and
that `"jwt_secret"` is in the message); the INI/env precedence suite in
the same file.

**Related.** ADR-0028 (decision), ADR-0021 (bootstrap admin values),
`glossary/02-technical-terms.md` (`kubedash.ini`, `KUBEDASH_HOME`).
