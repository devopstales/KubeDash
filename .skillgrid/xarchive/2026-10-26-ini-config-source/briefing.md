# Configuration source: kubedash.ini (4.1 format) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-26-ini-config-source`
**Date:** 2026-10-26
**ADR:** `../../knowledge/decisions/04-adr-0028-ini-config-source.md`

## Intent

KubeDash 5.0 reads all configuration from environment variables
(`backend/app/core/config.py`, a pydantic-settings `Settings` class with
hard-coded in-code defaults). This diverges from the operator-facing 4.1
product, which is configured through a single human-editable INI file,
`src/kubedash/kubedash.ini`, read with `configparser`.

The 5.0 rebase kept 4.1 parity for the *surfaces* (ADR-0022 sidebar,
ADR-0023/0024 tables) but dropped the one operator-facing configuration
surface they all shared. An operator upgrading from 4.1 loses the file they
know and meets a wall of `KUBEDASH_*` env vars.

This change makes `kubedash.ini` (the 4.1 format, minus the dropped plugin
system) the **primary** configuration source, with `KUBEDASH_*` env as an
**override**, and **no hard-coded in-code defaults** for identities or
credentials. A required value absent from both the INI and the environment
fails fast at boot with a named error.

Per the user (2026-10-26): "config always comes from ini, not env, not
hard-coded default." The precedence call the user made: **INI > env, env has
no defaults** — env is not a fallback that fills a gap; it is a higher-priority
source that the Helm chart uses to inject per-release secrets. Only *behavior*
knobs (not identities/credentials) may keep a fail-closed default
(`cookie_secure`, `app_mode`).

## Requirements

### R1 — `kubedash.ini` is the primary config source

The app MUST read configuration from a `kubedash.ini` file using the 4.1
`configparser` schema. The file location is operator-configurable
(`KUBEDASH_CONFIG_FILE`, default `kubedash.ini`, resolved relative to CWD,
matching 4.1's `os.path.isfile("kubedash.ini")` behavior). A missing required
value MUST fail boot with an error naming the section, key, and the INI
section/key that was expected.

### R2 — INI > env precedence, no in-code defaults

For every configuration value the resolution order is: **env (`KUBEDASH_*`)
wins if set; else the INI value; else (for required keys) fail fast**. There
MUST be no third, hard-coded in-code default for identities or credentials
(`jwt_secret`, `secret_key`, OIDC `client_id`/`client_secret`, `issuer`,
bootstrap admin email/password, `admin_kubeconfig`). The two *behavior* knobs
`cookie_secure` (defaults `True`, ADR-0025/0027) and `app_mode` (defaults
`development`) are the only allowed in-code defaults.

### R3 — 4.1 section parity (minus plugins)

The INI schema MUST support these 4.1 sections and map them to the existing
`Settings` fields 1:1:

- `[DEFAULT]` `app_mode` → `flask_env`
- `[security]` `admin_password` → bootstrap admin password; NEW `jwt_secret`,
  `secret_key` (the JWT + kubeconfig-encryption keys move out of code defaults)
- `[database]` `type/host/name/user/password` **or** `url` → `database_url`
- `[remote_cache]` redis `host/port/db/password` → `redis_url`
- `[sso_settings]` `issuer_url/callback_url/scope/client_id/secret` → OIDC
  fields
- `[monitoring]` `jaeger_enabled`, `jaeger_http_endpoint` (NEW 5.0 section)
- `[plugin_settings]` — **dropped** (no 5.0 plugin system); if present in a
  4.1 file it is ignored, not an error

The 5.0-only keys with no 4.1 home get explicit INI sections:
`[deployment]` (`kubedash_role`, `kubedash_replica_id`, `tls_edge`,
`cookie_secure`, `plugin_server`, `admin_kubeconfig`, `first_paint_backstop`,
`namespace_list_timeout`) and `[bootstrap]` (`bootstrap_admin_email`,
`bootstrap_admin_password`).

### R4 — The 4.1 `[k8s]` section is retired, not ported

4.1's `[k8s]` (`cluster_name/api_server/api_ca`) described ONE static cluster.
5.0 is a multi-cluster **registry** (clusters as DB rows, ADR-0002) with no
single configured cluster. The `[k8s]` section is **ignored** at load time
(a 4.1 `kubedash.ini` carrying `[k8s]` must still load and run), and
documented as retired. The admin cluster is reached via `admin_kubeconfig` /
in-cluster (ADR-0021); member clusters via the registry API.

### R5 — The shipped example carries no secrets

`kubedash.ini.example` MUST be committed: `app_mode=development`,
`[database] type=postgres` + localhost dev creds, empty `[security]`
`jwt_secret`/`secret_key`/`admin_password`, empty `[sso_settings]` secret.
The example is a *template*; the operator fills secrets. The example MUST NOT
contain a value that would silently run as a production credential.

### R6 — Existing env consumers keep working

The current env-based surface (`KUBEDASH_*`) MUST remain valid and MUST win
over the INI. The ~18 test sites that inject config via
`monkeypatch.setenv("KUBEDASH_*", …)` and the `create_app(config_overrides=…)`
seam MUST continue to work unchanged. The `get_settings()` public surface
(`settings.<field>` access) MUST be preserved so the ~10 call sites do not
each change.

### R7 — The chart keeps an env override path

The Helm chart's existing env→`Secret` injection (`KUBEDASH_JWT_SECRET`,
`KUBEDASH_SECRET_KEY`, OIDC secret via `secretKeyRef`) MUST continue to work —
those env vars override the INI. This change does NOT rewrite the chart to
mount a ConfigMap in this pass; the env path *is* the chart's injection path
(ADR-0006 single container unchanged).

## Non-goals

- No UI change (config is server-side only).
- No change to the multi-cluster registry model (ADR-0002) — `[k8s]` is
  retired, not turned into a registry-config section.
- No change to the chart's deployment shape (ADR-0006) or its Secret model;
  the chart keeps injecting secrets via env override.
- No new runtime dependency — `configparser` is stdlib (air-gap, ADR-0020).
- No change to the RQ/leader-election, SSE, or push transport (ADR-0007/0008/0009).
