# Configuration source: kubedash.ini — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR bodies 0001–0013
> have index entries but no bodies on disk (per AGENTS.md); the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0002 (multi-cluster registry) | `[k8s]` is **retired, not ported** — 5.0 has no single configured cluster; the admin cluster stays `admin_kubeconfig`/in-cluster and member clusters stay DB rows. The INI does not introduce a registry-config section. |
| ADR-0006 (single container) | Unchanged. The config source moves from env to INI+env-override inside the same container; the chart keeps injecting secrets via env→Secret (`secretKeyRef`), which now *overrides* the INI. No second container. |
| ADR-0020 (air gap) | `configparser` is stdlib; no new runtime dependency, no new egress. |
| ADR-0021 (local admin auth) | **Superseded-in-part (delivery mechanism only).** The bootstrap-admin *values* (`email`/`password`) move from env-primary to INI-primary; env still overrides. The auth *mechanism* (bootstrap upsert at boot, `POST /auth/local`) is unchanged. See "Recorded deviations". |
| ADR-0025 (HttpOnly session cookie) | `cookie_secure` keeps its fail-closed `True` default — it is one of the two allowed in-code *behavior* defaults. |
| ADR-0027 (plain-HTTP dev-stack) | The dev `kubedash.ini` carries `cookie_secure=false` for the plain path and the TLS path flips it via the `[deployment]` section / env override; the dev-stack default behavior is unchanged. |

## Decision created by this change

| ADR | Status | Path |
|-----|--------|------|
| ADR-0028 — Configuration source: `kubedash.ini` (4.1 format, minus plugins) primary, `KUBEDASH_*` env override, no hard-coded defaults for identities/credentials (fail fast at boot) | accepted | `../../knowledge/decisions/04-adr-0028-ini-config-source.md` |

## Recorded deviations from 4.1

- **`[k8s]` is ignored, not ported.** 4.1's `[k8s]` described one static cluster; 5.0 is a
  multi-cluster registry (ADR-0002). A 4.1 file with `[k8s]` still loads (the section is simply
  unmapped) instead of erroring.
- **`[plugin_settings]` is ignored, not ported.** No 5.0 plugin system (ADR-0022 dropped the
  group).
- **`[database] type=sqlite3` from a 4.1 file maps to Postgres** with a warning, not an error —
  5.0 is Postgres-only; tolerating the 4.1 default keeps an unedited 4.1 file bootable in dev.
- **`jwt_secret`/`secret_key` moved from `[security]` in-code defaults to INI-required.** 4.1
  carried `admin_password` in `[security]`; 5.0 also requires the JWT + kubeconfig-encryption
  keys there (one-way-door keys, ADR-0002), so they are INI-required with no code default.
- **Process/runtime knobs stay env-only** (`FLASK_RUN_PORT`, `KUBEDASH_STATIC_DIR`,
  `KUBEDASH_SSL_CERT`/`_KEY`) — these are not app config and are deliberately not INI fields.
