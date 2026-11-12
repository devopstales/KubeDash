---
type: InvariantContract
title: "Locked constraints — air-gap, session transport, encryption key, config fail-fast"
status: stable
anchors:
  - { path: "tests/fe-airgap-check.mjs", all_of: ["RE_HTTP", "RE_CDN"] }
  - { path: "backend/app/core/security.py", all_of: ["kd_access", "kd_refresh"] }
  - { path: "backend/app/core/ini_config.py", all_of: ["kubedash_secret_key", "KUBEDASH_SECRET_KEY"] }
claims:
  - { subject: "air-gap gate checks for external refs", literal: "RE_HTTP", path: "tests/fe-airgap-check.mjs" }
  - { subject: "session rides HttpOnly cookies", literal: "kd_access", path: "backend/app/core/security.py" }
  - { subject: "kubeconfig encryption key comes from config, never code", literal: "KUBEDASH_SECRET_KEY", path: "backend/app/core/ini_config.py" }
---

# Locked constraints

Must-hold tokens for KubeDash. Each is pinned by an anchor + claim — a
`projectwiki validate` drift means the constraint moved or the code drifted.
The ADR that pins each constraint is in `## Related`.

## AIR-GAP — zero outbound references in the built bundle

The built SPA bundle must contain no `https?://` or `//cdn.` reference whose
runtime execution would reach outside the deployment. The gate is
`task fe-check` (`tests/fe-airgap-check.mjs`, `RE_HTTP` / `RE_CDN`) and CI
runs the same script. Pinned by [[decisions/04-adr-0020-air-gap-deployment]].

## SESSION-TRANSPORT — HttpOnly cookies only

Browser credentials live exclusively in the HttpOnly cookies `kd_access`
(access) and `kd_refresh` (refresh) — `ACCESS_COOKIE` / `REFRESH_COOKIE` in
`backend/app/core/security.py`. No credentials in URLs or `localStorage`;
`Authorization: Bearer` is accepted **only** for the kubectl credential
plugin paths. Pinned by [[decisions/04-adr-0025-http-only-session-cookie]].

## ENCRYPTION-KEY — KUBEDASH_SECRET_KEY is the one-way door

Kubeconfigs at rest are AES-256-GCM encrypted with a key derived from
`KUBEDASH_SECRET_KEY` (`[security] secret_key`; env override
`KUBEDASH_SECRET_KEY`), distinct from the HS256 JWT key
(`jwt_secret`). Rotating it re-encrypts the registry — a one-way door.
Pinned by [[decisions/04-adr-0002-multi-cluster-registry]].

## CONFIG-FAIL-FAST — no fallback defaults for identities/credentials

`kubedash.ini` is the primary source, `KUBEDASH_*` env overrides, and missing
identity/credential keys raise `ConfigError` at boot. Do not add fallback
defaults. Pinned by [[decisions/04-adr-0028-ini-config-source]].

## Related

- [[decisions/04-adr-0020-air-gap-deployment]]
- [[decisions/04-adr-0025-http-only-session-cookie]]
- [[decisions/04-adr-0028-ini-config-source]]
- [[glossary/02-technical-terms]] — Config chain, K8sClientPool
