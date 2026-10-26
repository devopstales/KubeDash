# Tasks — Configuration source: kubedash.ini (4.1 format)

> **STATUS:** `sliced` (2026-10-26)

> Sliced from `.skillgrid/specs/2026-10-26-ini-config-source/blueprint.md`.
> Vertical tracer-bullet tickets, dependency-ordered, sized for one fresh agent context window.

## Epic Summary

Make `kubedash.ini` (the 4.1 format, minus plugins) the primary configuration source, with
`KUBEDASH_*` env as a higher-priority override and no hard-coded in-code defaults for
identities/credentials (fail fast at boot). The app discovers `KUBEDASH_HOME` (env, else
`wsgi.py`'s dir = `<repo>/backend`) and derives `<home>/kubedash.ini` + `<home>/static` from it;
`KUBEDASH_STATIC_DIR` is dropped. ADR-0028 (supersedes-in-part ADR-0021's bootstrap-admin
delivery).

## Delivery Strategy

| Field | Value |
|-------|-------|
| Estimated changed lines | ~900-1100 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (TICKET-01) → PR 2 (TICKET-02) → PR 3 (TICKET-03) → PR 4 (TICKET-04) → PR 5 (TICKET-05) |
| Delivery strategy | feature-branch-chain |
| Chain strategy | feature-branch-chain |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: feature-branch-chain
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | INI>env>override resolution core + `home_paths()` + `Settings` projection + reset contract | PR 1 | `cd backend && uv run pytest tests/test_ini_config.py -v` | N/A (in-process unit; no runtime) | `app/core/ini_config.py` + the `default_factory` field rewrites (revert = back to env+defaults) |
| 2 | Full 4.1 schema (all `_FIELDS`, both split-or-url resolvers, bools, `sso_bootstrap_users`) | PR 2 | `cd backend && uv run pytest tests/test_ini_config.py -k "database or remote or sso or app_mode" -v` | N/A (in-process unit) | the `_FIELDS` completion + `_resolve_database`/`_resolve_redis` |
| 3 | Fail-fast on `REQUIRED` + retire `[k8s]`/`[plugin_settings]` (ADR-0021 supersede) | PR 3 | `cd backend && uv run pytest tests/test_ini_config.py -k "required_key or retired" -v` | N/A (in-process unit) | the `REQUIRED` frozenset + the fail-fast branch in `resolve` |
| 4 | Ship `kubedash.ini.example` + strip in-code identity defaults + wsgi.py WHY-comment | PR 4 | `cd backend && uv run pytest tests/test_ini_config.py -k example -v` | N/A (in-process unit) | `kubedash.ini.example` + the dead-default strip in `config.py` |
| 5 | Dev wiring (4 Taskfile targets drop `KUBEDASH_STATIC_DIR`) + Dockerfile `KUBEDASH_HOME` + chart env-override note | PR 5 | `task dev-stack && curl -s localhost:8080/healthz` | real dev stack (compose + backend) | `Taskfile.yaml` + `Dockerfile` + `backend/kubedash.ini` (revert = back to inline env) |

> The four plain-text guard lines above are the **contract** — `skillgrid:subagent-execution`
> matches them literally.

## Tickets

### TICKET-01 — INI>env>override resolution core + home derivation + Settings projection

- **Tracker ID:** TASK-033
- **Scope:** New `app/core/ini_config.py` (home discovery, `home_paths()`, `load_ini`,
  `apply_overrides`, `resolve`, `reset`, `ConfigError`) with a partial `_FIELDS` (security +
  behavior/optional knobs); rewrite `config.py` fields to `default_factory=ini_config.resolve`;
  wire `create_app` to `apply_overrides` first + `register_static` to `home_paths()["static"]`;
  update the test reset contract to `ini_config.reset()` + `KUBEDASH_HOME` fixtures.
- **Acceptance:** `tests/test_ini_config.py` green for `ini-provides-value`, `env-overrides-ini`,
  `override-beats-env-and-ini`, `optional-and-behavior-knobs-keep-defaults`,
  `home-paths-derived-from-kubedash-home`, `home-falls-back-to-wsgi-dir`,
  `static-dir-from-home-paths`; full suite (`uv run pytest -m "not integration" -q`) green.
- **SATISFIES:** `ini-provides-value`, `env-overrides-ini`, `override-beats-env-and-ini`,
  `optional-and-behavior-knobs-keep-defaults`, `home-paths-derived-from-kubedash-home`,
  `home-falls-back-to-wsgi-dir`, `static-dir-from-home-paths`
- **Files:** `backend/app/core/ini_config.py` (new), `backend/app/core/config.py`,
  `backend/app/__init__.py`, `backend/wsgi.py`, `backend/tests/conftest.py`,
  `backend/tests/api/conftest.py`, `backend/tests/test_static.py`,
  `backend/tests/test_ini_config.py` (new)
- **Size:** ~700 (M)
- **Blocks:** TICKET-02, TICKET-03, TICKET-04, TICKET-05
- **Blocked by:** none
- **Precondition:** `backend/.venv` exists (`uv sync` run) so `uv run pytest` works.
- **Fails-when:** `uv run pytest tests/test_ini_config.py -v` exits non-zero, or the full unit
  suite reports a failure.

### TICKET-02 — Full 4.1 INI schema (database/remote_cache/sso/deployment, split-or-url, bools)

- **Tracker ID:** TASK-034
- **Scope:** Complete `_FIELDS` for every current `Settings` field; add `_resolve_database`
  (split-or-url + `quote_plus`) and `_resolve_redis` (split-or-url, port/db defaults); `flask_env`
  DEFAULT/no-leak fallback; `sso_bootstrap_users` optional; bool parse for `tls_edge`/
  `cookie_secure`.
- **Acceptance:** `tests/test_ini_config.py` green for `database-split-or-url`
  (incl. `quote_plus`), `remote-cache-split-or-url`; full unit suite green.
- **SATISFIES:** `database-split-or-url`, `remote-cache-split-or-url`
- **Files:** `backend/app/core/ini_config.py`, `backend/app/core/config.py`,
  `backend/tests/test_ini_config.py`
- **Size:** ~500 (M)
- **Blocks:** TICKET-03, TICKET-04, TICKET-05
- **Blocked by:** TICKET-01
- **Fails-when:** `uv run pytest tests/test_ini_config.py -k "database or remote or sso or app_mode" -v`
  exits non-zero.

### TICKET-03 — Fail-fast on required keys + retire [k8s]/[plugin_settings]

- **Tracker ID:** TASK-035
- **Scope:** Define `REQUIRED = {kubedash_jwt_secret, kubedash_secret_key, bootstrap_admin_email,
  bootstrap_admin_password, admin_kubeconfig}`; `resolve` raises `ConfigError` for these when
  absent from overrides/env/INI; confirm `[k8s]`/`[plugin_settings]` are unmapped (a 4.1 file
  with them loads fine).
- **Acceptance:** `tests/test_ini_config.py` green for `required-key-missing-fails-fast`,
  `retired-k8s-and-plugin-sections-ignored`; full unit suite green.
- **SATISFIES:** `required-key-missing-fails-fast`, `retired-k8s-and-plugin-sections-ignored`
- **Files:** `backend/app/core/ini_config.py`, `backend/tests/test_ini_config.py`
- **Size:** ~250 (S)
- **Blocks:** TICKET-04, TICKET-05
- **Blocked by:** TICKET-02
- **Reversibility:** one-way   # supersedes-in-part ADR-0021's bootstrap-admin delivery; human checkpoint before commit
- **Fails-when:** `uv run pytest tests/test_ini_config.py -k "required_key or retired" -v` exits
  non-zero.

### TICKET-04 — Ship kubedash.ini.example + strip in-code identity defaults

- **Tracker ID:** TASK-036
- **Scope:** Create `backend/kubedash.ini.example` (4.1 format, empty secrets, commented
  retired sections); strip the dead in-code defaults from `config.py` (identity/credential fields
  are `default_factory=ini_config.resolve` with no literal; only optional/behavior knobs keep a
  literal); add the `wsgi.py` WHY-comment (env-only process knobs).
- **Acceptance:** `test_example_file_parses_and_has_no_secrets` green (parses with interpolation
  off, `[security]` secrets + `[sso_settings] secret` empty); full unit suite green.
- **SATISFIES:** `existing-fixtures-keep-working`
- **Files:** `backend/kubedash.ini.example` (new), `backend/app/core/config.py`,
  `backend/wsgi.py`, `backend/tests/test_ini_config.py`
- **Size:** ~250 (S)
- **Blocks:** TICKET-05
- **Blocked by:** TICKET-03
- **Fails-when:** `uv run pytest tests/test_ini_config.py -k example -v` exits non-zero.

### TICKET-05 — Dev wiring (Taskfile + Dockerfile) + chart env-override backstop

- **Tracker ID:** TASK-037
- **Scope:** Create `backend/kubedash.ini` (gitignored, dev values); drop `KUBEDASH_STATIC_DIR`
  from all four Taskfile targets (`backend-run`, `backend-run-worker`, `dev-stack`,
  `dev-stack-ssl`) and the inline bootstrap/cookie env (INI carries them); keep
  `KUBEDASH_ROLE`/`KUBEDASH_REPLICA_ID`/`FLASK_RUN_PORT` + the ssl overrides; Dockerfile drops
  `KUBEDASH_STATIC_DIR`, bakes `KUBEDASH_HOME=/app`; chart `deployment.yaml`/`secret.yaml` get the
  WHY-comment + `KUBEDASH_HOME` note; finalize `adr.md` manifest.
- **Acceptance:** `task dev-stack` boots from `backend/kubedash.ini` (healthz 200, SPA from
  `backend/static`, `KUBEDASH_ROLE=leader` from INI, no `KUBEDASH_STATIC_DIR`); `helm template`
  shows the `KUBEDASH_JWT_SECRET` secretKeyRef (env overrides INI); full unit suite + `fe-build`
  green.
- **SATISFIES:** `dev-stack-boots-from-ini`, `chart-env-overrides-ini`
- **Files:** `backend/kubedash.ini` (new, gitignored), `backend/.gitignore`, `Taskfile.yaml`,
  `backend/Dockerfile`, `charts/kubedash/templates/deployment.yaml`,
  `charts/kubedash/templates/secret.yaml`, `.skillgrid/specs/2026-10-26-ini-config-source/adr.md`
- **Size:** ~300 (S)
- **Blocks:** none
- **Blocked by:** TICKET-04
- **Precondition:** `task dev-stack` prerequisites met (Docker for compose; `backend/.venv`).
- **Fails-when:** `curl -s localhost:8080/healthz` does not return 200, or the boot log does not
  show the INI's `KUBEDASH_ROLE=leader`.

## Dependency Graph

```mermaid
graph LR
    T01[TICKET-01] --> T02[TICKET-02]
    T02 --> T03[TICKET-03]
    T03 --> T04[TICKET-04]
    T04 --> T05[TICKET-05]
```

## Execution Order

- **Wave 1:** TICKET-01
- **Wave 2:** TICKET-02 (after TICKET-01)
- **Wave 3:** TICKET-03 (after TICKET-02) — one-way checkpoint (ADR-0021 supersede)
- **Wave 4:** TICKET-04 (after TICKET-03)
- **Wave 5:** TICKET-05 (after TICKET-04) — dev-stack backstop

> **Acceptance-first (BDD is always on):** each ticket's `SATISFIES` scenario is written and
> confirmed RED *before* the implementation that makes it green. The tickets are serial (each
> builds on the previous `ini_config` state), so there is no parallel wave — the tracer-thread
> shape thickens one slice at a time.

## Slicing Notes

- **Serial, not parallel.** The change is one concern (config resolution) thickened across 5
  slices; each ticket depends on the previous ticket's `ini_config`/`config.py` state. No
  independent tickets exist to parallelize — this matches the blueprint's Tracer-thread shape.
- **One-way checkpoint on TICKET-03.** The ADR-0021 supersede (bootstrap-admin values become
  INI-required) is the single hard-to-reverse decision; `Reversibility: one-way` inserts a human
  checkpoint before that commit.
- **Interface frozen at TICKET-01.** `ini_config.resolve`/`load_ini`/`apply_overrides`/
  `home_paths()`/`reset()`/`ConfigError` are defined once in TICKET-01 and consumed unchanged by
  TICKET-02..05 (the `_FIELDS` table grows; the function signatures do not change).
- **`existing-fixtures-keep-working` is a regression truth** enforced by the full-suite step in
  every code ticket (TICKET-01..04), not a standalone ticket — it is the R6 demotion (fixtures
  gain `KUBEDASH_HOME` sourcing, access pattern unchanged).
- **`fe-sync` is unchanged** — it still writes `frontend/dist → backend/static`, which is the
  derived `<KUBEDASH_HOME>/static`; only `KUBEDASH_STATIC_DIR` (the env read of that path) is
  dropped.
