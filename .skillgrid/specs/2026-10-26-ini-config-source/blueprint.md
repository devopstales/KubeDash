# Configuration source: kubedash.ini (4.1 format) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files to touch, tests,
> and verification. The product *why* lives in `briefing.md` and ADR-0028. This blueprint is
> pure-technical and cites them rather than restating.

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution (recommended) or
> skillgrid:simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Status:** PROPOSED

**Tier:** T2 — cross-cutting config change; touches every config consumer, the test suite, and
the chart's env contract. Full blueprint (threat matrix below: both rows N/A, see its text).

**Classification:** `standard` (normal refactor, single concern: config resolution; verification
floor L2 — full backend suite + build). No new trust boundary, no migration, no public API break.

**Build shape:** Tracer thread — Task 1 proves the INI>env resolution end-to-end for one real key
in the test client (the thinnest path through the new layer); Tasks 2-3 thicken it (full schema,
fail-fast, retired sections); Task 4 ships the example + strips dead defaults; Task 5 is the
runtime/dev-loop + chart-env backstop.

**Goal:** Make `kubedash.ini` (4.1 format, minus plugins) the primary configuration source, with
`KUBEDASH_*` env as a higher-priority override and no hard-coded in-code defaults for
identities/credentials; a missing required value fails fast at boot.

**Architecture:** A new `app/core/ini_config.py` module owns the WHOLE resolution and is the
single source of truth: it parses the INI (`configparser`, interpolation OFF) and exposes
`resolve(field)`. `config.py`'s `Settings` becomes a *projection* — every field is a
`default_factory=lambda: ini_config.resolve("<field>")`, so pydantic-settings no longer reads
env (the `env_prefix`/`AliasChoices`/`.env` are retired as value sources — the alias moves into
`_FIELDS`). The precedence is one chain, implemented once:

```
overrides (create_app config_overrides)  >  env (KUBEDASH_* / unprefixed alias)
  >  INI value  >  behavior/optional default  >  ConfigError (required key missing)
```

The `overrides` leg is applied by `create_app` calling `ini_config.apply_overrides(mapping)`
BEFORE `get_settings()` builds the `Settings` (and before the fail-fast), so the existing
`create_app({"KUBEDASH_COOKIE_SECURE": False, ...})` seam keeps working — see Task 1. The
`get_settings()` public surface (`settings.<field>`) is preserved verbatim so the ~10 call sites
do not change. No new dependency (stdlib `configparser`), air-gap safe (ADR-0020).

**Tech Stack:** Python stdlib `configparser`, pydantic-settings (retained as the settings
*container*, not the value source), Flask `create_app` seam, Taskfile, Helm (env override only).

**Spec:** `briefing.md` (R1-R7).
**Findings:** 4.1 config audit — `git show 4.1:src/kubedash/kubedash.ini.example`,
`4.1:src/kubedash/lib/initializers.py:160-192` (the `configparser` read + mode select),
`4.1:src/kubedash/lib/init_functions.py` (per-section `.get()` consumers), `4.1:src/kubedash/lib/config.py`.
**In-force ADRs:** per `adr.md` — ADR-0002, ADR-0006, ADR-0020, ADR-0021 (superseded-in-part:
bootstrap-admin delivery), ADR-0025, ADR-0027; ADR-0028 created by this change.

## Terms

None (uses the spec's vocabulary; the 4.1 `kubedash.ini` is cited as prior art, not a term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- A `kubedash.ini` providing `[security] jwt_secret` makes `get_settings().kubedash_jwt_secret`
  return that value (`ini-provides-value`).
- Setting `KUBEDASH_KUBEDASH_JWT_SECRET` in env to a different value makes
  `get_settings().kubedash_jwt_secret` return the **env** value (env beats INI)
  (`env-overrides-ini`).
- `create_app({"KUBEDASH_COOKIE_SECURE": False, ...})` still yields `app.config[...]` with the
  override — the `config_overrides` seam applies *ahead of* env/INI (`override-beats-env-and-ini`).
- With neither env nor INI providing a required key, constructing the settings raises
  `ConfigError` naming the section and key (`required-key-missing-fails-fast`).
- `cookie_secure` resolves `True`, `flask_env` `development`, `kubedash_role` `worker`,
  `kubedash_replica_id` `local` when unset in both sources — the only allowed in-code defaults
  (`optional-and-behavior-knobs-keep-defaults`).
- `[database]` split fields AND a single `[database] url` both produce a valid `database_url`,
  with `quote_plus` applied to user/password (`database-split-or-url`).
- `[remote_cache]` split fields AND `[remote_cache] url` both produce a valid `redis_url`
  (`remote-cache-split-or-url`).
- A 4.1 file containing `[k8s]` and `[plugin_settings]` sections loads without error; those
  sections are ignored (`retired-k8s-and-plugin-sections-ignored`).
- The existing `api_app` fixture and the ~18 `monkeypatch.setenv("KUBEDASH_*", …)` sites keep
  passing — **no change to access pattern**; fixtures may GAIN a `KUBEDASH_CONFIG_FILE` /
  fixture-INI line (R6, demoted from "unchanged" — see Global Constraints)
  (`existing-fixtures-keep-working`).
- **backstop:** `task dev-stack` boots against `dev/kubedash.ini` and serves with the file's
  values; the Helm chart's env-injected secrets override the INI for the same keys
  (`dev-stack-boots-from-ini`, `chart-env-overrides-ini`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/core/ini_config.py` — INI parse + the full precedence chain; single source of
  truth for config values.
- `backend/kubedash.ini.example` — the committed 4.1-format template (R5).
- `backend/tests/test_ini_config.py` — the R1/R2/R3/R4 unit suite.
- `dev/kubedash.ini` — the gitignored dev copy (Task 5).
- `Taskfile.yaml` — `backend-run`/`backend-run-worker`/`dev-stack`/`dev-stack-ssl` point at the
  INI; inline env becomes the override (Task 5).
- `.skillgrid/knowledge/decisions/04-adr-0028-ini-config-source.md` — the ADR (already written).

**Key links** (critical connections that must work together):
- `create_app` MUST call `ini_config.apply_overrides(config_overrides)` and THEN `get_settings()`
  — the override leg is applied before the fail-fast `Settings` is built, or the existing
  `config_overrides` fixtures break. `get_settings()` is the one constructor; `create_app` no
  longer reads `settings.<field>` directly for the override seam (it hands overrides to
  `ini_config`).
- `ini_config` exposes `reset()` which sets BOTH `_settings = None` (in `config.py`) AND
  `_parser = None` (in `ini_config`). Every test that resets config calls `ini_config.reset()` —
  this is the one test-contract change (R6 demotion). The parser cache is the staleness source
  the critic flagged; `reset()` is the fix.
- `wsgi.py`'s direct `os.environ.get("KUBEDASH_STATIC_DIR")` / `FLASK_RUN_PORT` / `KUBEDASH_SSL_*`
  reads stay env-only — process/runtime knobs, NOT app config, explicitly excluded from the INI.
  `wsgi.py`'s `get_settings().tls_edge` / `.kubedash_role` calls are unchanged (they read the
  INI/env-resolved values, not `config_overrides`).
- The unprefixed `DATABASE_URL`/`REDIS_URL` aliases (ARCHITECTURE.md §3.8) live in `_FIELDS` as a
  second `env_name`; `config.py` drops the dead `AliasChoices`. `KUBEDASH_*` prefix wins when both
  set.

**One-way-door decisions:**
- **Supersedes-in-part ADR-0021's delivery mechanism** (bootstrap-admin values move from
  env-primary to INI-primary, env-override). The `required-key-missing-fails-fast` scenario is the
  mechanism of the supersede. Flagged so the operator re-confirms before Task 3's commit.
  `> ⚠ one-way:` on Task 3.
- No DB migration, no public API break, no new dependency.

## Global Constraints

- No new Python dependency (air-gap, ADR-0020) — `configparser` is stdlib.
- **Precedence is exactly:** `overrides > env > INI > optional/behavior default > ConfigError`.
  Implemented once in `ini_config.resolve` / `apply_overrides`.
- **Allowed in-code defaults (optional/behavior knobs ONLY):** `cookie_secure` (`True`),
  `flask_env`/`app_mode` (`development`), `kubedash_role` (`worker`), `kubedash_replica_id`
  (`local`), and the empty-string optionals `cors_origins`/`plugin_server`/`sso_bootstrap_users`
  (`""`). Everything else (identities/credentials) is REQUIRED and fails fast.
- `configparser` is constructed with `interpolation=None` (4.1 files / base64 secrets may contain
  `%`; default BasicInterpolation would raise `InterpolationSyntaxError`).
- Bool INI values parse case-insensitively from `true/1/yes/on`; any other value is `ConfigError`.
- The 4.1 `[k8s]` and `[plugin_settings]` sections are ignored at load (briefing R4).
- `flask_env` reads `app_mode`; to avoid `configparser` DEFAULT-section leakage it is read from the
  literal `DEFAULT` section AND falls back to `[deployment] app_mode` (documented, tested).
- **R6 (demoted):** "no change to access pattern for the ~10 `get_settings()` call sites and the
  ~18 env-injecting sites; fixtures MAY gain a `KUBEDASH_CONFIG_FILE`/fixture-INI line and the
  reset becomes `ini_config.reset()`." (The critic confirmed "fully unchanged" is impossible once
  fail-fast is on.)
- Conventional commits; spec-zone commits precede code-zone commits (`pre-commit` zone guard);
  WHY-comments on load-bearing invariants (AGENTS.md).
- The chart is NOT rewritten in this pass — its env→Secret path is the override (briefing R7).
  **Deployment note:** the chart's `Secret` today carries `KUBEDASH_JWT_SECRET`,
  `KUBEDASH_SECRET_KEY`, and the OIDC secret (3 of the 5 REQUIRED keys). `bootstrap_admin_*` and
  `admin_kubeconfig` are NOT in the chart secret — a fresh release with an INI present must supply
  those via the INI (or env) or it fails fast. This is intended (fail-fast) and is recorded here so
  the operator is not surprised; the chart env path is unchanged.

## Threat Matrix

No routing / shell / subprocess / VCS-automation / PR-automation / executable-classification /
process-integration / Mnemonic-contract boundary is introduced. The INI is a plain data file read
at boot; the only new surface is the `KUBEDASH_CONFIG_FILE` path.

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Shell/subprocess | N/A: no subprocess spawned; the Taskfile only adds a `KUBEDASH_CONFIG_FILE` assignment (no new command/quoting surface). | Reuse `{{.TASKFILE_DIR}}/dev/kubedash.ini`; no new shell syntax. | Covered by the `dev-stack-boots-from-ini` backstop (Task 5), not a separate RED. |
| Path / file classification | N/A: the INI is read with `configparser.read()` (no `os.access`/mode/exec check); `KUBEDASH_CONFIG_FILE` is operator-supplied, never executed. | Absent file is tolerated until a required key is resolved, then `ConfigError` names the missing section/key. | `ini-provides-value` (Task 1) and `required-key-missing-fails-fast` (Task 3). |

---

### Task 1: INI>env>override resolution core + the `Settings` projection + reset contract

**SATISFIES:** `ini-provides-value`, `env-overrides-ini`, `override-beats-env-and-ini`,
`optional-and-behavior-knobs-keep-defaults`, `existing-fixtures-keep-working`

**Files:**
- Create: `backend/app/core/ini_config.py`
- Modify: `backend/app/core/config.py` (fields → `default_factory=ini_config.resolve`; drop
  `env_prefix`/`AliasChoices`/`env_file` as value sources; add `ini_config.reset()` that clears
  `_settings`)
- Modify: `backend/app/__init__.py` (`create_app` calls `ini_config.apply_overrides(overrides)`
  BEFORE `get_settings()`; stop reading `settings.<field>` for the seam)
- Modify: `backend/tests/conftest.py` + `backend/tests/api/conftest.py` (reset via
  `ini_config.reset()`; point `KUBEDASH_CONFIG_FILE` at a fixture INI that carries the required
  keys — the R6 demotion)
- Test: `backend/tests/test_ini_config.py` (new)

**Interfaces:**
- Consumes: nothing from earlier tasks (first code task).
- Produces:
  - `ini_config.reset() -> None` — sets `config._settings = None` **and** `ini_config._parser =
    None`. The single reset entry point for tests.
  - `ini_config.load_ini(path: str | None = None) -> configparser.ConfigParser` — `ConfigParser(
    interpolation=None)`; reads `path` or `KUBEDASH_CONFIG_FILE` or `kubedash.ini` in CWD; absent
    file → empty parser (only fatal when a required key is resolved).
  - `ini_config.apply_overrides(mapping: Mapping[str, object]) -> None` — copies the override
    values into a module-level `_overrides` dict keyed by FIELD NAME (the mapping's keys are the
    `KUBEDASH_*`/unprefixed env names; `_ENV_TO_FIELD` maps them back to field names). Cleared by
    `reset()`.
  - `ini_config.resolve(field: str) -> str` — the chain: `_overrides` → env (`_FIELDS` env names)
    → INI → default (`_FIELDS` `has_default`) → `ConfigError`.
  - `ini_config.ConfigError` — `Exception` with `.field`, `.section`, `.key`.
  - `config.get_settings()` — unchanged signature; `settings.<field>` reads through
    `ini_config.resolve`. The `_settings` singleton + `reset()` contract is what tests use.
- Seam: `ini_config.resolve` + `apply_overrides` — the precedence is implemented once.
- Deletion test: deleting `ini_config.py` removes the single precedence owner; `Settings` fields
  re-introduce in-code defaults or break the import — the silent-default foot-gun this removes
  (callers: `app/__init__.py`, `app/core/leader.py`, `app/core/security.py`,
  `app/services/k8s_client.py`, `app/api/*`).
- Adapters: 2 — the real INI (dev/prod) and the fixture INI (tests), so the seam is justified.

- [ ] **Step 1: Write the failing tests** — `backend/tests/test_ini_config.py`.

```python
import pytest
import app.core.config as _config
from app.core import ini_config


def _write_ini(tmp_path, text):
    p = tmp_path / "kubedash.ini"
    p.write_text(text)
    return str(p)


def test_ini_provides_value(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[security]\njwt_secret = from-ini\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().kubedash_jwt_secret == "from-ini"


def test_env_overrides_ini(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[security]\njwt_secret = from-ini\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    monkeypatch.setenv("KUBEDASH_KUBEDASH_JWT_SECRET", "from-env")
    ini_config.reset()
    assert _config.get_settings().kubedash_jwt_secret == "from-env"


def test_override_beats_env_and_ini(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[security]\njwt_secret = from-ini\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    monkeypatch.setenv("KUBEDASH_KUBEDASH_JWT_SECRET", "from-env")
    from app import create_app
    ini_config.reset()
    app = create_app({"KUBEDASH_KUBEDASH_JWT_SECRET": "from-override", "TESTING": True})
    assert _config.get_settings().kubedash_jwt_secret == "from-override"


def test_optional_and_behavior_knobs_keep_defaults(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[DEFAULT]\napp_mode = production\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    s = _config.get_settings()
    assert s.cookie_secure is True        # fail-closed default (ADR-0025/0027)
    assert s.flask_env == "production"    # INI value
    assert s.kubedash_role == "worker"    # optional default
    assert s.kubedash_replica_id == "local"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/test_ini_config.py -v`
Expected: FAIL — `ModuleNotFoundError: app.core.ini_config`.

- [ ] **Step 3: Write `backend/app/core/ini_config.py`** (core; `_FIELDS` partial here, completed
  in Task 2).

```python
"""Single source of truth for configuration values (ADR-0028).

Precedence per field, one chain:
    create_app overrides  >  env (KUBEDASH_* / unprefixed alias)  >  INI
      >  optional/behavior default  >  ConfigError (required key missing).
configparser with interpolation OFF (4.1/base64 values may contain '%').
"""
import configparser
import os
from collections.abc import Mapping

# field -> (section, key, env_names, has_default, default, is_bool)
_FIELDS: dict[str, tuple[str, str, tuple[str, ...], bool, str, bool]] = {
    "kubedash_jwt_secret": ("security", "jwt_secret",
        ("KUBEDASH_KUBEDASH_JWT_SECRET", "KUBEDASH_JWT_SECRET"), False, "", False),
    "kubedash_secret_key": ("security", "secret_key",
        ("KUBEDASH_SECRET_KEY",), False, "", False),
    "bootstrap_admin_password": ("security", "admin_password",
        ("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD",), False, "", False),
    # ... remaining fields completed in Task 2 ...
    "flask_env": ("DEFAULT", "app_mode", ("KUBEDASH_FLASK_ENV",), True, "development", False),
    "cookie_secure": ("deployment", "cookie_secure", ("KUBEDASH_COOKIE_SECURE",), True, "true", True),
    "kubedash_role": ("deployment", "kubedash_role", ("KUBEDASH_ROLE",), True, "worker", False),
    "kubedash_replica_id": ("deployment", "kubedash_replica_id",
        ("KUBEDASH_REPLICA_ID",), True, "local", False),
}

# env name -> field (for apply_overrides)
_ENV_TO_FIELD = {e: f for f, (_, _, envs, *_r) in _FIELDS.items() for e in envs}

REQUIRED: frozenset[str] = frozenset({
    "kubedash_jwt_secret", "kubedash_secret_key",
    "bootstrap_admin_email", "bootstrap_admin_password", "admin_kubeconfig",
})


class ConfigError(Exception):
    def __init__(self, field: str, section: str, key: str):
        self.field, self.section, self.key = field, section, key
        super().__init__(f"missing required config {field!r} (INI [{section}] {key} or env)")


_parser: configparser.ConfigParser | None = None
_overrides: dict[str, object] = {}


def reset() -> None:
    global _parser
    _parser = None
    _overrides.clear()
    import app.core.config as _c
    _c._settings = None


def load_ini(path: str | None = None) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path or os.environ.get("KUBEDASH_CONFIG_FILE", "kubedash.ini"))
    return parser


def _get_parser() -> configparser.ConfigParser:
    global _parser
    if _parser is None:
        _parser = load_ini()
    return _parser


def apply_overrides(mapping: Mapping[str, object]) -> None:
    for key, value in (mapping or {}).items():
        field = _ENV_TO_FIELD.get(key) or _ENV_TO_FIELD.get(key.replace("KUBEDASH_", "", 1))
        if field is not None:
            _overrides[field] = value


def _parse_bool(value: str, field: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise ConfigError(field, "ini", f"bool for {field}")


def resolve(field: str) -> str:
    section, key, env_names, has_default, default, is_bool = _FIELDS[field]
    if field in _overrides and _overrides[field] is not None:
        val = _overrides[field]
        return val if isinstance(val, str) else str(val)
    for env in env_names:
        ev = os.environ.get(env)
        if ev is not None and ev != "":
            return ev
    ini = _get_parser().get(section, key, fallback=None)
    if ini is not None and ini != "":
        return ini
    if has_default:
        return default
    if field in REQUIRED:
        raise ConfigError(field, section, key)
    return ""
```

- [ ] **Step 4: Rewrite `config.py`** — every field becomes
  `Field(default_factory=lambda: ini_config.resolve("<field>"))`; drop `env_prefix`,
  `AliasChoices`, `env_file` from `model_config` (keep `extra="ignore"`); keep the `_settings`
  global + `get_settings()`. Example (repeat per field, completed in Task 2):

```python
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.core import ini_config


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")
    kubedash_jwt_secret: str = Field(
        default_factory=lambda: ini_config.resolve("kubedash_jwt_secret"))
    # ... all other fields the same (Task 2 completes the table) ...
```

- [ ] **Step 5: Wire `create_app`** — in `app/__init__.py`, the FIRST line of `create_app`
  becomes `ini_config.apply_overrides(overrides)`; the existing `settings = get_settings()` then
  runs and the fail-fast is satisfied by the overrides (for the fixture INI keys) + INI + env.
  Replace the `overrides.get("KUBEDASH_COOKIE_SECURE", settings.cookie_secure)` style reads with
  `app.config["KUBEDASH_COOKIE_SECURE"] = str(get_settings().cookie_secure)` (the override already
  applied in `ini_config`).

- [ ] **Step 6: Update the test reset contract** — `tests/conftest.py` and `tests/api/conftest.py`:
  replace `_config._settings = None` with `ini_config.reset()`; add
  `monkeypatch.setenv("KUBEDASH_CONFIG_FILE", <fixture ini with the required keys>)` to `api_app`.
  (The R6 demotion — fixtures gain config sourcing, access pattern unchanged.)

- [ ] **Step 7: Run test to verify it passes**

Run: `cd backend && uv run pytest tests/test_ini_config.py -v`
Expected: PASS (4 tests).

- [ ] **Step 8: Full suite regression**

Run: `cd backend && uv run pytest -m "not integration" -q`
Expected: PASS — the ~18 `setenv` sites + the `api_app` fixture (now with a fixture INI) stay
green (R6).

- [ ] **Step 9: Commit**

```bash
git add backend/app/core/ini_config.py backend/app/core/config.py backend/app/__init__.py \
        backend/tests/conftest.py backend/tests/api/conftest.py backend/tests/test_ini_config.py
git commit -m "feat(config): INI>env>override resolution core; Settings projects from ini_config"
```

### Task 2: Full 4.1 schema mapping (all `Settings` fields, both split-or-url paths, bools)

**SATISFIES:** `database-split-or-url`, `remote-cache-split-or-url`, `existing-fixtures-keep-working`

**Files:**
- Modify: `backend/app/core/ini_config.py` (complete `_FIELDS`; `_resolve_database`,
  `_resolve_redis`, bool parse; `flask_env` DEFAULT/no-leak; `sso_bootstrap_users` optional)
- Modify: `backend/app/core/config.py` (point every remaining field at `ini_config.resolve`)
- Test: `backend/tests/test_ini_config.py` (add the schema cases)

**Interfaces:**
- Consumes: `ini_config.resolve`, `ini_config._get_parser`, `ini_config.ConfigError` (Task 1).
- Produces: the complete `_FIELDS` table covering EVERY current `Settings` field — `database_url`,
  `redis_url`, `oidc_client_id`/`oidc_client_secret`/`oidc_issuer`, `admin_kubeconfig`,
  `plugin_server`, `cors_origins`, `sso_bootstrap_users` (optional, default `""`),
  `bootstrap_admin_email`, `tls_edge` (bool), `first_paint_backstop`, `namespace_list_timeout`.
  - `[database]` (special-cased in `_resolve_database`): `url` wins if present; else
    `postgresql://{quote_plus(user)}:{quote_plus(password)}@{host}/{name}` where `host` is
    `host[:port]` as written (4.1 style `db:5432`); `type` is read for the sqlite→postgres
    warning only and does NOT change the driver (documented).
  - `[remote_cache]` (special-cased in `_resolve_redis`): `url` wins if present; else
    `redis://{host}:{port}/{db}` with `port` defaulting to `6379` and `db` to `0`; optional
    `password` → `redis://:pass@host:port/db`.
  - `flask_env`: read `app_mode` from the literal `DEFAULT` section; if absent, fall back to
    `[deployment] app_mode`; a `app_mode` set under an unrelated section must NOT leak (tested).
  - `sso_bootstrap_users`: INI `[sso_settings] bootstrap_users`, optional, default `""` (an
    SSO-optional knob, same class as `cors_origins`).
  - bool fields (`tls_edge`, `cookie_secure`) parse via `_parse_bool` (Task 1).
- Seam / Deletion test / Adapters: same as Task 1.

- [ ] **Step 1: Write the failing tests** — add to `backend/tests/test_ini_config.py`.

```python
def test_database_split_fields(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://u:p@db:5432/kubedash"


def test_database_split_quotes_password(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p@ss:wd\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://u:p%40ss%3Awd@db:5432/kubedash"


def test_database_url_wins_over_split(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p\nurl = postgresql://x:y@z/q\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://x:y@z/q"


def test_remote_cache_split_or_url(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[remote_cache]\nredis_host = cache:6380\nredis_db = 2\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().redis_url == "redis://cache:6380/2"
    ini = _write_ini(tmp_path, "[remote_cache]\nurl = redis://other:6379/9\nredis_host = cache\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    assert _config.get_settings().redis_url == "redis://other:6379/9"


def test_sso_and_deployment_and_optional(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[sso_settings]\nissuer_url = https://idp\nclient_id = cid\nsecret = csec\nbootstrap_users = a@x,b@y\n[deployment]\nkubedash_role = leader\ntls_edge = true\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    s = _config.get_settings()
    assert s.oidc_issuer == "https://idp" and s.oidc_client_id == "cid"
    assert s.oidc_client_secret == "csec" and s.sso_bootstrap_users == "a@x,b@y"
    assert s.kubedash_role == "leader" and s.tls_edge is True


def test_app_mode_no_default_leak(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[deployment]\napp_mode = production\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    # app_mode under [deployment] is seen (fallback), not from a leaked DEFAULT
    assert _config.get_settings().flask_env == "production"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/test_ini_config.py -k "database or remote or sso or app_mode" -v`
Expected: FAIL — `ConfigError` / wrong value for the unmapped fields.

- [ ] **Step 3: Complete `_FIELDS` + `_resolve_database` + `_resolve_redis`** in `ini_config.py`
  (fill the `# ... remaining fields ...` from Task 1; add the two special-case resolvers and the
  `flask_env` fallback; wire `resolve` to call them for `database_url`/`redis_url`/`flask_env`).

- [ ] **Step 4: Point every remaining `config.py` field at `ini_config.resolve`.**

- [ ] **Step 5: Run test to verify it passes** — `cd backend && uv run pytest tests/test_ini_config.py -v`

- [ ] **Step 6: Full suite regression** — `cd backend && uv run pytest -m "not integration" -q`

- [ ] **Step 7: Commit**

```bash
git add backend/app/core/ini_config.py backend/app/core/config.py backend/tests/test_ini_config.py
git commit -m "feat(config): full 4.1 INI schema (database/remote_cache/sso/deployment, split-or-url, bools)"
```

### Task 3: Fail-fast on required keys + retire `[k8s]`/`[plugin_settings]`

> ⚠ **one-way:** this task makes the ADR-0021 supersede real — bootstrap-admin values become
> INI-required (env-override). You are about to make these values mandatory from the file. STOP
> here and confirm before committing.

**SATISFIES:** `required-key-missing-fails-fast`, `retired-k8s-and-plugin-sections-ignored`

**Files:**
- Modify: `backend/app/core/ini_config.py` (confirm `REQUIRED` set; confirm retired sections are
  unmapped)
- Test: `backend/tests/test_ini_config.py` (add the fail-fast + retired-section cases)

**Interfaces:**
- Consumes: `ini_config.resolve`, `ini_config.ConfigError`, `ini_config.REQUIRED` (Task 1).
- Produces: `REQUIRED = {kubedash_jwt_secret, kubedash_secret_key, bootstrap_admin_email,
  bootstrap_admin_password, admin_kubeconfig}`; `resolve` raises `ConfigError` for these when
  absent from overrides/env/INI. Retired sections (`k8s`, `plugin_settings`) have no `_FIELDS`
  entry, so a 4.1 file with them loads fine.

- [ ] **Step 1: Write the failing tests**

```python
def test_required_key_missing_fails_fast(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path, "[DEFAULT]\napp_mode = development\n")  # no [security]
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    for v in ("KUBEDASH_KUBEDASH_JWT_SECRET", "KUBEDASH_BOOTSTRAP_ADMIN_EMAIL",
              "KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "KUBEDASH_SECRET_KEY", "KUBEDASH_ADMIN_KUBECONFIG"):
        monkeypatch.delenv(v, raising=False)
    ini_config.reset()
    with pytest.raises(ini_config.ConfigError) as e:
        _config.get_settings()
    assert "jwt_secret" in str(e.value)


def test_retired_k8s_and_plugin_sections_ignored(tmp_path, monkeypatch):
    ini = _write_ini(tmp_path,
        "[security]\njwt_secret = a\nsecret_key = b\nadmin_password = c\n"
        "[bootstrap]\nbootstrap_admin_email = a@x\n"
        "[deployment]\nadmin_kubeconfig = /kc\n"
        "[k8s]\ncluster_name = kdev\napi_server = https://x\napi_ca = Zm9v\n"
        "[plugin_settings]\nregistry = true\n")
    monkeypatch.setenv("KUBEDASH_CONFIG_FILE", ini)
    ini_config.reset()
    s = _config.get_settings()  # must NOT raise on [k8s]/[plugin_settings]
    assert s.kubedash_jwt_secret == "a" and s.admin_kubeconfig == "/kc"
```

- [ ] **Step 2: Run test to verify it fails** — `cd backend && uv run pytest tests/test_ini_config.py -k "required_key or retired" -v`

- [ ] **Step 3: Confirm `REQUIRED` + the fail-fast branch in `resolve`** (already sketched in
  Task 1) and that no field maps to `[k8s]`/`[plugin_settings]`.

- [ ] **Step 4: Run test to verify it passes** — `cd backend && uv run pytest tests/test_ini_config.py -v`

- [ ] **Step 5: Full suite regression** — `cd backend && uv run pytest -m "not integration" -q`

- [ ] **Step 6: STOP** — confirm the ADR-0021 supersede (bootstrap values now INI-required).

- [ ] **Step 7: Commit**

```bash
git add backend/app/core/ini_config.py backend/tests/test_ini_config.py
git commit -m "feat(config): fail-fast on required keys; retire [k8s] and [plugin_settings]"
```

### Task 4: Shipped `kubedash.ini.example` + strip dead in-code defaults

**SATISFIES:** `existing-fixtures-keep-working`

**Files:**
- Create: `backend/kubedash.ini.example`
- Modify: `backend/app/core/config.py` (strip the now-dead in-code defaults for identities; keep
  ONLY the optional/behavior defaults)
- Modify: `backend/wsgi.py` (no change to the `KUBEDASH_STATIC_DIR`/`FLASK_RUN_PORT`/`KUBEDASH_SSL_*`
  env reads — add a WHY-comment: these are env-only process knobs, not INI fields)
- Test: `backend/tests/test_ini_config.py` (example-file sanity: parses, no non-empty secrets,
  interpolation safe)

**Interfaces:**
- Consumes: `ini_config.load_ini` (Task 1).
- Produces: `backend/kubedash.ini.example` — `[DEFAULT] app_mode=development`; `[security]` with
  EMPTY `jwt_secret`/`secret_key`/`admin_password`; `[database] type=postgres` + localhost dev
  creds; `[remote_cache]` localhost; `[sso_settings]` empty `secret`; `[deployment]` and
  `[bootstrap]` present but empty/commented; a header comment naming the precedence (override >
  env > INI) and the retired `[k8s]`/`[plugin_settings]` sections.

- [ ] **Step 1: Write the failing test**

```python
def test_example_file_parses_and_has_no_secrets():
    import pathlib
    p = pathlib.Path(__file__).resolve().parent.parent / "kubedash.ini.example"
    parser = ini_config.load_ini(str(p))  # interpolation OFF -> '%' safe
    assert parser.get("DEFAULT", "app_mode") == "development"
    for k in ("jwt_secret", "secret_key", "admin_password"):
        assert (parser.get("security", k) or "").strip() == ""
    assert (parser.get("sso_settings", "secret") or "").strip() == ""
```

- [ ] **Step 2: Run test to verify it fails** — `cd backend && uv run pytest tests/test_ini_config.py -k example -v`

- [ ] **Step 3: Create `backend/kubedash.ini.example`** and **strip the dead in-code defaults**
  from `config.py` (identity/credential fields are now `default_factory=ini_config.resolve` with
  no literal; only the optional/behavior knobs keep a literal default).

- [ ] **Step 4: Run test to verify it passes** — `cd backend && uv run pytest tests/test_ini_config.py -v`

- [ ] **Step 5: Full suite + build** — `cd backend && uv run pytest -m "not integration" -q`

- [ ] **Step 6: Commit**

```bash
git add backend/kubedash.ini.example backend/app/core/config.py backend/wsgi.py backend/tests/test_ini_config.py
git commit -m "feat(config): ship kubedash.ini.example; strip in-code identity defaults"
```

### Task 5: Dev-loop wiring (all four Taskfile targets) + chart env-override backstop

**SATISFIES:** `dev-stack-boots-from-ini`, `chart-env-overrides-ini` (backstops)

**Files:**
- Modify: `Taskfile.yaml` — `backend-run`, `backend-run-worker`, `dev-stack`, `dev-stack-ssl`:
  set `KUBEDASH_CONFIG_FILE={{.TASKFILE_DIR}}/dev/kubedash.ini`; DROP the now-INADEQUATE inline
  `KUBEDASH_BOOTSTRAP_ADMIN_*`/`KUBEDASH_COOKIE_SECURE` (the INI carries them); KEEP
  `KUBEDASH_ROLE`/`KUBEDASH_REPLICA_ID`/`KUBEDASH_STATIC_DIR`/`FLASK_RUN_PORT` as env overrides /
  process knobs; for `dev-stack-ssl` KEEP `KUBEDASH_TLS_EDGE=true` + OIDC trio +
  `KUBEDASH_SSO_BOOTSTRAP_USERS` as env overrides on top of the INI.
- Create: `dev/kubedash.ini` (gitignored; seeded from the example + dev values: bootstrap admin
  `admin@local`/`admin`, `kubedash_role=leader`, `cookie_secure=false`, `admin_kubeconfig`,
  localhost `[database]`/`[remote_cache]`)
- Modify: `dev/.gitignore` (ignore `dev/kubedash.ini`)
- Modify: `charts/kubedash/templates/deployment.yaml` + `secret.yaml` (no code change expected —
  add a one-line WHY-comment that env overrides the INI; note the deployment-note from Global
  Constraints: the chart secret carries 3 of 5 REQUIRED keys, `bootstrap_admin_*` +
  `admin_kubeconfig` must come from the INI/env)
- Test: the backstops are runtime checks (recorded in `acceptance.feature`).

**Interfaces:**
- Consumes: `KUBEDASH_CONFIG_FILE` (Task 1) + the existing chart env.
- Produces: `task dev-stack` / `dev-stack-ssl` / `backend-run` / `backend-run-worker` booting from
  `dev/kubedash.ini`.

- [ ] **Step 1: Create `dev/kubedash.ini`** (the example + dev values) and add it to `dev/.gitignore`.

- [ ] **Step 2: Update all four Taskfile targets** as above (the R6-demotion: the INI is primary,
  the inline env is the override).

- [ ] **Step 3: Boot the dev stack and verify from the INI** (the backstop)

Run: `task dev-stack && curl -s localhost:8080/healthz`
Expected: 200; boot log shows the bootstrap admin + `KUBEDASH_ROLE=leader` from the INI;
`task db-shell` → `SELECT * FROM leader_lease` shows the INI's `kubedash_replica_id`.

- [ ] **Step 4: Verify the chart env override** (no code change; document)

Run: `helm template t charts/kubedash | grep -A2 KUBEDASH_JWT_SECRET`
Expected: the `secretKeyRef` env entry present — env overrides the INI `[security] jwt_secret`.
Add the WHY-comment to `deployment.yaml`.

- [ ] **Step 5: Finalize the ADR manifest** (`.skillgrid/specs/2026-10-26-ini-config-source/adr.md`)
  — in-force ADRs followed + ADR-0028 created + the ADR-0021 supersede note + the deployment note.

- [ ] **Step 6: Full suite + build** — `cd backend && uv run pytest -m "not integration" -q && task fe-build`

- [ ] **Step 7: Commit**

```bash
git add Taskfile.yaml dev/kubedash.ini dev/.gitignore \
        charts/kubedash/templates/deployment.yaml charts/kubedash/templates/secret.yaml \
        .skillgrid/specs/2026-10-26-ini-config-source/adr.md
git commit -m "feat(config): dev targets boot from kubedash.ini; chart env override documented"
```

## Self-Review

1. **Spec coverage:** R1→Task 1-3, R2→Task 1-2 (precedence chain explicit), R3→Task 2 (both
   split-or-url paths, bools, `sso_bootstrap_users`), R4→Task 3, R5→Task 4, R6→Task 1 (demoted:
   access pattern unchanged, fixtures gain config sourcing), R7→Task 5. All covered.
2. **Must-haves coverage:** every truth maps to a test (Tasks 1-4) or a backstop (Task 5).
   `existing-fixtures-keep-working` is enforced by the full-suite regression in every code task.
3. **One-way-door completeness:** the ADR-0021 supersede is listed in Must-Haves, tagged
   `> ⚠ one-way:` on Task 3, and the STOP is worded as the actual contract change (values become
   INI-required).
4. **Placeholder scan:** `_FIELDS` shows its shape + real entries in Task 1, completed in Task 2;
   both split-or-url resolvers are specified with quoting; no "similar to Task N" (each test
   repeats its code); the pytest filter is now `-k "database or remote or sso or app_mode"`.
5. **Type consistency:** `ini_config.resolve`, `ini_config.load_ini`, `ini_config.apply_overrides`,
   `ini_config.reset`, `ini_config.ConfigError(field, section, key)`, `_FIELDS` 6-tuple — used
   identically in Tasks 1-5. Critic findings 1-19 all addressed: (1) reset clears `_parser`;
   (2) `apply_overrides` runs before the fail-fast + R6 demoted; (3) `sso_bootstrap_users` mapped;
   (4) `[remote_cache]` specified; (5) `quote_plus` + driver documented; (6) bool parse +
   `[deployment]` present; (7) precedence chain + empty-env rule stated; (8) `flask_env`
   no-leak; (9) aliases in `_FIELDS`, `AliasChoices`/`.env` dropped; (10) `create_app`→
   `apply_overrides` mechanism; (11) all four Taskfile targets; (12) role/replica_id defaults
   documented; (13) STOP reworded; (14) `env_names` tuple; (15) `admin_password` + interpolation
   off; (16) deployment note; (17) `-k` fixed; (18) example path via `resolve().parent.parent`;
   (19) deletion-test prose corrected (removes the single precedence owner).
