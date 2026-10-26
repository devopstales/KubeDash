"""Single source of truth for configuration values (ADR-0028).

Precedence per field, one chain:
    create_app overrides  >  env (KUBEDASH_* / unprefixed alias)  >  INI
      >  optional/behavior default  >  ConfigError (required key missing).

The app discovers ONE anchor, ``KUBEDASH_HOME``, and derives every
home-relative path from it: the INI is ``<home>/kubedash.ini``, the static
dir ``<home>/static``. ``KUBEDASH_HOME`` is the app root — baked as ``/app``
in the container, and in dev hard-derived from ``wsgi.py``'s own location
(`<repo>/backend`), so it is never manually set in the dev loop.

``configparser`` is used with interpolation OFF: 4.1-style values and base64
secrets may contain ``%``, which the default BasicInterpolation would reject.
"""
from __future__ import annotations

import configparser
import os
import pathlib
from collections.abc import Mapping

# field -> (section, key, env_names, has_default, default, is_bool)
#
# TICKET-01 carries the resolution core + the home-derivation + the
# security/behavior/optional fields. TICKET-02 completes the table for the
# remaining fields (database_url, redis_url, oidc_*, admin_kubeconfig,
# plugin_server, cors_origins, sso_bootstrap_users, bootstrap_admin_email,
# tls_edge, first_paint_backstop, namespace_list_timeout) and adds the
# [database]/[remote_cache] split-or-url resolvers.
_FIELDS: dict[str, tuple[str, str, tuple[str, ...], bool, str, bool]] = {
    "kubedash_jwt_secret": (
        "security", "jwt_secret",
        ("KUBEDASH_KUBEDASH_JWT_SECRET", "KUBEDASH_JWT_SECRET"), False, "", False,
    ),
    "kubedash_secret_key": (
        "security", "secret_key", ("KUBEDASH_SECRET_KEY",), False, "", False,
    ),
    "bootstrap_admin_password": (
        "security", "admin_password",
        ("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD",), False, "", False,
    ),
    "flask_env": (
        "DEFAULT", "app_mode", ("KUBEDASH_FLASK_ENV",), True, "development", False,
    ),
    "cookie_secure": (
        "deployment", "cookie_secure", ("KUBEDASH_COOKIE_SECURE",), True, "true", True,
    ),
    "kubedash_role": (
        "deployment", "kubedash_role", ("KUBEDASH_ROLE",), True, "worker", False,
    ),
    "kubedash_replica_id": (
        "deployment", "kubedash_replica_id", ("KUBEDASH_REPLICA_ID",), True, "local", False,
    ),
    # --- TICKET-02: remaining fields ----------------------------------------
    "database_url": (
        "database", "url",
        ("KUBEDASH_DATABASE_URL", "DATABASE_URL"), True, "", False,
    ),
    "redis_url": (
        "remote_cache", "url",
        ("KUBEDASH_REDIS_URL", "REDIS_URL"), True, "", False,
    ),
    "oidc_client_id": (
        "sso_settings", "client_id", ("KUBEDASH_OIDC_CLIENT_ID",), True, "", False,
    ),
    "oidc_client_secret": (
        "sso_settings", "secret", ("KUBEDASH_OIDC_CLIENT_SECRET",), True, "", False,
    ),
    "oidc_issuer": (
        "sso_settings", "issuer_url", ("KUBEDASH_OIDC_ISSUER",), True, "", False,
    ),
    "cors_origins": (
        "deployment", "cors_origins", ("KUBEDASH_CORS_ORIGINS",), True, "", False,
    ),
    "bootstrap_admin_email": (
        "bootstrap", "bootstrap_admin_email",
        ("KUBEDASH_BOOTSTRAP_ADMIN_EMAIL",), True, "", False,
    ),
    "admin_kubeconfig": (
        "deployment", "admin_kubeconfig", ("KUBEDASH_ADMIN_KUBECONFIG",), True, "", False,
    ),
    "first_paint_backstop": (
        "deployment", "first_paint_backstop",
        ("KUBEDASH_FIRST_PAINT_BACKSTOP",), True, "5m", False,
    ),
    "namespace_list_timeout": (
        "deployment", "namespace_list_timeout",
        ("KUBEDASH_NAMESPACE_LIST_TIMEOUT",), True, "5s", False,
    ),
    "plugin_server": (
        "deployment", "plugin_server", ("KUBEDASH_PLUGIN_SERVER",), True, "", False,
    ),
    "tls_edge": (
        "deployment", "tls_edge", ("KUBEDASH_TLS_EDGE",), True, "false", True,
    ),
    "sso_bootstrap_users": (
        "sso_settings", "bootstrap_users", ("KUBEDASH_SSO_BOOTSTRAP_USERS",), True, "", False,
    ),
}

# env name -> field (for apply_overrides: the mapping keys are env names)
_ENV_TO_FIELD: dict[str, str] = {
    env: field for field, (_s, _k, envs, *_rest) in _FIELDS.items() for env in envs
}

# Required keys: absent from overrides + env + INI -> ConfigError at boot.
# (Full set finalized in TICKET-03; declared here so `resolve` can reference it.)
REQUIRED: frozenset[str] = frozenset({
    "kubedash_jwt_secret",
    "kubedash_secret_key",
    "bootstrap_admin_email",
    "bootstrap_admin_password",
    "admin_kubeconfig",
})


class ConfigError(Exception):
    """A required config value is absent from every source."""

    def __init__(self, field: str, section: str, key: str) -> None:
        self.field, self.section, self.key = field, section, key
        super().__init__(
            f"missing required config {field!r} (INI [{section}] {key} or env)"
        )


_home: pathlib.Path | None = None
_parser: configparser.ConfigParser | None = None
_overrides: dict[str, object] = {}


def reset() -> None:
    """The single test reset: clear the home cache, INI parser, overrides, and
    the Settings singleton (``config._settings``). Tests must call this (not
    ``config._settings = None`` alone) so the derived home + parser are
    re-derived per test."""
    global _parser, _home
    _parser = None
    _home = None
    _overrides.clear()
    import app.core.config as _c

    _c._settings = None


def resolve_home() -> pathlib.Path:
    """KUBEDASH_HOME, else hard-derived from this file's location
    (``app/core/ini_config.py`` -> ``parents[2]`` == ``<repo>/backend``)."""
    env = os.environ.get("KUBEDASH_HOME")
    return pathlib.Path(env) if env else pathlib.Path(__file__).resolve().parents[2]


def home_paths() -> dict[str, pathlib.Path]:
    """The single derivation point for every home-relative path."""
    global _home
    if _home is None:
        _home = resolve_home()
    return {"ini": _home / "kubedash.ini", "static": _home / "static"}


def load_ini(path: str | pathlib.Path | None = None) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(str(path) if path else str(home_paths()["ini"]))
    return parser


def _get_parser() -> configparser.ConfigParser:
    global _parser
    if _parser is None:
        _parser = load_ini()
    return _parser


def apply_overrides(mapping: Mapping[str, object] | None) -> None:
    """Record ``create_app(config_overrides)`` values ahead of env/INI. Keys are
    the ``KUBEDASH_*``/unprefixed env names; mapped back to field names."""
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


def _ini(section: str, key: str) -> str:
    """Read one INI value ('' when absent), from the cached parser."""
    return _get_parser().get(section, key, fallback=None) or ""


def _resolve_database() -> str:
    """[database]: a single ``url`` wins; else build the postgres URL from the
    split fields with ``quote_plus`` on user/password. ``type`` is read for the
    sqlite->postgres warning only and does NOT change the driver (5.0 is
    Postgres-only)."""
    url = _ini("database", "url")
    if url:
        return url
    from urllib.parse import quote_plus

    host = _ini("database", "host")
    name = _ini("database", "name")
    if not host and not name:
        return ""
    user = quote_plus(_ini("database", "user"))
    password = quote_plus(_ini("database", "password"))
    auth = ""
    if user or password:
        auth = f"{user}:{password}@"
    return f"postgresql://{auth}{host}/{name}"


def _resolve_redis() -> str:
    """[remote_cache]: a single ``url`` wins; else build ``redis://[pass@]host:port/db``
    (port defaults to 6379, db to 0)."""
    url = _ini("remote_cache", "url")
    if url:
        return url
    host = _ini("remote_cache", "redis_host")
    if not host:
        return ""
    port = _ini("remote_cache", "redis_port") or "6379"
    db = _ini("remote_cache", "redis_db") or "0"
    password = _ini("remote_cache", "redis_password")
    auth = f":{password}@" if password else ""
    return f"redis://{auth}{host}:{port}/{db}"


# Fields whose INI value is composed from multiple section keys (TICKET-02).
_SPECIAL_RESOLVERS = {
    "database_url": _resolve_database,
    "redis_url": _resolve_redis,
}


def resolve(field: str) -> str:
    """The one precedence chain for a single field."""
    if field in _overrides and _overrides[field] is not None:
        val = _overrides[field]
        return val if isinstance(val, str) else str(val)
    section, key, env_names, has_default, default, _is_bool = _FIELDS[field]
    for env in env_names:
        ev = os.environ.get(env)
        if ev is not None and ev != "":
            return ev
    # A composed field (database/redis split-or-url) reads its section keys
    # directly rather than a single section/key.
    if field in _SPECIAL_RESOLVERS:
        composed = _SPECIAL_RESOLVERS[field]()
        return composed if composed else (default if has_default else "")
    ini = _ini(section, key)
    if ini:
        return ini
    if has_default:
        return default
    if field in REQUIRED:
        raise ConfigError(field, section, key)
    return ""


def resolve_bool(field: str) -> bool:
    """Bool variant of :func:`resolve` (tls_edge, cookie_secure)."""
    return _parse_bool(resolve(field), field)


class _SettingsProxy:
    """A LAZY projection of ``Settings`` (ADR-0028).

    ``get_settings()`` returns this — cheap, no ``Settings()`` construction —
    so module-import-time callers that never read a field do not trigger the
    fail-fast. A field access resolves THAT field through the precedence
    chain (override > env > INI > default), returning a ``str``/``bool``: the
    public surface (``settings.<field>``) is byte-for-byte the same. A field
    that raises ``ConfigError`` (a missing REQUIRED value) propagates — that IS
    the fail-fast, and only the field actually read fails.

    ``__call__`` returns the real ``Settings`` for the test-call form
    (``settings()``). Because ``Settings()`` still runs every ``default_factory``
    eagerly, the constructed model resolves all fields — used only by tests.
    """

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in _FIELDS:
            raise AttributeError(name)
        _section, _key, _envs, _has_default, _default, is_bool = _FIELDS[name]
        return resolve_bool(name) if is_bool else resolve(name)

    def _construct(self):
        from app.core import config as _c

        if _c._settings is None:
            _c._settings = _c.Settings()
        return _c._settings

    def __call__(self):
        # The test-call form: settings() -> the real Settings (construction).
        return self._construct()
