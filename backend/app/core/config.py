"""Settings is a thin PROJECTION over ``ini_config`` (ADR-0028).

Every field sources from ``ini_config.resolve`` / ``resolve_bool`` via
``default_factory`` — pydantic-settings no longer reads env directly
(``env_prefix``/``AliasChoices``/``env_file`` are retired as value sources;
the unprefixed ``DATABASE_URL``/``REDIS_URL`` aliases now live in
``ini_config._FIELDS``). The only in-code defaults are the optional/behavior
knobs; identities/credentials are INI/env-resolved with no literal fallback.

``get_settings()`` returns a LAZY ``ini_config._SettingsProxy``: the real
``Settings()`` (which runs the ``default_factory`` fail-fast) is constructed on
first field access, so module-import-time calls that never read a field do not
trigger the fail-fast. The public surface (``settings.<field>`` and the
``settings()`` test-call) is unchanged.
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core import ini_config


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    # [DEFAULT] app_mode -> development|production
    flask_env: str = Field(default_factory=lambda: ini_config.resolve("flask_env"))
    # [database] -> database_url (split-or-url)
    database_url: str = Field(default_factory=lambda: ini_config.resolve("database_url"))
    # [remote_cache] -> redis_url (split-or-url)
    redis_url: str = Field(default_factory=lambda: ini_config.resolve("redis_url"))
    # [security] jwt_secret / secret_key (moved out of code defaults, ADR-0028)
    kubedash_jwt_secret: str = Field(
        default_factory=lambda: ini_config.resolve("kubedash_jwt_secret")
    )
    kubedash_secret_key: str = Field(
        default_factory=lambda: ini_config.resolve("kubedash_secret_key")
    )
    # [deployment] kubedash_role / kubedash_replica_id
    kubedash_role: str = Field(default_factory=lambda: ini_config.resolve("kubedash_role"))
    kubedash_replica_id: str = Field(
        default_factory=lambda: ini_config.resolve("kubedash_replica_id")
    )
    # [sso_settings] client_id / client_secret / issuer
    oidc_client_id: str = Field(default_factory=lambda: ini_config.resolve("oidc_client_id"))
    oidc_client_secret: str = Field(
        default_factory=lambda: ini_config.resolve("oidc_client_secret")
    )
    oidc_issuer: str = Field(default_factory=lambda: ini_config.resolve("oidc_issuer"))
    # optional empty-string knobs
    cors_origins: str = Field(default_factory=lambda: ini_config.resolve("cors_origins"))
    # ADR-0025: Secure flag, fail-closed True default (behavior knob)
    cookie_secure: bool = Field(default_factory=lambda: ini_config.resolve_bool("cookie_secure"))
    # [bootstrap] bootstrap_admin_email / bootstrap_admin_password (ADR-0021)
    bootstrap_admin_email: str = Field(
        default_factory=lambda: ini_config.resolve("bootstrap_admin_email")
    )
    bootstrap_admin_password: str = Field(
        default_factory=lambda: ini_config.resolve("bootstrap_admin_password")
    )
    # [deployment] admin_kubeconfig (ADR-0021)
    admin_kubeconfig: str = Field(default_factory=lambda: ini_config.resolve("admin_kubeconfig"))
    # [deployment] tuning (§7.5)
    first_paint_backstop: str = Field(
        default_factory=lambda: ini_config.resolve("first_paint_backstop")
    )
    namespace_list_timeout: str = Field(
        default_factory=lambda: ini_config.resolve("namespace_list_timeout")
    )
    # [deployment] plugin_server (ADR-0011); None when unset
    plugin_server: str | None = Field(
        default_factory=lambda: ini_config.resolve("plugin_server") or None
    )
    # [deployment] tls_edge (ADR-0026/0027)
    tls_edge: bool = Field(default_factory=lambda: ini_config.resolve_bool("tls_edge"))
    # [sso_settings] bootstrap_users (optional empty-string knob)
    sso_bootstrap_users: str = Field(
        default_factory=lambda: ini_config.resolve("sso_bootstrap_users")
    )


_settings: Settings | None = None
_proxy = ini_config._SettingsProxy()


def get_settings():
    """Return the lazy settings proxy. The real ``Settings`` is constructed on
    first field access (see ``ini_config._SettingsProxy``). Tests that call
    ``settings()`` get the constructed ``Settings`` via the proxy's
    ``__call__``."""
    return _proxy
