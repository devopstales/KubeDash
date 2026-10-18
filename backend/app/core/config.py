from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUBEDASH_", env_file=".env", extra="ignore")

    flask_env: str = "development"  # development | staging | production
    # ARCHITECTURE.md §3.8 names these vars without the KUBEDASH_ prefix, so
    # accept the unprefixed name too (prefix still wins when both are set).
    database_url: str = Field(
        default="postgresql://kubedash:kubedash@localhost:5432/kubedash",
        validation_alias=AliasChoices("KUBEDASH_DATABASE_URL", "DATABASE_URL"),
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias=AliasChoices("KUBEDASH_REDIS_URL", "REDIS_URL"),
    )
    # 32-byte dev default (PyJWT ≥2.10 warns below 32 bytes for HS256); set
    # KUBEDASH_KUBEDASH_JWT_SECRET in real environments.
    kubedash_jwt_secret: str = "dev-jwt-secret-32-bytes-long!!!!!01"
    kubedash_secret_key: str = "dev-enc-key-32-bytes-long!!!!"
    # Replica role for the leader-gated RQ worker (ADR-0008): "leader" starts
    # the worker thread + Leader in wsgi.py; "worker" (default) and any other
    # value keep this replica worker-only. Env: KUBEDASH_ROLE.
    kubedash_role: str = "worker"
    kubedash_replica_id: str = "local"
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_issuer: str = ""
    cors_origins: str = ""
    # ADR-0021 (local admin auth): both set → the bootstrap admin row is
    # created at boot and POST /auth/local is enabled; either empty → local
    # login answers 403 LOCAL_AUTH_DISABLED. Double prefix is deliberate
    # (env_prefix + field name), same convention as KUBEDASH_KUBEDASH_JWT_SECRET.
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    # ADR-0021: admin kubeconfig source — empty → in-cluster service account,
    # set → kubeconfig file path. Declared here; CONSUMED by the next tickets
    # (client pool admin source / TICKET-15).
    admin_kubeconfig: str = ""
    # §7.5 tuning — the two keys this change consumes (the other four are
    # deferred to the informer change, ADR-0010; see Task 10 Interfaces)
    first_paint_backstop: str = "5m"  # KUBEDASH_FIRST_PAINT_BACKSTOP
    namespace_list_timeout: str = "5s"  # KUBEDASH_NAMESPACE_LIST_TIMEOUT


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
