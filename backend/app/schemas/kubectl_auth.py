"""AuthConfig — the plugin ↔ server contract for
``GET /api/v1/kubectl/auth/v1/config`` — per
.skillgrid/artifacts/04-adr-0011-kubectl-credential-plugin.md (ADR-0011).
The in-flight kubectl-oidc-plugin change replaces the resolution logic
(clusters.oidc_config / Helm ConfigMap); this schema is the frozen wire
shape it consumes."""
from pydantic import BaseModel


class AuthConfig(BaseModel):
    """SSO config per cluster for the kubectl credential plugin (unauthenticated
    bootstrap endpoint; TLS + rate-limited)."""

    issuer: str
    client_id: str
    token_url: str
    auth_url: str
    scopes: list[str] = []
    expiry: int | None = None
