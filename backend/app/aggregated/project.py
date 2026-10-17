"""Project projection — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): Namespace → Project with RBAC filter. Stub."""
from app.core.errors import NotImplementedError_


def projects(cluster: str, **kw: object) -> list[dict[str, object]]:
    raise NotImplementedError_("project projection not implemented in base structure")
