"""Grafana client — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md.
Thin httpx embed/query client lands with the observability change."""
from app.core.errors import NotImplementedError_


def query(dashboard_uid: str, **kw: object) -> dict[str, object]:
    raise NotImplementedError_("grafana query not implemented in base structure")
