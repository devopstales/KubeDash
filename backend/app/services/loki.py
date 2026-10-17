"""Loki client — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md.
Thin httpx LogQL client lands with the observability change (SSE tail per
ADR-0009)."""
from app.core.errors import NotImplementedError_


def query(logql: str, **kw: object) -> list[dict[str, object]]:
    raise NotImplementedError_("loki query not implemented in base structure")
