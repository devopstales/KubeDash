"""Prometheus client — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md.
Thin httpx query/range client lands with the observability change."""
from app.core.errors import NotImplementedError_


def query(promql: str, **kw: object) -> dict[str, object]:
    raise NotImplementedError_("prometheus query not implemented in base structure")
