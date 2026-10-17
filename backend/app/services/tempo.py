"""Tempo client — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md.
Thin httpx trace search/detail client lands with the observability change."""
from app.core.errors import NotImplementedError_


def search(**kw: object) -> list[dict[str, object]]:
    raise NotImplementedError_("tempo search not implemented in base structure")


def get(trace_id: str) -> dict[str, object]:
    raise NotImplementedError_("tempo detail not implemented in base structure")
