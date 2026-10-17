"""Smorest resource schemas (marshmallow). OpenAPI spec source of truth."""
from app.schemas.auth import RefreshIn
from app.schemas.errors import ErrorOut

__all__ = ["ErrorOut", "RefreshIn"]
