"""SCIM externalId ↔ KubeDash id mapping (§ 5F) — per
.skillgrid/artifacts/04-adr-0018-scim-2-0-gateway.md.
Migration for this table lands with the SCIM change.
STUB: NOT imported in app/models/__init__.py, so it stays off db.metadata
until its owning change imports it (see app/models/__init__.py docstring)."""
from app.extensions import db


class ScimMapping(db.Model):
    __tablename__ = "scim_mappings"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(255), unique=True)
