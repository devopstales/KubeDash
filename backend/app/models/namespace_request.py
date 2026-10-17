"""NaaS onboarding requests (§ 5C) — per .skillgrid/artifacts/04-adr-0015-namespace-as-a-service.md.
Migration for this table lands with the NaaS change.
STUB: NOT imported in app/models/__init__.py, so it stays off db.metadata
until its owning change imports it (see app/models/__init__.py docstring)."""
from app.extensions import db


class NamespaceRequest(db.Model):
    __tablename__ = "namespace_requests"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(32), nullable=False, default="pending")
