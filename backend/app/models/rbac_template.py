"""Role templates — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
Migration for this table lands with the permission-management change.
STUB: NOT imported in app/models/__init__.py, so it stays off db.metadata
until its owning change imports it (see app/models/__init__.py docstring)."""
from app.extensions import db


class RBACTemplate(db.Model):
    __tablename__ = "rbac_templates"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
