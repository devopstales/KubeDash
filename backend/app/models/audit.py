"""Audit log rows — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(permission change owns the audit reads/export). The Task 2 initial migration
created ``audit_log`` without this model class; the owning change imports it
into app/models/__init__.py and reconciles it with the existing table.
STUB: NOT imported in app/models/__init__.py, so it stays off db.metadata
until its owning change imports it (see app/models/__init__.py docstring)."""
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255))
