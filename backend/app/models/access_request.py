"""PAM elevation requests (§ 5D) — per
.skillgrid/artifacts/04-adr-0016-privileged-access-management.md.
Migration for this table lands with the PAM change.
STUB: NOT imported in app/models/__init__.py, so it stays off db.metadata
until its owning change imports it (see app/models/__init__.py docstring)."""
from app.extensions import db


class AccessRequest(db.Model):
    __tablename__ = "access_requests"
    STUB = True
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(32), nullable=False, default="pending")
