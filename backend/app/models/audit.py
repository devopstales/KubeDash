"""Audit log rows — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(permission change owns the audit reads/export). Un-stubbed by the
user-management change (TICKET-01); reconciling the LIVE ``audit_log`` table
with these columns (additive only) is the later TICKET-02 migration."""
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    # The action verb, e.g. "bind", "unbind", "template.create".
    action = db.Column(db.String(255), nullable=False)
    # Acting identity (OIDC sub or local:<email>).
    actor_sub = db.Column(db.String(255), nullable=False)
    # What was acted on (user id, template name, ...).
    target = db.Column(db.String(255), nullable=False)
    # Optional context — None for cluster-scoped / non-cluster actions.
    cluster = db.Column(db.String(255))
    namespace = db.Column(db.String(255))
    template = db.Column(db.String(255))
    at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action!r} target={self.target!r} by={self.actor_sub!r}>"
