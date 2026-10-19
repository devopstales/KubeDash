"""Role templates — per .skillgrid/artifacts/04-adr-0013-permission-management.md.
Un-stubbed by the user-management change (TICKET-01); the table's migration
(plus the 4 seeded built-ins) lands in TICKET-02."""
from sqlalchemy.dialects.postgresql import JSONB

from app.extensions import db


class RBACTemplate(db.Model):
    __tablename__ = "rbac_templates"

    id = db.Column(db.Integer, primary_key=True)
    # Unique template name, e.g. "developer", "sre-oncall" (ARCHITECTURE.md §5B).
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), default="")
    # "namespace" | "cluster".
    scope = db.Column(db.String(16), nullable=False)
    # [{api_groups: [...], resources: [...], verbs: [...]}]
    rules = db.Column(JSONB, nullable=False, default=list)
    # Opaque actor identity (user sub or email); None for pre-SSO / legacy rows.
    created_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())
    # True for the 4 built-ins — cannot be deleted (BUILTIN_TEMPLATE_PROTECTED).
    builtin = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RBACTemplate {self.name!r} scope={self.scope!r} builtin={self.builtin}>"
