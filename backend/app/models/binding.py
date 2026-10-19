"""User × cluster bindings — a user sees only bound clusters (R3).

User-management (ADR-0013 / TICKET-01) extends the row with the bound
``namespace`` (None = cluster scope) and the role ``template`` name; ``role``
stays but becomes template-derived (default "viewer"). One-way-door
(ADR-0002): model only here — the migration is TICKET-02.
"""
from sqlalchemy import UniqueConstraint

from app.extensions import db

# Per ARCHITECTURE.md: viewer | editor | admin.
ALLOWED_ROLES = frozenset({"viewer", "editor", "admin"})


class ClusterBinding(db.Model):
    __tablename__ = "cluster_bindings"
    # One binding per (user, cluster, namespace, template). Postgres treats
    # NULL namespaces as distinct in a unique constraint — accepted:
    # cluster-scoped rows (namespace=None) are out of scope for dedup here.
    __table_args__ = (
        UniqueConstraint(
            "user_id", "cluster_id", "namespace", "template", name="uq_cluster_binding_triple"
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cluster_id = db.Column(
        db.Integer, db.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Template-derived role (viewer | editor | admin); the template is the
    # source of truth, this column is its cached projection.
    role = db.Column(db.String(32), nullable=False, default="viewer")
    # The bound namespace; None = cluster scope.
    namespace = db.Column(db.String(255), nullable=True, index=True)
    # The role template name (e.g. "developer"); None for legacy rows.
    template = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __init__(
        self,
        *,
        user_id: int,
        cluster_id: int,
        role: str,
        namespace: str | None = None,
        template: str | None = None,
    ) -> None:
        if role not in ALLOWED_ROLES:
            msg = f"unknown binding role {role!r}; expected one of {sorted(ALLOWED_ROLES)}"
            raise ValueError(msg)
        self.user_id = user_id
        self.cluster_id = cluster_id
        self.role = role
        self.namespace = namespace
        self.template = template

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ClusterBinding user={self.user_id} cluster={self.cluster_id} "
            f"role={self.role!r} namespace={self.namespace!r} template={self.template!r}>"
        )
