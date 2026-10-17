"""User × cluster bindings — a user sees only bound clusters (R3)."""
from app.extensions import db

# Per ARCHITECTURE.md: viewer | editor | admin.
ALLOWED_ROLES = frozenset({"viewer", "editor", "admin"})


class ClusterBinding(db.Model):
    __tablename__ = "cluster_bindings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cluster_id = db.Column(
        db.Integer, db.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role = db.Column(db.String(32), nullable=False)

    def __init__(self, *, user_id: int, cluster_id: int, role: str) -> None:
        if role not in ALLOWED_ROLES:
            msg = f"unknown binding role {role!r}; expected one of {sorted(ALLOWED_ROLES)}"
            raise ValueError(msg)
        self.user_id = user_id
        self.cluster_id = cluster_id
        self.role = role

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ClusterBinding user={self.user_id} cluster={self.cluster_id} role={self.role!r}>"
