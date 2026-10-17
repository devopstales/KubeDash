"""Registered clusters (ADR-0002: encrypted kubeconfig registry, one-way-door)."""
from app.extensions import db


class Cluster(db.Model):
    __tablename__ = "clusters"

    id = db.Column(db.Integer, primary_key=True)
    # Human-readable name, unique across the registry.
    name = db.Column(db.String(255), unique=True, nullable=False)
    api_server = db.Column(db.String(255), nullable=False)
    # AES-256-GCM ciphertext of the kubeconfig (KUBEDASH_SECRET_KEY, R3).
    kubeconfig_enc = db.Column(db.LargeBinary, nullable=False)
    context = db.Column(db.String(255))
    status = db.Column(db.String(32), nullable=False, default="unknown")
    # Refreshed by the leader-gated health_probe task (Task 7 / ADR-0008).
    last_probe_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Cluster {self.name!r}>"
