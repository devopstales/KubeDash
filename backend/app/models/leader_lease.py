"""Single-row lease, the observable state of leader election (ADR-0008).

The advisory lock is the mutex; this row is what followers read to decide
the lease is stale and to take over (ARCHITECTURE §3.7).
"""
import uuid

from app.extensions import db


class LeaderLease(db.Model):
    __tablename__ = "leader_lease"

    # Single lease row, always id = 1 (INSERT ... ON CONFLICT (id)).
    id = db.Column(db.Integer, primary_key=True, default=1)
    replica_id = db.Column(db.String(255), nullable=False)
    token = db.Column(db.Uuid, nullable=False, default=uuid.uuid4)
    acquired_at = db.Column(db.DateTime(timezone=True), nullable=False)
    heartbeat_at = db.Column(db.DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<LeaderLease replica={self.replica_id!r}>"
