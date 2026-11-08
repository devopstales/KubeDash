"""Row of the Postgres task queue (ADR-0029).

Replaces the RQ job in Redis; Task 2 claims it with
``FOR UPDATE SKIP LOCKED``. The index on ``enqueued_at`` is plain, not a
partial ``WHERE available_at > now()`` — ``now()`` is STABLE, not IMMUTABLE,
so the partial form is invalid (findings #2); the reaper bounds the table.
"""
from app.extensions import db


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    # The dotted task path, e.g. ``app.tasks.health.run``.
    path = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False, server_default="pending")
    attempts = db.Column(db.Integer, nullable=False, server_default="0")
    enqueued_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=db.text("now()")
    )
    locked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    locked_by = db.Column(db.Text, nullable=True)
    available_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=db.text("now()")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Task id={self.id} path={self.path!r} status={self.status!r}>"
