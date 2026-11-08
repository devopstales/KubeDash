"""Postgres key-value store (ADR-0030).

Replaces the remaining Redis consumers — OIDC ``state`` (one-shot CSRF
nonce) and the SAR verdict cache (keys are long ``sar:<...>`` strings, hence
Text PK, not ``String(n)``). ``value`` is nullable: a tombstone row (value
NULL) is a legal one-shot state. The index on ``expires_at`` is plain, not a
partial ``WHERE expires_at > now()`` — ``now()`` is STABLE, not IMMUTABLE
(findings #2); the reaper bounds the table.
"""
from app.extensions import db


class Kv(db.Model):
    __tablename__ = "kv"

    key = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text, nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Kv key={self.key!r}>"
