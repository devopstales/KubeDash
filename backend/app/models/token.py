"""Rotating refresh tokens (R2). Only the sha256 hash is ever stored."""
import hashlib

from app.extensions import db


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # sha256 hex of the raw token — the raw token is never persisted.
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    # Set by rotation / revocation (ADR-0014 propagates revocation).
    revoked_at = db.Column(db.DateTime(timezone=True))

    @staticmethod
    def hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RefreshToken user={self.user_id}>"
