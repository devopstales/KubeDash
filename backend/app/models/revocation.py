"""Access-token jti deny-list (ADR-0030).

Replaces the Redis ``jti`` revocation key; the verify hook is a primary-key
lookup with ``jti`` bound as a parameter (findings #1). Expired rows are
pruned out-of-band; no index beyond the PK is needed.
"""
from app.extensions import db


class RevokedJti(db.Model):
    __tablename__ = "revoked_jtis"

    jti = db.Column(db.Uuid, primary_key=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RevokedJti jti={self.jti!r}>"
