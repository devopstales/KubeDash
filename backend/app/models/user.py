"""User rows, upserted by the OIDC callback (R2)."""
from sqlalchemy.dialects.postgresql import JSONB

from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    # OIDC subject — stable identity across logins.
    sub = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    # OIDC groups claim (JSON array); R9/RBAC consumes it later.
    # Postgres JSONB (the brief's `db.JSON` maps to plain JSON; JSONB is the
    # intended Postgres type per the Task 2 controller ruling).
    groups = db.Column(JSONB, nullable=False, default=list)
    role = db.Column(db.String(32), nullable=False, default="user")
    status = db.Column(db.String(32), nullable=False, default="active")
    last_login_at = db.Column(db.DateTime(timezone=True))

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User sub={self.sub!r}>"
