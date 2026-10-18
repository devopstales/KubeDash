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
    # ADR-0021 (local admin auth): pbkdf2:sha256:600000$<b64salt>$<b64hash>
    # (stdlib hashlib, no new dep). None for SSO rows. The Alembic revision
    # lands in the next ticket (TICKET-14); tests' db.create_all() reads this
    # model, so the column ships here.
    password_hash = db.Column(db.String(255))
    # 'local' (bootstrap admin, later permission-management local users) or
    # 'oidc' (SSO upsert). Existing rows default to 'oidc' — the migration
    # applies the same default.
    auth_source = db.Column(db.String(16), nullable=False, default="oidc")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User sub={self.sub!r}>"
