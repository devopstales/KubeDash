"""Admin-managed groups + user↔group membership.

The ``/groups`` admin surface (TASK-026): groups are first-class rows an
admin creates and assigns users to — the 5.0 analogue of the legacy app's
``sso_groups`` / ``sso_user_group_mapping`` tables. OIDC ``groups`` claims
on users remain the second source: the effective group list for a user is
stored membership ∪ claim (merged at read time in the admin API).

Plain relational (no JSONB) so the sqlite api test tier and PG both work.
"""
from sqlalchemy import UniqueConstraint

from app.extensions import db


class Group(db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    # Unique group name (e.g. "platform", "sre-oncall").
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Group {self.name!r}>"


class UserGroup(db.Model):
    """Membership mapping: one row per (user, group) pair."""

    __tablename__ = "user_groups"
    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_user_group_pair"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id = db.Column(
        db.Integer, db.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UserGroup user={self.user_id} group={self.group_id}>"
