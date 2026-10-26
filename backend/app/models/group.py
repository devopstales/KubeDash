"""Group rows — OpenID-synced and local (ADR-0013 parity, 4.1 /user/group).

A group is the subject of RBAC bindings in the target clusters (K8s
``Group`` subjects), so group privileges mirror user privileges: a binding
row binds a template to the group on a cluster, and every member inherits
the access. Member rows are materialized at login (the auth upsert) and at
sync (``POST /admin/groups/sync``) — the same idempotent upsert the users
table uses, so re-syncs are no-ops.
"""
from sqlalchemy import UniqueConstraint

from app.extensions import db


class Group(db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    # Stable identity — the OIDC ``groups`` claim value (e.g.
    # "cn=devs,ou=groups"). ``local:`` is the reserved prefix for groups
    # created from the dashboard (an IdP claim starting with ``local:``
    # would collide — same ruling as ``local:`` subs, ADR-0021).
    # ``kubedash-admin`` and ``kubedash-user`` are the built-in local
    # groups that back the admin and user permission roles.
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(255))
    # 'oidc' (synced from an IdP claim) or 'local' (dashboard-created,
    # including the two role groups). Same vocabulary as User.auth_source.
    source = db.Column(db.String(16), nullable=False, default="local")
    # True when the name is known to an IdP (a claim was seen) — such rows
    # are kept on sync even with no members; manual rows are pruned when
    # their last member leaves (see GroupMember below).
    seen_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __init__(
        self,
        *,
        name: str,
        source: str = "local",
        display_name: str | None = None,
    ) -> None:
        if source not in ("oidc", "local"):
            msg = f"unknown group source {source!r}; expected 'oidc' or 'local'"
            raise ValueError(msg)
        if not name:
            raise ValueError("group name must not be blank")
        self.name = name
        self.source = source
        self.display_name = display_name

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Group name={self.name!r} source={self.source!r}>"


class GroupMember(db.Model):
    """A user's membership in a group — one row per (user, group).

    Unique (user_id, group_id); the member COUNT is what the groups list
    renders, and the row set is what group binding applies to in k8s
    (each member is a ``Group`` subject's audience, not a per-user
    binding — the binding's subject is the group name itself).
    """
    __tablename__ = "group_members"
    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_group_member_pair"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id = db.Column(
        db.Integer, db.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=db.func.now())

    def __repr__(self) -> str:  # pragma: no cover
        return f"<GroupMember user={self.user_id} group={self.group_id}>"
