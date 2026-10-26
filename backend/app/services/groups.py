"""Group service — 4.1 /user/group parity (group list / members / sync).

Pure Python — no Flask imports: ``db_session`` is a SQLAlchemy session, and
group privileges delegate to ``services/permission.bind``/``unbind`` with
``subject_kind="Group"`` (the API layer passes the k8s client in, exactly
like the user bind path).
"""
from typing import Any

from app.core.errors import ClusterAlreadyExistsError, ResourceKindNotSupportedError
from app.models.group import Group, GroupMember
from app.models.user import User

#: Dashboard-created groups get this name prefix (an IdP claim starting with
#: ``local:`` would collide — same ruling as ``local:`` user subs, ADR-0021).
LOCAL_PREFIX = "local:"

#: Local groups that back the user-permission roles. Membership is derived
#: from ``User.role`` — admin users belong to kubedash-admin, everyone else
#: with role ``user`` belongs to kubedash-user. These names are reserved:
#: an IdP claim with the same value is not materialized as an OpenID group.
ROLE_GROUPS = {
    "admin": "kubedash-admin",
    "user": "kubedash-user",
}
RESERVED_ROLE_GROUPS = frozenset(ROLE_GROUPS.values())


def sync_from_users(db_session: Any) -> int:
    """Upsert Group + GroupMember rows from every user's ``groups`` claim.

    Idempotent: a (user, group) pair already present is untouched. Returns
    the number of NEW member rows created. Members whose user was deleted
    cascade away with the user row (ondelete CASCADE on group_members).
    """
    created = 0
    for user in db_session.execute(db_session.query(User).statement).scalars():
        for name in user.groups or []:
            if name in RESERVED_ROLE_GROUPS:
                continue
            group = db_session.execute(
                db_session.query(Group).filter_by(name=name).statement
            ).scalar_one_or_none()
            if group is None:
                group = Group(name=name, source="oidc")
                db_session.add(group)
                db_session.flush()
            member = db_session.execute(
                db_session.query(GroupMember).filter_by(
                    user_id=user.id, group_id=group.id
                ).statement
            ).scalar_one_or_none()
            if member is None:
                db_session.add(GroupMember(user_id=user.id, group_id=group.id))
                created += 1
    db_session.commit()
    return created


def sync_one_user(db_session: Any, *, user_id: int, group_names: list[str]) -> None:
    """Upsert Group + membership rows for ONE user's claims (the login
    hook's call — no commit here: the caller's transaction owns it)."""
    for name in group_names or []:
        if name in RESERVED_ROLE_GROUPS:
            continue
        group = db_session.execute(
            db_session.query(Group).filter_by(name=name).statement
        ).scalar_one_or_none()
        if group is None:
            group = Group(name=name, source="oidc")
            db_session.add(group)
            db_session.flush()
        member = db_session.execute(
            db_session.query(GroupMember).filter_by(user_id=user_id, group_id=group.id).statement
        ).scalar_one_or_none()
        if member is None:
            db_session.add(GroupMember(user_id=user_id, group_id=group.id))


def add_manual_group(db_session: Any, *, name: str) -> Group:
    """Create a dashboard group (source ``local``, ``local:`` prefix)."""
    full_name = name if name.startswith(LOCAL_PREFIX) else LOCAL_PREFIX + name
    if full_name in RESERVED_ROLE_GROUPS:
        raise ClusterAlreadyExistsError("group name is reserved for a permission role")
    existing = db_session.execute(
        db_session.query(Group).filter_by(name=full_name).statement
    ).scalar_one_or_none()
    if existing is not None:
        raise ClusterAlreadyExistsError("group name already exists")
    group = Group(name=full_name, source="local", display_name=name)
    db_session.add(group)
    db_session.commit()
    return group


def _role_group(db_session: Any, name: str) -> Group:
    """The local group that backs a permission role, created on first use."""
    group = db_session.execute(
        db_session.query(Group).filter_by(name=name).statement
    ).scalar_one_or_none()
    if group is None:
        group = Group(name=name, source="local", display_name=name)
        db_session.add(group)
        db_session.flush()
    elif group.source != "local":
        group.source = "local"
    return group


def sync_user_role_group(db_session: Any, user: User) -> None:
    """Membership of the two role groups follows ``user.role``.

    No commit — the caller owns the transaction. A user is in exactly one
    of kubedash-admin / kubedash-user.
    """
    wanted = ROLE_GROUPS.get(user.role)
    for name in RESERVED_ROLE_GROUPS:
        group = _role_group(db_session, name)
        member = db_session.execute(
            db_session.query(GroupMember).filter_by(
                user_id=user.id, group_id=group.id
            ).statement
        ).scalar_one_or_none()
        if name == wanted and member is None:
            db_session.add(GroupMember(user_id=user.id, group_id=group.id))
        elif name != wanted and member is not None:
            db_session.delete(member)


def ensure_role_groups(db_session: Any) -> None:
    """Create kubedash-admin and kubedash-user and align every user's
    membership with their permission role. Idempotent."""
    users = db_session.execute(db_session.query(User).statement).scalars().all()
    for user in users:
        sync_user_role_group(db_session, user)
    # Flush the empty-user case so the two groups exist even with no users.
    for name in RESERVED_ROLE_GROUPS:
        _role_group(db_session, name)
    db_session.commit()


def add_member(db_session: Any, *, group_name: str, user_sub: str) -> GroupMember:
    """Add a user to a group (404 when the group or user is missing)."""
    group = db_session.execute(
        db_session.query(Group).filter_by(name=group_name).statement
    ).scalar_one_or_none()
    if group is None:
        group = db_session.execute(
            db_session.query(Group).filter_by(name=LOCAL_PREFIX + group_name).statement
        ).scalar_one_or_none()
    if group is None:
        raise ResourceKindNotSupportedError(f"group {group_name!r} not found")
    if group.name in RESERVED_ROLE_GROUPS:
        raise ClusterAlreadyExistsError("membership follows the user permission role")
    user = db_session.execute(
        db_session.query(User).filter_by(sub=user_sub).statement
    ).scalar_one_or_none()
    if user is None:
        raise ResourceKindNotSupportedError(f"user {user_sub!r} not found")
    member = db_session.execute(
        db_session.query(GroupMember).filter_by(user_id=user.id, group_id=group.id).statement
    ).scalar_one_or_none()
    if member is None:
        member = GroupMember(user_id=user.id, group_id=group.id)
        db_session.add(member)
        db_session.commit()
    return member


def remove_member(db_session: Any, *, group_name: str, user_sub: str) -> None:
    """Remove a user from a group (404 when the membership is missing)."""
    group = db_session.execute(
        db_session.query(Group).filter_by(name=group_name).statement
    ).scalar_one_or_none()
    if group is None:
        group = db_session.execute(
            db_session.query(Group).filter_by(name=LOCAL_PREFIX + group_name).statement
        ).scalar_one_or_none()
    if group is None:
        raise ResourceKindNotSupportedError(f"group {group_name!r} not found")
    if group.name in RESERVED_ROLE_GROUPS:
        raise ClusterAlreadyExistsError("membership follows the user permission role")
    user = db_session.execute(
        db_session.query(User).filter_by(sub=user_sub).statement
    ).scalar_one_or_none()
    if user is None:
        raise ResourceKindNotSupportedError(f"user {user_sub!r} not found")
    member = db_session.execute(
        db_session.query(GroupMember).filter_by(user_id=user.id, group_id=group.id).statement
    ).scalar_one_or_none()
    if member is None:
        raise ResourceKindNotSupportedError("user is not a member of this group")
    db_session.delete(member)
    db_session.commit()
