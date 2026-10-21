"""Group management schemas — 4.1 /user/group parity.

Match the ``app/schemas/permissions.py`` style: plain marshmallow
``Schema`` classes, docs-only where the response is a bare list.
"""
from marshmallow import Schema, fields


class GroupIn(Schema):
    """POST body (manual group create). ``name`` is the display name — the
    ``manual:`` prefix is applied server-side."""

    name = fields.String(required=True)


class GroupOut(Schema):
    """A group as listed by ``GET /admin/groups`` (bare list). ``members``
    is populated only by the detail route."""

    id = fields.Int()
    name = fields.String()
    display_name = fields.String()
    source = fields.String()
    member_count = fields.Int()
    created_at = fields.DateTime(allow_none=True)
    members = fields.List(fields.Dict(), load_default=None)


class GroupMemberIn(Schema):
    """Member add/remove + privilege bind/unbind body. ``user`` is the user
    sub (member ops); ``cluster`` / ``template`` / ``namespace`` are the
    privilege ops' coordinates (cluster NAME — resolved by the handler).
    ``required=True`` fields are omitted: the ops share one schema and
    validation happens per-route in the handler (missing field → the
    stable 404/422 the route already documents)."""

    user = fields.String(allow_none=True)
    cluster = fields.String(allow_none=True)
    namespace = fields.String(allow_none=True)
    template = fields.String(allow_none=True)


class GroupBindIn(Schema):
    """Privilege bind/unbind body only (cluster + template required)."""

    cluster = fields.String(required=True)
    namespace = fields.String(allow_none=True)
    template = fields.String(required=True)


class GroupSyncOut(Schema):
    """POST /admin/groups/sync result."""

    created_members = fields.Int()


class GroupPrivilegeOut(Schema):
    """A group binding as listed by GET /admin/groups/<name>/privileges —
    same shape as ``BindingOut`` (the user my-access row)."""

    cluster = fields.String()
    namespace = fields.String(allow_none=True)
    template = fields.String(allow_none=True)
    created_at = fields.DateTime(allow_none=True)
