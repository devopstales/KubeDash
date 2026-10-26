"""User-management request/response schemas (TICKET-04, ADR-0013).

Match the ``app/schemas/cluster.py`` style: plain marshmallow ``Schema``
classes, docs-only where the response is a bare list (smorest dumps handler
returns THROUGH the response schema — see the ponytail note in
``app/api/clusters.py``).
"""
from marshmallow import Schema, fields, validate


class UserOut(Schema):
    """Every user as listed by ``GET /admin/users`` (R1). ``cluster_count``
    is the number of ``cluster_bindings`` rows for that user (the synthetic
    local cluster is not a binding row, so it is never counted)."""

    id = fields.Int()
    sub = fields.String()
    email = fields.String(allow_none=True)
    display_name = fields.String(allow_none=True)
    groups = fields.List(fields.String())
    role = fields.String()
    status = fields.String()
    auth_source = fields.String()
    cluster_count = fields.Int()
    last_login_at = fields.DateTime(allow_none=True)
    # The main-branch "Type" column: "Local" (auth_source=local) or "OIDC".
    user_type = fields.String()


class UserPatch(Schema):
    """PATCH body (R1): ``role`` and/or ``status``; each is optional (a
    patch may carry only one). Validation errors map to 422
    ``INVALID_KUBECONFIG`` (the only stable 422)."""

    role = fields.String(allow_none=True)
    status = fields.String(allow_none=True)


class UserIn(Schema):
    """POST body for the 4.1 Create User form. ``role`` is ``user`` or
    ``admin`` (the form labels are User / Admin). ``type`` is ``Local`` —
    created rows are password users, not SSO upserts."""

    username = fields.String(required=True)
    email = fields.String(required=True)
    password = fields.String(required=True)
    role = fields.String(required=True)
    type = fields.String(load_default="Local")


class TemplateIn(Schema):
    """Create body (R2). ``rules`` is a list of rule dicts
    ``[{api_groups, resources, verbs}]``; the SHAPE validation (non-empty
    verbs/resources) lives in the handler (422), not here — marshmallow's
    ValidationError would map to a generic 422 envelope without the stable
    code."""

    name = fields.String(required=True)
    description = fields.String(load_default="")
    scope = fields.String(required=True)
    rules = fields.List(fields.Dict(), required=True)


class TemplateOut(Schema):
    """A role template as listed/fetched (R2)."""

    id = fields.Int()
    name = fields.String()
    description = fields.String()
    scope = fields.String()
    rules = fields.List(fields.Dict())
    builtin = fields.Boolean()
    created_by = fields.String(allow_none=True)
    created_at = fields.DateTime(allow_none=True)


class UserCreateIn(Schema):
    """Create body for ``POST /admin/users`` (TASK-027). Creates an
    ``auth_source=local`` user with a pbkdf2 password (ADR-0021). Blank
    username/password and an invalid role are 422 INVALID_KUBECONFIG (the
    handler validates — marshmallow's ValidationError would map to a generic
    422 without the stable code)."""

    username = fields.String(required=True)
    email = fields.String(required=True)
    password = fields.String(required=True)
    role = fields.String(required=True)


# NOTE: GroupIn / GroupMemberIn used to live here (TASK-026) but the groups
# surface moved to the GroupsApi, whose schemas live in
# app/schemas/groups.py — the duplicate names here collided in apispec
# (Multiple schemas resolved to the name "GroupIn"). Removed 2026-10-26.


class BindIn(Schema):
    """Bind/Unbind body (R3/R4). ``cluster`` is the cluster NAME (resolved
    by the handler — 404 ``CLUSTER_NOT_FOUND`` if missing); ``user`` is the
    user sub; ``template`` is the template name; ``namespace`` is omitted
    for cluster-scoped templates."""

    user = fields.String(required=True)
    cluster = fields.String(required=True)
    namespace = fields.String(allow_none=True)
    template = fields.String(required=True)


class BindingOut(Schema):
    """A caller's binding as listed by ``GET /permissions/my-access`` (R5).
    ``cluster`` is the human-readable NAME (the handler resolves the id)."""

    cluster = fields.String()
    namespace = fields.String(allow_none=True)
    template = fields.String(allow_none=True)
    created_at = fields.DateTime(allow_none=True)


class AuditOut(Schema):
    """An audit row (R7's read routes land later; this documents the row
    shape for the mutations that write it)."""

    actor_sub = fields.String()
    action = fields.String()
    target = fields.String()
    cluster = fields.String(allow_none=True)
    namespace = fields.String(allow_none=True)
    template = fields.String(allow_none=True)
    at = fields.DateTime(allow_none=True)
