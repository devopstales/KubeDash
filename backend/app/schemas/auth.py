"""Auth API request/response schemas."""
import marshmallow as ma


class RefreshIn(ma.Schema):
    refresh_token = ma.fields.String(required=True)


class RefreshOut(ma.Schema):
    """Rotation returns BOTH tokens — the old refresh is consumed."""

    access = ma.fields.String()
    refresh = ma.fields.String()


class MeOut(ma.Schema):
    sub = ma.fields.String()
    email = ma.fields.String(allow_none=True)
    display_name = ma.fields.String(allow_none=True)
    groups = ma.fields.List(ma.fields.String())
    role = ma.fields.String()
