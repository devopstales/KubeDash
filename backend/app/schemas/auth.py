"""Auth API request/response schemas.

marshmallow (not Pydantic): flask-smorest 0.47's ``@blp.arguments`` /
``@blp.response`` require marshmallow.
"""
import marshmallow as ma


class RefreshIn(ma.Schema):
    refresh_token = ma.fields.String(required=True)


class RefreshOut(ma.Schema):
    """Rotation returns BOTH tokens — the old refresh is consumed."""

    access = ma.fields.String()
    refresh = ma.fields.String()


def _validate_local_email(value: object) -> None:
    # Deliberately NOT EmailStr (that would pull in the email-validator
    # dependency and break "no new Python deps", ADR-0020): minimal shape
    # check at the trust boundary — contains '@' and is at least 3 chars.
    if not isinstance(value, str) or "@" not in value or len(value) < 3:
        raise ma.ValidationError("email must be a string containing '@' (>= 3 chars)")


class LocalLoginIn(ma.Schema):
    """ADR-0021: bootstrap-admin local password login (sibling of OIDC)."""

    email = ma.fields.String(required=True, validate=_validate_local_email)
    password = ma.fields.String(required=True)


class AuthSettingsOut(ma.Schema):
    """Open (pre-JWT) capability flags for the login page (R3)."""

    sso_enabled = ma.fields.Boolean()
    local_enabled = ma.fields.Boolean()


class MeOut(ma.Schema):
    sub = ma.fields.String()
    email = ma.fields.String(allow_none=True)
    display_name = ma.fields.String(allow_none=True)
    groups = ma.fields.List(ma.fields.String())
    role = ma.fields.String()
