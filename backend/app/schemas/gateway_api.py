"""Gateway API schemas (the Ingress → Gateway API converter response)."""

from marshmallow import Schema, fields


class GatewayConvertOut(Schema):
    """``POST /clusters/<id>/gateway-api/convert`` — the generated Gateway API
    resources for one Ingress."""

    cluster = fields.Str()
    namespace = fields.Str()
    source = fields.Str()
    gatewayClassName = fields.Str(load_default=None)
    resources = fields.List(fields.Dict())
    warnings = fields.List(fields.Str())
