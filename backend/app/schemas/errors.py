"""OD-1 error envelope, documented in the OpenAPI spec.

The 10 stable codes are the frozen OD-1 set; ``details`` is optional and only
present on errors that carry it.
"""
import marshmallow as ma

_CODES = (
    "UNAUTHORIZED",
    "STATE_MISMATCH",
    "RBAC_DENIED",
    "CLUSTER_NOT_FOUND",
    "RESOURCE_KIND_NOT_SUPPORTED",
    "CLUSTER_UNREACHABLE",
    "CLUSTER_ALREADY_EXISTS",
    "INVALID_KUBECONFIG",
    "NOT_IMPLEMENTED",
    "INTERNAL_ERROR",
)


class Error(ma.Schema):
    code = ma.fields.String(description="Stable OD-1 error code", enum=list(_CODES))
    message = ma.fields.String()
    details = ma.fields.Dict(required=False)


class ErrorOut(ma.Schema):
    error = ma.Nested(Error)
