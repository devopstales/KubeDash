"""Resource list response schema (R4).

The item shape is cluster-native (the kubernetes ``to_dict`` form of each
object), so ``items`` stays ``dict``-typed: a generic endpoint cannot
promise a per-kind marshmallow shape without one schema per kind — the
``_KINDS`` table grows a row per kind, not a schema per kind.
"""
from marshmallow import Schema
from marshmallow.fields import Dict, List, Nested, String


class ResourceListOut(Schema):
    """``GET /clusters/<id>/resources/<kind>`` — the listed items plus the
    kind/cluster they were listed from (the ciphertext never leaves the
    registry, so no kubeconfig material appears here either)."""

    kind = String()
    cluster = String()
    items = List(Dict())


class NamespaceIn(Schema):
    name = String(required=True)


class NamespaceMutationOut(Schema):
    name = String(required=True)


class ApplyObjectIn(Schema):
    """One object for the generic apply (the converter's output shape)."""

    kind = String(required=True)
    apiVersion = String(required=True)
    metadata = Dict()
    spec = Dict()


class ApplyIn(Schema):
    """``POST /clusters/<id>/resources/apply`` — the target namespace and
    the objects to apply (all-or-nothing in the SAR phase, per-object in
    the apply phase)."""

    namespace = String(required=True)
    objects = List(Nested(ApplyObjectIn), required=True)


class AppliedOut(Schema):
    kind = String()
    name = String()
    namespace = String(allow_none=True)
    status = String()


class ApplyErrorOut(Schema):
    kind = String()
    name = String()
    message = String()


class ApplyOut(Schema):
    """Partial failure is a 200 with ``errors`` populated, not a 500."""

    applied = List(Nested(AppliedOut))
    errors = List(Nested(ApplyErrorOut))
