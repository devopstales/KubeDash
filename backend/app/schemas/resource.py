"""Resource list response schema (R4).

The item shape is cluster-native (the kubernetes ``to_dict`` form of each
object), so ``items`` stays ``dict``-typed: a generic endpoint cannot
promise a per-kind marshmallow shape without one schema per kind — the
``_KINDS`` table grows a row per kind, not a schema per kind.
"""
from marshmallow import Schema
from marshmallow.fields import Dict, List, String


class ResourceListOut(Schema):
    """``GET /clusters/<id>/resources/<kind>`` — the listed items plus the
    kind/cluster they were listed from (the ciphertext never leaves the
    registry, so no kubeconfig material appears here either)."""

    kind = String()
    cluster = String()
    items = List(Dict())
