"""Cluster registry request/response schemas (R3)."""
from marshmallow import Schema
from marshmallow.fields import DateTime, Int, String


class ClusterIn(Schema):
    """Registration body. ``kubeconfig`` is the plaintext YAML document — it
    is validated with ``yaml.safe_load`` in the handler (422 on failure) and
    stored ONLY in its encrypted OD-2 form; ``api_server`` is the cluster's
    API endpoint, recorded for display and the health probe."""

    name = String(required=True)
    api_server = String(required=True)
    kubeconfig = String(required=True)
    context = String(required=True)


class ClusterOut(Schema):
    """A bound cluster as listed/fetched — the ciphertext never leaves the
    registry, so the response carries the at-rest form, not the plaintext."""

    id = Int()
    name = String()
    api_server = String()
    context = String(allow_none=True)
    status = String()
    last_probe_at = DateTime(allow_none=True)


class HealthOut(Schema):
    status = String()
