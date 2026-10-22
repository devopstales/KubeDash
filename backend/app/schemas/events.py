"""Events response contract (Task 4, R3).

``EventOut`` is the DOCUMENTED item contract for ``GET /clusters/<id>/
events`` — the shape the OpenAPI spec shows for this route. It is docs-only:
the endpoint returns a bare list (the smorest list-dump limitation, see the
ponytail in ``api/events.py``), so no marshmallow serialization runs at
request time. The field set and types here are what the runtime payload
guarantees.

The runtime shape is cluster-native: kubernetes 37.0.1's
``CoreV1Event.to_dict()`` emits snake_case keys (``last_timestamp``,
``involved_object``); ``last_timestamp`` is a ``datetime`` on the Python
side, which Flask's jsonify serializes to an RFC-1123 string in the wire
payload (hence the ``String`` field type here).
"""

from marshmallow import Schema
from marshmallow.fields import Dict, Integer, String


class EventOut(Schema):
    """``GET /clusters/<id>/events`` — one cluster event (newest-first).

    ``involved_object`` carries kind/name/namespace; ``count`` is the raw
    event count (None when the API omits it). ``last_timestamp`` is the
    sort key (desc).
    """

    type = String()
    reason = String()
    involved_object = Dict()
    message = String()
    count = Integer(allow_none=True)
    last_timestamp = String(allow_none=True)
