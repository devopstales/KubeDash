"""Events response schema (Task 4, R3).

The shape is cluster-native (the kubernetes ``to_dict`` form of each
``V1Event``, snake_cased by the kubernetes library). ``lastTimestamp``
arrives as ``last_timestamp`` in the ``to_dict`` form.
"""

from marshmallow import Schema
from marshmallow.fields import Dict, Integer, String


class EventOut(Schema):
    """``GET /clusters/<id>/events`` — one cluster event, newest-first.

    ``involved_object`` carries kind/name/namespace; the message and count
    are the raw event fields. ``last_timestamp`` is the sort key (desc).
    """

    type = String()
    reason = String()
    involved_object = Dict()
    message = String()
    count = Integer(allow_none=True)
    last_timestamp = String(allow_none=True)
