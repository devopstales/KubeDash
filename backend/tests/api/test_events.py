"""Task 4 — GET /api/v1/clusters/<id>/events.

Docker-free unit tier (same fixture pattern as test_metrics_summary.py):
FakeK8s injected through the pool's ``factory`` seam, the SAR answered by
the ``rbac._sar_allowed`` module seam. The cluster-registration + SAR
helpers are shared in ``tests/api/_helpers.py``. SATISFIES:
events-endpoint-lists; events-endpoint-rbac-denied.
"""

import pytest

from tests.api._helpers import register_cluster as _register, sar as _sar


def _event(seq: int, ns: str = "default") -> dict:
    """One event item in the EXACT ``CoreV1Event.to_dict()`` shape
    (kubernetes 37.0.1): snake_case keys, ``datetime`` for
    ``last_timestamp``, full ``involved_object`` reference with null
    fields. ``seq`` maps to microsecond-offset from a fixed base so any
    count produces unique, sortable timestamps."""
    import datetime
    import zoneinfo

    base = datetime.datetime(2026, 10, 20, 0, 0, 0, tzinfo=zoneinfo.ZoneInfo("UTC"))
    t = base + datetime.timedelta(microseconds=seq)
    return {
        "action": None,
        "api_version": None,
        "count": seq,
        "event_time": None,
        "first_timestamp": t,
        "involved_object": {
            "api_version": None,
            "field_path": None,
            "kind": "Pod",
            "name": f"pod-{seq}",
            "namespace": ns,
            "resource_version": None,
            "uid": None,
        },
        "kind": None,
        "last_timestamp": t,
        "message": f"message {seq}",
        "metadata": {"name": f"evt-{seq}", "namespace": ns},
        "reason": "BackOff" if seq % 2 else "Pulled",
        "related": None,
        "reporting_component": None,
        "reporting_instance": None,
        "series": None,
        "source": None,
        "type": "Warning" if seq % 2 else "Normal",
    }


# Two events in OLDER-first order (the API must sort newest-first).
EVENTS = [_event(1), _event(2)]


class FakeK8s:
    """Double standing in for a live K8sClient: the cluster-wide event list."""

    def list_events(self, _namespace: str | None) -> list[dict]:
        return EVENTS


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    """Inject the FakeK8s factory into the events module's pool binding."""
    import importlib

    import app.services.k8s_client as kc

    fake = FakeK8s()
    events_mod = importlib.import_module("app.api.events")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(events_mod.__dict__, "pool", fake_pool)
    return fake


def _allow_all(monkeypatch: pytest.MonkeyPatch) -> None:
    _sar(monkeypatch)


def _events(api_client, headers) -> object:
    return api_client.get("/api/v1/clusters/1/events", headers=headers)


def test_events_200_newest_first(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """events-endpoint-lists (happy path): 200, events sorted newest-first
    by last_timestamp desc, EventOut fields present in the real
    ``CoreV1Event.to_dict()`` shape (snake_case, datetime timestamps)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _events(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert isinstance(body, list)
    assert len(body) == 2
    # Newest first: seq 2 (last_timestamp 00:01) before seq 1 (00:00).
    assert body[0]["involved_object"]["name"] == "pod-2"
    assert body[1]["involved_object"]["name"] == "pod-1"
    # EventOut fields present and shaped correctly on each event.
    for item in body:
        assert item["type"] in ("Normal", "Warning")
        assert "reason" in item
        assert "message" in item
        assert "count" in item
        assert "last_timestamp" in item
        io = item["involved_object"]
        assert io["kind"] == "Pod"
        assert io["name"]
        assert io["namespace"]
    # last_timestamp round-trips as the RFC-1123 string jsonify emits for
    # the datetime the client form carries.
    assert "2026" in body[0]["last_timestamp"]


def test_events_rbac_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """events-endpoint-rbac-denied (failure): no cluster-wide ``list events``
    -> 403 RBAC_DENIED, no data returned."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _sar(monkeypatch, allow=set())
    r = _events(api_client, h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_events_403_before_pool(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """403 fires BEFORE any cluster data is fetched (ADR-0004) — the pool
    client is never consulted."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _sar(monkeypatch, allow=set())

    def boom(*_a, **_k):
        raise AssertionError("pool consulted before the RBAC gate")

    fake_k8s.list_events = boom  # type: ignore[method-assign]
    r = _events(api_client, h)
    assert r.status_code == 403


def test_events_limit_100(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """Default limit: 150 events on the cluster -> exactly 100 returned,
    the NEWEST 100, newest-first."""
    fake_k8s.list_events = lambda _namespace: [_event(i) for i in range(150)]
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _events(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert len(body) == 100
    # Newest first: the first item is the newest (seq 149), the last the
    # oldest of the returned window (seq 50).
    assert body[0]["involved_object"]["name"] == "pod-149"
    assert body[-1]["involved_object"]["name"] == "pod-50"
