"""Task 4 — GET /api/v1/clusters/<id>/events.

Docker-free unit tier (same fixture pattern as test_metrics_summary.py):
FakeK8s injected through the pool's ``factory`` seam, the SAR answered by
the ``rbac._sar_allowed`` module seam. SATISFIES: events-endpoint-lists;
events-endpoint-rbac-denied.
"""

import pytest

KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    "contexts:\n"
    "- name: c\n"
    "  context:\n"
    "    cluster: c\n"
    "    user: u\n"
    "current-context: c\n"
    "users:\n"
    "- name: u\n"
    "  user: {}\n"
)

# Events in OLDER-first order (the API must sort newest-first).
EVENTS = [
    {
        "type": "Normal",
        "reason": "Pulled",
        "message": "Container image pulled",
        "count": 1,
        "firstTimestamp": "2026-10-20T00:00:00Z",
        "lastTimestamp": "2026-10-20T00:00:00Z",
        "involvedObject": {
            "kind": "Pod",
            "name": "web-0",
            "namespace": "default",
        },
    },
    {
        "type": "Warning",
        "reason": "BackOff",
        "message": "Back-off restarting failed container",
        "count": 5,
        "firstTimestamp": "2026-10-20T00:01:00Z",
        "lastTimestamp": "2026-10-20T00:02:00Z",
        "involvedObject": {
            "kind": "Pod",
            "name": "db-0",
            "namespace": "prod",
        },
    },
]


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


def _sar(
    monkeypatch: pytest.MonkeyPatch,
    allow: set[tuple] | None = None,
    record: list[tuple] | None = None,
) -> None:
    """Patch the SAR seam: allow the exact (verb, resource, group) calls in
    ``allow`` (None = allow everything), record every call in ``record``."""
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)

    def sar_allowed(client, verb, resource, ns, name, group=""):
        key = (verb, resource, group)
        if record is not None:
            record.append((verb, resource, ns, name, group))
        return True if allow is None else key in allow

    monkeypatch.setattr(rb, "_sar_allowed", sar_allowed)


def _allow_all(monkeypatch: pytest.MonkeyPatch) -> None:
    _sar(monkeypatch)


def _register(api_client, headers, name="prod") -> None:
    r = api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )
    assert r.status_code == 201


def _events(api_client, headers) -> object:
    return api_client.get("/api/v1/clusters/1/events", headers=headers)


def test_events_200_newest_first(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """events-endpoint-lists (happy path): 200, events sorted newest-first
    by last_timestamp desc, snake_case fields present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _events(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert isinstance(body, list)
    assert len(body) == 2
    # Newest first: Warning/BackOff (lastTimestamp 00:02) before Normal/Pulled (00:00).
    assert body[0]["reason"] == "BackOff"
    assert body[1]["reason"] == "Pulled"
    # snake_case fields present on each event.
    for item in body:
        assert item["type"] in ("Normal", "Warning")
        assert "reason" in item
        assert "message" in item
        assert "count" in item
        assert "last_timestamp" in item
        io = item["involved_object"]
        assert io["kind"] is not None
        assert io["name"] is not None
        assert io["namespace"] is not None


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
