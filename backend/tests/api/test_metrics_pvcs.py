"""PVC-usage endpoint — GET /api/v1/clusters/<id>/metrics/pvcs.

Docker-free unit tier (same fixture pattern as test_metrics_summary.py):
FakeK8s injected through the pool's ``factory`` seam, the SAR answered by
the ``rbac._sar_allowed`` module seam. The cluster-registration + SAR
helpers are shared in ``tests/api/_helpers.py``.

SATISFIES: pvc-usage-happy-path; pvc-usage-sar-denied;
pvc-usage-kubelet-degrade (endpoint half); pvc-usage-binding-404;
pvc-usage-missing-namespace.
"""

import pytest

from tests.api._helpers import register_cluster as _register
from tests.api._helpers import sar as _sar


class FakeK8s:
    """Double standing in for a live K8sClient: only the ``pvc_usage`` read
    (``available`` toggles the stats-unavailable response; the call list
    proves the SAR gate / missing-namespace short-circuit happens BEFORE
    the read)."""

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.pvc_usage_calls: list[str] = []

    def pvc_usage(self, namespace: str) -> tuple[bool, list[dict]]:
        self.pvc_usage_calls.append(namespace)
        if not self.available:
            return (False, [])
        return (
            True,
            [
                {
                    "name": "data-pvc",
                    "capacity_bytes": 1000,
                    "used_bytes": 400,
                    "available_bytes": 600,
                    "percentage_used": 40.0,
                }
            ],
        )


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    """Inject the FakeK8s factory into the metrics module's pool binding
    (the same seam test_metrics_summary.py patches)."""
    import importlib

    import app.services.k8s_client as kc

    fake = FakeK8s()
    metrics = importlib.import_module("app.api.metrics")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(metrics.__dict__, "pool", fake_pool)
    return fake


def _allow_core_nodes(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Allow ``get nodes`` on the CORE group (empty string) and record
    every SAR call."""
    asked: list[tuple] = []
    _sar(monkeypatch, allow={("get", "nodes", "")}, record=asked)
    return asked


def _deny_all(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Deny every SAR and record the calls."""
    asked: list[tuple] = []
    _sar(monkeypatch, allow=set(), record=asked)
    return asked


def _pvcs(api_client, headers, namespace: str = "team-a") -> object:
    url = "/api/v1/clusters/1/metrics/pvcs"
    if namespace is not None:
        url += f"?namespace={namespace}"
    return api_client.get(url, headers=headers)


def test_pvc_usage_happy_path(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvc-usage-happy-path] get nodes allowed on the core group -> 200
    with the kubelet source, metrics_available true, one item in the
    exact response shape."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _allow_core_nodes(monkeypatch)
    r = _pvcs(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["cluster"] == "prod"
    assert body["namespace"] == "team-a"
    assert body["source"] == "kubelet stats/summary"
    assert body["metrics_available"] is True
    assert body["metrics_denied"] is False
    [item] = body["items"]
    assert item == {
        "name": "data-pvc",
        "capacity_bytes": 1000,
        "used_bytes": 400,
        "available_bytes": 600,
        "percentage_used": 40.0,
    }
    assert ("get", "nodes", None, None, "") in asked
    assert fake_k8s.pvc_usage_calls == ["team-a"]


def test_pvc_usage_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvc-usage-sar-denied] ADR-0004: get nodes on the core group is
    asked BEFORE any stats call; a deny degrades to 200
    ``metrics_denied: true`` + empty items — NEVER a 403, and the read is
    never made."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _deny_all(monkeypatch)
    r = _pvcs(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    assert body["metrics_denied"] is True
    assert body["items"] == []
    assert ("get", "nodes", None, None, "") in asked
    assert fake_k8s.pvc_usage_calls == []  # the stats read was never made


def test_pvc_usage_kubelet_degrade(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvc-usage-kubelet-degrade] ADR-0003: no node yields stats -> 200
    ``metrics_available: false`` + empty items — never 500, and NOT
    ``metrics_denied`` (the grant is present; the stats source is not)."""
    fake_k8s.available = False
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_core_nodes(monkeypatch)
    r = _pvcs(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    assert body["metrics_denied"] is False
    assert body["items"] == []
    assert fake_k8s.pvc_usage_calls == ["team-a"]


def test_pvc_usage_binding_404(api_client, auth_client) -> None:
    """[pvc-usage-binding-404] an unbound user: the binding gate fails
    before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/metrics/pvcs?namespace=team-a", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_pvc_usage_missing_namespace_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[pvc-usage-missing-namespace] no ?namespace= -> 200
    ``metrics_available: false`` + empty items (4.1 had no all-namespace
    branch for this read); the SAR is never asked and the read never made
    (the param check short-circuits first)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _allow_core_nodes(monkeypatch)
    r = _pvcs(api_client, h, namespace=None)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["namespace"] == ""
    assert body["metrics_available"] is False
    assert body["metrics_denied"] is False
    assert body["items"] == []
    assert asked == []  # the SAR was never asked
    assert fake_k8s.pvc_usage_calls == []  # the stats read was never made
