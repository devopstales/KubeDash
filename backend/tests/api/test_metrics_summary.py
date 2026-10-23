"""Task 3 — GET /api/v1/clusters/<id>/metrics/summary.

Docker-free unit tier (same fixture pattern as test_resources.py): FakeK8s
injected through the pool's ``factory`` seam, the SAR answered by the
``rbac._sar_allowed`` module seam. The cluster-registration + SAR helpers
are shared in ``tests/api/_helpers.py`` (also consumed by test_events.py).
SATISFIES: summary-endpoint-rbac-denied;
summary-used-gated-separately-on-metrics-read;
summary-metrics-unavailable-not-zero (endpoint half).
"""

import pytest

from tests.api._helpers import register_cluster as _register, sar as _sar

NODES = [
    {
        "metadata": {"name": "n1"},
        "status": {
            "capacity": {"cpu": "4000m", "memory": "8Gi"},
            "allocatable": {"pods": "110"},
        },
    }
]
PODS = [
    {
        "metadata": {"name": "web", "namespace": "default"},
        "spec": {
            "containers": [
                {
                    "resources": {
                        "requests": {"cpu": "2000m", "memory": "2Gi"},
                        "limits": {"memory": "4Gi"},
                    }
                }
            ]
        },
        "status": {"phase": "Running"},
    }
]
USAGE = {"n1": {"cpu_millicores": 800, "memory_bytes": 4 * 2**30}}


class FakeK8s:
    """Double standing in for a live K8sClient: node/pod lists plus the
    Metrics-API read (``available`` toggles the 404-shaped response)."""

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.node_usage_calls = 0

    def list_nodes(self, _namespace: str | None) -> list[dict]:
        return NODES

    def list_pods(self, _namespace: str | None) -> list[dict]:
        return PODS

    def node_usage(self, name: str | None = None) -> tuple[bool, dict | None]:
        self.node_usage_calls += 1
        if not self.available:
            return (False, {} if name is None else None)
        if name is None:
            return (True, USAGE)
        return (True, USAGE.get(name))

    def node_metrics(self) -> tuple[bool, list[dict]]:
        # Mirrors the real contract: join USAGE with NODES' status.capacity,
        # keyed by node name. Unavailable -> (False, []) (never zero-filled).
        if not self.available:
            return (False, [])
        out = []
        for name, u in USAGE.items():
            cap = next((n["status"]["capacity"] for n in NODES if n["metadata"]["name"] == name), {})
            out.append(
                {
                    "name": name,
                    "cpu_used_millicores": u["cpu_millicores"],
                    "cpu_capacity_millicores": int(str(cap.get("cpu", "0m")).rstrip("m") or 0),
                    "memory_used_bytes": u["memory_bytes"],
                    "memory_capacity_bytes": 8 * 2**30,  # NODES memory "8Gi"
                }
            )
        return (True, out)


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    """Inject the FakeK8s factory into the metrics module's pool binding
    (the same seam test_resources.py patches)."""
    import importlib

    import app.services.k8s_client as kc

    fake = FakeK8s()
    metrics = importlib.import_module("app.api.metrics")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(metrics.__dict__, "pool", fake_pool)
    return fake


def _allow_all(monkeypatch: pytest.MonkeyPatch) -> None:
    _sar(monkeypatch)


def _allow_core_only(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """pods/nodes cluster-wide allowed, metrics.k8s.io read denied."""
    asked: list[tuple] = []
    _sar(
        monkeypatch,
        allow={("list", "pods", ""), ("list", "nodes", "")},
        record=asked,
    )
    return asked


def _summary(api_client, headers) -> object:
    return api_client.get("/api/v1/clusters/1/metrics/summary", headers=headers)


def test_summary_200_with_sums(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """summary-computes-overcommit (endpoint half): capacity/requests/used
    sums, metrics_available true."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _summary(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is True
    assert body["metrics_denied"] is False
    assert body["cpu"] == {
        "capacity_millicores": 4000,
        "used_millicores": 800,
        "requests_millicores": 2000,
        "limits_millicores": 0,
    }
    assert body["memory"] == {
        "capacity_bytes": 8 * 2**30,
        "used_bytes": 4 * 2**30,
        "requests_bytes": 2 * 2**30,
        "limits_bytes": 4 * 2**30,
    }
    assert body["pods"] == {"capacity": 110, "running": 1, "pending": 0, "completed": 0}


def test_rbac_denied_when_pods_list_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """summary-endpoint-rbac-denied: no cluster-wide pods/nodes list ->
    403 RBAC_DENIED, no count returned. Triangulation input 1: pods denied,
    nodes allowed."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _sar(monkeypatch, allow={("list", "nodes", "")})
    r = _summary(api_client, h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_rbac_denied_when_nodes_list_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """summary-endpoint-rbac-denied, triangulation input 2: nodes denied,
    pods allowed — the tier is AND, so this must also be 403."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _sar(monkeypatch, allow={("list", "pods", "")})
    r = _summary(api_client, h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_rbac_denied_without_k8s_call(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """403 fires BEFORE any cluster data is fetched (ADR-0004: a derived
    count must never leak) — the pool client is never consulted."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _sar(monkeypatch, allow=set())

    def boom(*_a, **_k):
        raise AssertionError("pool consulted before the RBAC gate")

    fake_k8s.list_nodes = boom  # type: ignore[method-assign]
    fake_k8s.list_pods = boom  # type: ignore[method-assign]
    r = _summary(api_client, h)
    assert r.status_code == 403
    assert fake_k8s.node_usage_calls == 0


def test_metrics_read_denied_keeps_declared(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """summary-used-gated-separately-on-metrics-read: core list allowed but
    ``get nodes`` on metrics.k8s.io denied -> 200, metrics_available false,
    used null, declared/declared-state fields still present; usage is never
    fetched (distinct source, distinct gate)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _allow_core_only(monkeypatch)
    r = _summary(api_client, h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["metrics_available"] is False
    # The distinct state (OWASP A05/A10): the UI must say "you lack the
    # grant", not "install metrics-server".
    assert body["metrics_denied"] is True
    assert body["cpu"]["used_millicores"] is None
    assert body["memory"]["used_bytes"] is None
    # Declared + capacity unaffected by the metrics gate.
    assert body["cpu"]["requests_millicores"] == 2000
    assert body["cpu"]["capacity_millicores"] == 4000
    assert body["memory"]["requests_bytes"] == 2 * 2**30
    assert body["memory"]["limits_bytes"] == 4 * 2**30
    assert fake_k8s.node_usage_calls == 0
    # The second tier is actually asked: metrics.k8s.io node read.
    assert ("get", "nodes", None, None, "metrics.k8s.io") in asked


def test_metrics_404_is_200_unknown_not_500(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """summary-metrics-unavailable-not-zero (endpoint half): RBAC passes but
    the Metrics API 404s (node_usage -> (False, {})) -> 200,
    metrics_available false, used null — never 500, never 0."""
    fake_k8s.available = False
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _summary(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    # RBAC passed; the Metrics API itself is absent. The UI must say
    # "install metrics-server" (not "you lack the grant").
    assert body["metrics_denied"] is False
    assert body["cpu"]["used_millicores"] is None
    assert body["memory"]["used_bytes"] is None
    # Declared state still returned from pod specs.
    assert body["cpu"]["requests_millicores"] == 2000
    assert body["memory"]["limits_bytes"] == 4 * 2**30
    assert fake_k8s.node_usage_calls == 1


def _node_metrics(api_client, headers) -> object:
    return api_client.get("/api/v1/clusters/1/metrics/nodes", headers=headers)


def test_node_metrics_series_with_capacity(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """metrics-nodes-series (blueprint Task 3): the per-node series joins the
    Metrics API usage with core-v1 capacity, keyed by node name."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _node_metrics(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["cluster"] == "prod"
    assert body["metrics_available"] is True
    assert body["source"] == "metrics.k8s.io"
    item = body["items"][0]
    assert item["name"] == "n1"
    assert item["cpu_used_millicores"] == 800
    assert item["cpu_capacity_millicores"] == 4000  # from NODES status.capacity
    assert item["memory_used_bytes"] == 4 * 2**30
    assert item["memory_capacity_bytes"] == 8 * 2**30


def test_node_metrics_unavailable_is_empty_not_zero(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """metrics-nodes-unavailable (blueprint Task 3): Metrics API 404s ->
    metrics_available false, items [] — never 500, never a zero-filled series."""
    fake_k8s.available = False
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _node_metrics(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    assert body["items"] == []


def test_node_metrics_denied_is_200_empty(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """metrics-nodes-denied: get nodes on metrics.k8s.io denied -> 200 with
    empty items (the table renders unknown used, not a 403)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_core_only(monkeypatch)
    r = _node_metrics(api_client, h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    assert body["items"] == []


def _node_usage(api_client, headers, name: str = "n1") -> object:
    return api_client.get(f"/api/v1/clusters/1/nodes/{name}/usage", headers=headers)


def test_node_usage_200_with_used(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """node-detail-usage: metrics allowed + available -> 200 with the node's
    used values (the node detail view's observed tier)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _node_usage(api_client, h, "n1")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is True
    assert body["metrics_denied"] is False
    assert body["used_millicores"] == 800
    assert body["used_bytes"] == 4 * 2**30


def test_node_usage_metrics_denied_is_200_not_403(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """node-detail-usage-gated: metrics.k8s.io read denied -> 200 with
    metrics_denied true and null used (the declared state still renders; the
    used tier degrades to unknown, never a 403 error on the detail page)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_core_only(monkeypatch)
    r = _node_usage(api_client, h, "n1")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_denied"] is True
    assert body["used_millicores"] is None
    assert body["used_bytes"] is None
    assert fake_k8s.node_usage_calls == 0  # never fetched


def test_node_usage_unavailable_is_null_not_zero(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """node-detail-usage-unavailable: metrics allowed but the Metrics API 404s
    -> 200, metrics_available false, used null — never 0, never 500."""
    fake_k8s.available = False
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _node_usage(api_client, h, "n1")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is False
    assert body["used_millicores"] is None


def test_node_usage_unscraped_node_is_null(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """node-detail-usage-unscraped: metrics available but the node is not in
    the metrics list (just added, or vanished) -> 200, used null, never 0."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_all(monkeypatch)
    r = _node_usage(api_client, h, "ghost-node")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["metrics_available"] is True
    assert body["used_millicores"] is None
    assert body["used_bytes"] is None
