"""Task 3 — GET /api/v1/clusters/<id>/metrics/summary.

Docker-free unit tier (same fixture pattern as test_resources.py): FakeK8s
injected through the pool's ``factory`` seam, the SAR answered by the
``rbac._sar_allowed`` module seam. SATISFIES: summary-endpoint-rbac-denied;
summary-used-gated-separately-on-metrics-read;
summary-metrics-unavailable-not-zero (endpoint half).
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

    def node_usage(self) -> tuple[bool, dict]:
        self.node_usage_calls += 1
        return (True, USAGE) if self.available else (False, {})


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


def _allow_core_only(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """pods/nodes cluster-wide allowed, metrics.k8s.io read denied."""
    asked: list[tuple] = []
    _sar(
        monkeypatch,
        allow={("list", "pods", ""), ("list", "nodes", "")},
        record=asked,
    )
    return asked


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
    assert body["cpu"]["used_millicores"] is None
    assert body["memory"]["used_bytes"] is None
    # Declared state still returned from pod specs.
    assert body["cpu"]["requests_millicores"] == 2000
    assert body["memory"]["limits_bytes"] == 4 * 2**30
    assert fake_k8s.node_usage_calls == 1
