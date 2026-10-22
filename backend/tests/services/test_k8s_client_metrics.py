"""K8s client — cluster nodes + metrics.k8s.io node usage (Task 2).

Covers the client half of the acceptance scenarios
``summary-computes-overcommit`` (``client-node-usage-available``) and
``summary-metrics-unavailable-not-zero`` (``client-node-usage-unavailable``).

The metrics read goes through the shared ``ApiClient.call_api`` (kubernetes
37.0.1 has NO ``MetricsV1beta1Api`` and no ``V1NodeMetricsList`` model — see
Step 0 of the brief), so the test double stubs the raw ``RESTResponse`` that
``call_api`` returns (body UNREAD, materialized via ``.read()``), not a
deserialized model.
"""

import json
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

# The exact (method, path) the client must call against the Metrics API.
_METH = "GET"
_MPATH = ["/apis/metrics.k8s.io/v1beta1/nodes"]


def _node_metrics(name: str, cpu: str, mem: str) -> dict:
    """One item of the ``NodeMetricsList`` body (the metrics-server shape)."""
    return {
        "metadata": {"name": name},
        "timestamp": "2026-10-22T00:00:00Z",
        "window": "30s",
        "usage": {"cpu": cpu, "memory": mem},
    }


def _response(status: int, body: list | None = None) -> SimpleNamespace:
    """A raw RESTResponse double.

    Mirrors the real ``RESTResponse`` from kubernetes 37.0.1: ``call_api``
    returns it with the body UNREAD (``data`` is None); the caller must call
    ``.read()`` to materialize the bytes. The client's ``node_usage`` does
    exactly that (it cannot rely on a preloaded ``.data``).
    """
    data = json.dumps({"kind": "NodeMetricsList", "items": body or []}).encode()
    return SimpleNamespace(status=status, read=lambda: data)


def _client(v1: object, call_api) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    client._api_client = SimpleNamespace(call_api=call_api)
    return client


def _raise_api(status: int):
    def call_api(*args, **kwargs):
        raise ApiException(status=status)

    return call_api


def test_node_usage_available_parses_single_node() -> None:
    seen: list[tuple] = []

    def call_api(*a, **k):
        seen.append((a, k))
        return _response(200, [_node_metrics("n1", "800m", "4Gi")])

    client = _client(SimpleNamespace(list_node=lambda: None), call_api)
    available, usage = client.node_usage()
    assert available is True
    assert usage == {"n1": {"cpu_millicores": 800, "memory_bytes": 4 * 2**30}}
    # The call hit the Metrics API GET (the only path that yields usage).
    assert seen and seen[0][0][:2] == (_METH, _MPATH)


def test_node_usage_available_parses_multiple_nodes() -> None:
    body = [
        _node_metrics("n1", "800m", "4Gi"),
        _node_metrics("n2", "1200m", "2Gi"),
        _node_metrics("n3", "500m", "1Gi"),
    ]

    def call_api(*a, **k):
        return _response(200, body)

    available, usage = _client(SimpleNamespace(list_node=lambda: None), call_api).node_usage()
    assert available is True
    assert usage == {
        "n1": {"cpu_millicores": 800, "memory_bytes": 4 * 2**30},
        "n2": {"cpu_millicores": 1200, "memory_bytes": 2 * 2**30},
        "n3": {"cpu_millicores": 500, "memory_bytes": 1 * 2**30},
    }


def test_node_usage_404_is_unavailable_not_error() -> None:
    call_api = _raise_api(404)
    client = _client(SimpleNamespace(list_node=lambda: None), call_api)
    available, usage = client.node_usage()
    assert available is False
    assert usage == {}


def test_node_usage_5xx_is_unavailable_not_error() -> None:
    call_api = _raise_api(500)
    available, usage = _client(SimpleNamespace(list_node=lambda: None), call_api).node_usage()
    assert available is False
    assert usage == {}


def test_node_usage_transport_failure_is_unreachable() -> None:
    # A non-4xx/5xx ApiException is a transport failure, not a "missing
    # metrics-server" — it must surface as 502 ClusterUnreachableError.
    call_api = _raise_api(403)
    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_node=lambda: None), call_api).node_usage()


def test_list_nodes_returns_node_dicts() -> None:
    node = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "n1"}})
    v1 = SimpleNamespace(list_node=lambda: SimpleNamespace(items=[node]))
    # Cluster-scoped: the resource route always passes the query namespace;
    # it is ignored for nodes (mirrors list_namespaces).
    result = _client(v1, lambda *a, **k: _response(200)).list_nodes("default")
    assert result == [{"metadata": {"name": "n1"}}]
