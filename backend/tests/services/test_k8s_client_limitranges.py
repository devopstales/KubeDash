from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

LR = {"metadata": {"name": "default", "namespace": "team-a"},
      "spec": {"limits": [{"type": "Container",
                           "max": {"cpu": "2", "memory": "4Gi"},
                           "min": {"cpu": "500m", "memory": "1Gi"}}]}}


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_limit_ranges_uses_namespace() -> None:
    """[limitranges-list-respects-namespace] namespaced kind: the
    namespace argument drives ``list_namespaced_limit_range`` (the
    ``list_network_policies`` pattern — NOT the accept-and-ignore
    cluster-scoped one)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: dict(LR))
    v1 = SimpleNamespace(
        list_namespaced_limit_range=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1],
    )
    result = _client(v1).list_limit_ranges("team-a")
    assert result == [LR]
    assert seen == ["team-a"]  # the namespace was passed through


def test_list_limit_ranges_all_namespaces_when_none() -> None:
    """[limitranges-list-200] no namespace hits the all-namespaces branch
    (the ``list_secrets`` branch)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: dict(LR))
    v1 = SimpleNamespace(
        list_limit_range_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[item]),
        )[1],
    )
    assert _client(v1).list_limit_ranges(None) == [LR]
    assert seen == [True]  # the all-namespaces list was called


def test_get_limit_range_hit_returns_one_item() -> None:
    """[limitranges-get-by-name] a hit is the single object."""
    item = SimpleNamespace(to_dict=lambda: dict(LR))
    v1 = SimpleNamespace(read_namespaced_limit_range=lambda name, ns: item)
    assert _client(v1).get_limit_range("team-a", "default") == [LR]


def test_get_limit_range_404_returns_empty_list() -> None:
    """[limitranges-get-by-name] a miss is ``[]``, mirroring
    ``get_network_policy``'s 0/1-item contract."""
    def read(name, ns) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_namespaced_limit_range=read)).get_limit_range("team-a", "gone") == []


def test_get_limit_range_other_api_error_maps_to_unreachable() -> None:
    def read(name, ns) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_limit_range=read)).get_limit_range("team-a", "default")


def test_list_limit_ranges_maps_500_to_unreachable() -> None:
    def list_all(ns) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_limit_range=list_all)).list_limit_ranges("team-a")
