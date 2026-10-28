from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_resource_quotas_in_namespace() -> None:
    """[resourcequotas-list-200-in-namespace] a namespace is forwarded to
    ``list_namespaced_resource_quota`` (the ``list_secrets`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "compute", "namespace": "team-a"},
            "status": {
                "hard": {"requests.cpu": "4", "limits.memory": "20Gi"},
                "used": {"requests.cpu": "2", "limits.memory": "8Gi"},
            },
        }
    )
    v1 = SimpleNamespace(
        list_namespaced_resource_quota=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(v1).list_resource_quotas("team-a")
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_resource_quotas_all_namespaces_without_namespace() -> None:
    """[resourcequotas-list-all-namespaces-without-param] ``None`` uses
    the all-namespaces call (the ``list_secrets`` branch)."""
    seen: list[object] = []
    v1 = SimpleNamespace(
        list_resource_quota_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(v1).list_resource_quotas(None) == []
    assert seen == [True]


def test_list_resource_quotas_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_resource_quota=list_all)).list_resource_quotas("team-a")


def test_get_resource_quota_404_returns_empty_list() -> None:
    """[resourcequotas-get-by-name] a miss is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    v1 = SimpleNamespace(read_namespaced_resource_quota=read)
    assert _client(v1).get_resource_quota("team-a", "ghost") == []


def test_get_resource_quota_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "compute"}})
    v1 = SimpleNamespace(read_namespaced_resource_quota=lambda name, namespace: item)
    assert _client(v1).get_resource_quota("team-a", "compute") == [
        {"metadata": {"name": "compute"}}
    ]


def test_get_resource_quota_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_resource_quota=read)).get_resource_quota(
            "team-a", "compute"
        )
