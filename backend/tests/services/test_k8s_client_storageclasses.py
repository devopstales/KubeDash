from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(storage: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._storage = storage
    return client


def test_list_storage_classes_ignores_namespace() -> None:
    """[storageclasses-list-ignores-namespace] cluster-scoped: the
    namespace argument is accepted and ignored (the ``list_nodes``
    pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "csi-fast"},
            "provisioner": "csi.example.com",
            "reclaim_policy": "Delete",
            "volume_binding_mode": "WaitForFirstConsumer",
        }
    )
    storage = SimpleNamespace(
        list_storage_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
    )
    result = _client(storage).list_storage_classes("team-a")
    assert result == [
        {
            "metadata": {"name": "csi-fast"},
            "provisioner": "csi.example.com",
            "reclaim_policy": "Delete",
            "volume_binding_mode": "WaitForFirstConsumer",
        }
    ]
    assert seen == [True]  # called once, cluster list


def test_get_storage_class_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "csi-fast"}})
    storage = SimpleNamespace(read_storage_class=lambda name: item)
    assert _client(storage).get_storage_class(None, "csi-fast") == [
        {"metadata": {"name": "csi-fast"}}
    ]


def test_get_storage_class_404_returns_empty_list() -> None:
    """[storageclasses-get-by-name] a miss is ``[]``, mirroring
    ``get_priority_class``'s 0/1-item contract."""
    def read(_name: str) -> None:
        raise ApiException(status=404)

    storage = SimpleNamespace(read_storage_class=read)
    assert _client(storage).get_storage_class(None, "gone") == []


def test_get_storage_class_ignores_namespace() -> None:
    """cluster-scoped: the namespace is accepted and ignored (the
    ``get_priority_class`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "csi-fast"}})
    storage = SimpleNamespace(read_storage_class=lambda name: (seen.append(name), item)[1])
    _client(storage).get_storage_class("team-a", "csi-fast")  # ns ignored
    assert seen == ["csi-fast"]


def test_get_storage_class_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_storage_class=read)).get_storage_class(None, "csi-fast")


def test_list_storage_classes_maps_500_to_unreachable() -> None:
    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_storage_class=list_all)).list_storage_classes(None)
