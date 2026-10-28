from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(node: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._node = node
    return client


def test_list_runtime_classes_ignores_namespace() -> None:
    """[runtimeclasses-list-ignores-namespace] cluster-scoped: the
    namespace argument is accepted and ignored (the ``list_nodes``
    pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "runc"},
            "handler": "runc",
        }
    )
    node = SimpleNamespace(
        list_runtime_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
    )
    result = _client(node).list_runtime_classes("team-a")
    assert result == [{"metadata": {"name": "runc"}, "handler": "runc"}]
    assert seen == [True]  # called once, cluster list


def test_get_runtime_class_404_returns_empty_list() -> None:
    """[runtimeclasses-get-by-name] a miss is ``[]``, mirroring
    ``get_priority_class``'s 0/1-item contract."""
    def read(_name: str) -> None:
        raise ApiException(status=404)

    node = SimpleNamespace(read_runtime_class=read)
    assert _client(node).get_runtime_class(None, "gone") == []


def test_get_runtime_class_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_runtime_class=read)).get_runtime_class(None, "runc")


def test_list_runtime_classes_maps_500_to_unreachable() -> None:
    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_runtime_class=list_all)).list_runtime_classes(None)
