from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(scheduling: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._scheduling = scheduling
    return client


def test_list_priority_classes_ignores_namespace() -> None:
    """[priorityclasses-list-ignores-namespace] cluster-scoped: the namespace
    argument is accepted and ignored (the ``list_nodes`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "high"}})
    scheduling = SimpleNamespace(
        list_priority_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
    )
    result = _client(scheduling).list_priority_classes("team-a")
    assert result == [{"metadata": {"name": "high"}}]
    assert seen == [True]  # called once, cluster list


def test_get_priority_class_404_returns_empty_list() -> None:
    """[priorityclasses-get-by-name] a miss is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""
    def read(_name: str) -> None:
        raise ApiException(status=404)

    scheduling = SimpleNamespace(read_priority_class=read)
    assert _client(scheduling).get_priority_class(None, "gone") == []


def test_get_priority_class_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_priority_class=read)).get_priority_class(None, "high")


def test_list_priority_classes_maps_500_to_unreachable() -> None:
    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_priority_class=list_all)).list_priority_classes(None)
