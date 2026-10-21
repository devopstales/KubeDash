from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterAlreadyExistsError, ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_create_namespace_returns_cluster_object() -> None:
    seen: list[object] = []
    namespace = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "team-a"}})
    v1 = SimpleNamespace(
        create_namespace=lambda body: (seen.append(body), namespace)[1],
    )
    result = _client(v1).create_namespace("team-a")
    assert result == {"metadata": {"name": "team-a"}}
    assert seen[0].metadata.name == "team-a"


def test_create_namespace_maps_409_to_conflict() -> None:
    def create_namespace(_body: object) -> None:
        raise ApiException(status=409)

    with pytest.raises(ClusterAlreadyExistsError):
        _client(SimpleNamespace(create_namespace=create_namespace)).create_namespace("team-a")


def test_create_namespace_maps_other_api_error_to_unreachable() -> None:
    def create_namespace(_body: object) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(create_namespace=create_namespace)).create_namespace("team-a")


def test_delete_namespace_is_idempotent_on_404() -> None:
    def delete_namespace(_name: str) -> None:
        raise ApiException(status=404)

    _client(SimpleNamespace(delete_namespace=delete_namespace)).delete_namespace("gone")
