from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_configmaps_namespaced_keeps_data() -> None:
    """[configmaps-list-200] a namespace is forwarded to
    ``list_namespaced_config_map`` (the ``list_secrets`` pattern), and the
    read does NOT pop ``data``: a ConfigMap's ``data`` is public config,
    and the list view's Data Keys column is computed from it."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {
                "name": "app-config",
                "namespace": "team-a",
                "creation_timestamp": "2026-01-02T03:04:05Z",
                "resource_version": "4242",
                "labels": {"app": "web"},
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{}",
                    "owner": "platform",
                },
            },
            "data": {"LOG_LEVEL": "info", "URL": "https://internal"},
        }
    )
    v1 = SimpleNamespace(
        list_namespaced_config_map=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(v1).list_configmaps("team-a")
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert result[0]["data"] == {"LOG_LEVEL": "info", "URL": "https://internal"}  # NOT stripped
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_configmaps_all_namespaces_without_namespace() -> None:
    """[configmaps-list-all-namespaces] ``None`` uses the all-namespaces
    call (the ``list_secrets`` branch)."""
    seen: list[object] = []
    v1 = SimpleNamespace(
        list_config_map_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(v1).list_configmaps(None) == []
    assert seen == [True]


def test_list_configmaps_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_config_map=list_all)).list_configmaps(
            "team-a"
        )


def test_get_configmap_404_returns_empty_list() -> None:
    """[configmaps-get-by-name] a miss is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    v1 = SimpleNamespace(read_namespaced_config_map=read)
    assert _client(v1).get_configmap("team-a", "ghost") == []


def test_get_configmap_hit_returns_one_item_with_data() -> None:
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "app-config", "namespace": "team-a"},
            "data": {"LOG_LEVEL": "info"},
        }
    )
    v1 = SimpleNamespace(read_namespaced_config_map=lambda name, namespace: item)
    assert _client(v1).get_configmap("team-a", "app-config") == [
        {"metadata": {"name": "app-config", "namespace": "team-a"}, "data": {"LOG_LEVEL": "info"}}
    ]


def test_get_configmap_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_config_map=read)).get_configmap(
            "team-a", "app-config"
        )
