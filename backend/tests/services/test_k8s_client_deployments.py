from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(apps: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._apps = apps
    return client


def test_list_deployments_in_namespace() -> None:
    """[deployments-list-200-in-namespace] a namespace is forwarded to
    ``list_namespaced_deployment`` (the ``list_horizontal_pod_autoscalers``
    pattern, apps/v1)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web", "namespace": "team-a"},
            "spec": {"replicas": 3},
            "status": {"replicas": 3, "ready_replicas": 2},
        }
    )
    apps = SimpleNamespace(
        list_namespaced_deployment=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(apps).list_deployments("team-a")
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert result[0]["status"]["ready_replicas"] == 2
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_deployments_all_namespaces_without_namespace() -> None:
    """[deployments-list-all-namespaces-without-param] ``None`` uses the
    all-namespaces call (the ``list_horizontal_pod_autoscalers`` branch)."""
    seen: list[object] = []
    apps = SimpleNamespace(
        list_deployment_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(apps).list_deployments(None) == []
    assert seen == [True]


def test_list_deployments_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_deployment=list_all)).list_deployments("team-a")


def test_get_deployment_hit_returns_one_item() -> None:
    """[deployments-get-by-name] a hit is the single full object in a
    0/1-item list (the generic resource route's ``items`` contract)."""
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web", "namespace": "team-a"},
            "spec": {"replicas": 3},
            "status": {"replicas": 3, "ready_replicas": 3},
        }
    )
    seen: list[tuple[str, str]] = []
    apps = SimpleNamespace(
        read_namespaced_deployment=lambda name, namespace, **kw: (
            seen.append((name, namespace)), item
        )[1]
    )
    assert _client(apps).get_deployment("team-a", "web") == [
        {
            "metadata": {"name": "web", "namespace": "team-a"},
            "spec": {"replicas": 3},
            "status": {"replicas": 3, "ready_replicas": 3},
        }
    ]
    assert seen == [("web", "team-a")]


def test_get_deployment_404_returns_empty_list() -> None:
    """[deployments-get-by-name] a miss is ``[]`` (the data page renders a
    not-found state, never an API error)."""

    def read(name: str, namespace: str, **kw: object) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_namespaced_deployment=read)).get_deployment("team-a", "ghost") == []


def test_get_deployment_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str, **kw: object) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_deployment=read)).get_deployment("team-a", "web")
