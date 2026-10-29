from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(autoscaling: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._autoscaling = autoscaling
    return client


def test_list_horizontal_pod_autoscalers_in_namespace() -> None:
    """[horizontalpodautoscalers-list-200-in-namespace] a namespace is
    forwarded to ``list_namespaced_horizontal_pod_autoscaler`` (the
    ``list_network_policies`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web-hpa", "namespace": "team-a"},
            "spec": {
                "max_replicas": 10,
                "min_replicas": 2,
                "scale_target_ref": {"kind": "Deployment", "name": "web"},
            },
            "status": {
                "current_replicas": 3,
                "current_cpu_utilization_percentage": 50,
            },
        }
    )
    autoscaling = SimpleNamespace(
        list_namespaced_horizontal_pod_autoscaler=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(autoscaling).list_horizontal_pod_autoscalers("team-a")
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_horizontal_pod_autoscalers_all_namespaces_without_namespace() -> None:
    """[horizontalpodautoscalers-list-all-namespaces-without-param]
    ``None`` uses the all-namespaces call (the ``list_secrets`` branch)."""
    seen: list[object] = []
    autoscaling = SimpleNamespace(
        list_horizontal_pod_autoscaler_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(autoscaling).list_horizontal_pod_autoscalers(None) == []
    assert seen == [True]


def test_list_horizontal_pod_autoscalers_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_horizontal_pod_autoscaler=list_all)).list_horizontal_pod_autoscalers(
            "team-a"
        )


def test_get_horizontal_pod_autoscaler_404_returns_empty_list() -> None:
    """[horizontalpodautoscalers-get-by-name] a miss is ``[]``, mirroring
    ``get_network_policy``'s 0/1-item contract."""
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    autoscaling = SimpleNamespace(read_namespaced_horizontal_pod_autoscaler=read)
    assert _client(autoscaling).get_horizontal_pod_autoscaler("team-a", "ghost") == []


def test_get_horizontal_pod_autoscaler_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-hpa"}})
    autoscaling = SimpleNamespace(
        read_namespaced_horizontal_pod_autoscaler=lambda name, namespace: item
    )
    assert _client(autoscaling).get_horizontal_pod_autoscaler("team-a", "web-hpa") == [
        {"metadata": {"name": "web-hpa"}}
    ]


def test_get_horizontal_pod_autoscaler_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_horizontal_pod_autoscaler=read)).get_horizontal_pod_autoscaler(
            "team-a", "web-hpa"
        )
