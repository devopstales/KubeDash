from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(policy: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._policy = policy
    return client


def test_list_pod_disruption_budgets_in_namespace() -> None:
    """[poddisruptionbudgets-list-200-in-namespace] a namespace is
    forwarded to ``list_namespaced_pod_disruption_budget`` (the
    ``list_secrets`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web", "namespace": "team-a"},
            "spec": {"min_available": 3, "selector": {"match_labels": {"app": "web"}}},
            "status": {"disruptions_allowed": 1, "current_healthy": 4},
        }
    )
    policy = SimpleNamespace(
        list_namespaced_pod_disruption_budget=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(policy).list_pod_disruption_budgets("team-a")
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_pod_disruption_budgets_all_namespaces_without_namespace() -> None:
    """[poddisruptionbudgets-list-all-namespaces-without-param] ``None``
    uses the all-namespaces call (the ``list_secrets`` branch)."""
    seen: list[object] = []
    policy = SimpleNamespace(
        list_pod_disruption_budget_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(policy).list_pod_disruption_budgets(None) == []
    assert seen == [True]


def test_list_pod_disruption_budgets_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(
            SimpleNamespace(list_namespaced_pod_disruption_budget=list_all)
        ).list_pod_disruption_budgets("team-a")


def test_get_pod_disruption_budget_404_returns_empty_list() -> None:
    """[poddisruptionbudgets-get-by-name] a miss is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    policy = SimpleNamespace(read_namespaced_pod_disruption_budget=read)
    assert _client(policy).get_pod_disruption_budget("team-a", "ghost") == []


def test_get_pod_disruption_budget_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web"}})
    policy = SimpleNamespace(read_namespaced_pod_disruption_budget=lambda name, namespace: item)
    assert _client(policy).get_pod_disruption_budget("team-a", "web") == [
        {"metadata": {"name": "web"}}
    ]


def test_get_pod_disruption_budget_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(
            SimpleNamespace(read_namespaced_pod_disruption_budget=read)
        ).get_pod_disruption_budget("team-a", "web")
