from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_get_pod_hit_returns_one_item() -> None:
    """[pods-get-by-name] a hit is the single full object in a 0/1-item
    list (the generic resource route's ``items`` contract)."""
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web-1", "namespace": "team-a"},
            "spec": {"node_name": "node-1"},
            "status": {"phase": "Running", "pod_ip": "10.0.0.5"},
        }
    )
    seen: list[tuple[str, str]] = []
    v1 = SimpleNamespace(
        read_namespaced_pod=lambda name, namespace, **kw: (
            seen.append((name, namespace)), item
        )[1]
    )
    assert _client(v1).get_pod("team-a", "web-1") == [
        {
            "metadata": {"name": "web-1", "namespace": "team-a"},
            "spec": {"node_name": "node-1"},
            "status": {"phase": "Running", "pod_ip": "10.0.0.5"},
        }
    ]
    assert seen == [("web-1", "team-a")]


def test_get_pod_404_returns_empty_list() -> None:
    """[pods-get-by-name] a miss is ``[]`` (the data page renders a
    not-found state, never an API error)."""

    def read(name: str, namespace: str, **kw: object) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_namespaced_pod=read)).get_pod("team-a", "ghost") == []


def test_get_pod_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str, **kw: object) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_pod=read)).get_pod("team-a", "web-1")


def test_list_pods_forwards_label_selector() -> None:
    """[pods-labelselector-filters] the ``label_selector`` is passed
    through to ``list_namespaced_pod`` (4.1's ``k8sPodSelectorListGet``
    behavior, re-implemented as a pass-through param)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
    v1 = SimpleNamespace(
        list_namespaced_pod=lambda ns, label_selector=None: (
            seen.append(label_selector), SimpleNamespace(items=[item]))[1]
    )
    result = _client(v1).list_pods("team-a", label_selector="app=web")
    assert result[0]["metadata"]["name"] == "web-abc"
    assert seen == ["app=web"]


def test_list_pods_no_label_selector_unchanged() -> None:
    """[pods-labelselector-absent-unchanged] without a ``label_selector``
    the call is the existing unfiltered list (``label_selector=None``)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
    v1 = SimpleNamespace(
        list_namespaced_pod=lambda ns, label_selector=None: (
            seen.append(label_selector), SimpleNamespace(items=[item]))[1]
    )
    _client(v1).list_pods("team-a")
    assert seen == [None]
