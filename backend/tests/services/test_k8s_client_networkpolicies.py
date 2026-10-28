from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(networking: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._networking = networking
    return client


def test_list_network_policies_namespaced_hits_namespaced_api() -> None:
    """[networkpolicies-list-namespaced] the namespaced list hits the
    namespaced NetworkingV1Api method with the query namespace."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "deny-all"}})

    def list_namespaced(ns: str) -> SimpleNamespace:
        seen.append(ns)
        return SimpleNamespace(items=[item])

    networking = SimpleNamespace(
        list_namespaced_network_policy=list_namespaced,
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[]),
    )
    result = _client(networking).list_network_policies("team-a")
    assert result == [{"metadata": {"name": "deny-all"}}]
    assert seen == ["team-a"]


def test_list_network_policies_no_namespace_lists_all() -> None:
    """[networkpolicies-list-all-namespaces] no namespace query takes the
    all-namespaces branch; the namespaced method is never called."""
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "np"}})

    def never_called(_ns: str) -> object:
        raise AssertionError("must not be called")

    networking = SimpleNamespace(
        list_namespaced_network_policy=never_called,
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[item]),
    )
    result = _client(networking).list_network_policies(None)
    assert result == [{"metadata": {"name": "np"}}]


def test_get_network_policy_404_returns_empty_list() -> None:
    """[networkpolicies-get-by-name] a missing policy is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=404)

    networking = SimpleNamespace(read_namespaced_network_policy=read)
    assert _client(networking).get_network_policy("team-a", "gone") == []


def test_get_network_policy_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=500)

    client = _client(SimpleNamespace(read_namespaced_network_policy=read))
    with pytest.raises(ClusterUnreachableError):
        client.get_network_policy("team-a", "np")


def test_list_network_policies_maps_500_to_unreachable() -> None:
    def list_namespaced(_ns: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_network_policy=list_namespaced)).list_network_policies("team-a")
