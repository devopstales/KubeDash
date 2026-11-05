from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_VERSION = "v1"


def _client(custom: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    # The Gateway API CRDs are present and served (the absent case is tested
    # separately).
    client.get_crd_served = lambda group, plural: (_VERSION, "Cluster")
    return client


def _gateway_class(name: str) -> dict:
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayClass",
        "metadata": {
            "name": name,
            "creationTimestamp": "2026-01-02T03:04:05Z",
        },
        "spec": {"controllerName": "istio"},
    }


def test_list_gateway_classes_cluster_scoped() -> None:
    """[gatewayclasses-list-200] the GatewayClass list goes through the VPA
    CRD seam (full custom object, camelCase) and ignores the namespace arg."""
    seen: list[object] = []
    gateway_class = _gateway_class("istio")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [gateway_class]},
        )[1],
    )
    result = _client(custom).list_gateway_classes("team-a")
    assert result[0]["metadata"]["name"] == "istio"
    assert result[0]["spec"]["controllerName"] == "istio"  # spec intact
    assert seen == [("gateway.networking.k8s.io", _VERSION, "gatewayclasses")]


def test_list_gateway_classes_crd_absent_is_empty() -> None:
    """[gatewayclasses-crd-absent-empty] the CRD read is ``None`` (the Gateway
    API CRDs are optional) -> ``[]`` (the first-class empty state)."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_gateway_classes("team-a") == []
    assert seen == []  # the list call was never made


def test_get_gateway_class_404_returns_empty_list() -> None:
    """[gatewayclasses-get-by-name] a miss is ``[]``, mirroring the VPA
    0/1-item contract."""

    def get(group, version, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_cluster_custom_object=get)
    assert _client(custom).get_gateway_class("team-a", "ghost") == []


def test_get_gateway_class_hit_returns_one_full_item() -> None:
    gateway_class = _gateway_class("istio")
    custom = SimpleNamespace(get_cluster_custom_object=lambda *a, **k: gateway_class)
    result = _client(custom).get_gateway_class("team-a", "istio")
    assert result[0]["spec"]["controllerName"] == "istio"  # full object


def test_get_gateway_class_other_api_error_maps_to_unreachable() -> None:
    def get(group, version, plural, name):
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(get_cluster_custom_object=get)).get_gateway_class(
            "team-a", "istio"
        )


def test_list_ingress_classes_ignore_namespace() -> None:
    """[ingressclasses-list-ignores-namespace] cluster-scoped: the namespace
    argument is accepted and ignored (the ``list_runtime_classes`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "nginx"},
            "spec": {"controller": "nginx"},
        }
    )
    networking = SimpleNamespace(
        list_ingress_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
    )
    client = object.__new__(K8sClient)
    client._networking = networking
    result = client.list_ingress_classes("team-a")
    assert result == [{"metadata": {"name": "nginx"}, "spec": {"controller": "nginx"}}]
    assert seen == [True]  # called once, cluster list


def test_get_ingress_class_404_returns_empty_list() -> None:
    """[ingressclasses-get-by-name] a miss is ``[]``, mirroring the
    ``get_runtime_class`` 0/1-item contract."""

    def read(name: str) -> None:
        raise ApiException(status=404)

    networking = SimpleNamespace(read_ingress_class=read)
    client = object.__new__(K8sClient)
    client._networking = networking
    assert client.get_ingress_class(None, "gone") == []


def test_get_ingress_class_other_api_error_maps_to_unreachable() -> None:
    def read(name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        client = object.__new__(K8sClient)
        client._networking = SimpleNamespace(read_ingress_class=read)
        client.get_ingress_class(None, "nginx")
