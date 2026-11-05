from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_GROUP = "gateway.networking.k8s.io"
_VERSION = "v1"


def _client(custom: object, served: tuple[str, str] | None = ("v1", "Namespaced")) -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: served
    return client


def _gateway(name: str, ns: str) -> dict:
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": name,
            "namespace": ns,
            "creationTimestamp": "2026-01-02T03:04:05Z",
        },
        "spec": {
            "gatewayClassName": "istio",
            "listeners": [{"name": "http", "protocol": "HTTP", "port": {"number": 80}}],
        },
    }


def test_list_gateways_in_namespace() -> None:
    """[gateways-list-200] a namespaced Gateway list goes through the VPA
    CRD seam (full custom object, camelCase) and honors the namespace."""
    seen: list[object] = []
    gateway = _gateway("my-gw", "team-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [gateway]},
        )[1],
    )
    result = _client(custom).list_gateways("team-a")
    assert result[0]["metadata"]["name"] == "my-gw"
    assert result[0]["spec"]["gatewayClassName"] == "istio"  # spec intact
    assert seen == [(self_ := _GROUP, _VERSION, "team-a", "gateways")]


def test_list_gateways_crd_absent_is_empty() -> None:
    """[gateways-crd-absent-empty] the CRD read is ``None`` -> ``[]`` (the
    first-class empty state)."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_gateways("team-a") == []
    assert seen == []  # the list call was never made


def test_get_gateway_404_returns_empty_list() -> None:
    """[gateways-get-by-name] a miss is ``[]`` (the 0/1-item contract)."""

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_gateway("team-a", "ghost") == []


def test_get_gateway_hit_returns_one_full_item() -> None:
    """[gateways-get-by-name] a hit is the full custom object."""
    gateway = _gateway("my-gw", "team-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: gateway)
    result = _client(custom).get_gateway("team-a", "my-gw")
    assert result[0]["spec"]["gatewayClassName"] == "istio"  # full object


def test_get_gateway_other_api_error_maps_to_unreachable() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(get_namespaced_custom_object=get)).get_gateway("team-a", "my-gw")


def test_list_http_routes_in_namespace() -> None:
    """[httproutes-list-200] a namespaced HTTPRoute list goes through the VPA
    CRD seam and honors the namespace."""
    seen: list[object] = []
    httproute = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "web", "namespace": "team-a"},
        "spec": {"hostnames": ["app.example.com"], "parentRefs": []},
    }
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [httproute]},
        )[1],
    )
    result = _client(custom).list_http_routes("team-a")
    assert result[0]["metadata"]["name"] == "web"
    assert result[0]["spec"]["hostnames"] == ["app.example.com"]
    assert seen == [(_GROUP, _VERSION, "team-a", "httproutes")]


def test_list_reference_grants_cluster_scoped() -> None:
    """[referencegrants-list-200] a cluster-scoped ReferenceGrant list goes
    through the VPA CRD seam and ignores the namespace."""
    seen: list[object] = []
    grant = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrant",
        "metadata": {"name": "allow"},
        "spec": {"from": [], "to": []},
    }
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [grant]},
        )[1],
    )
    result = _client(custom).list_reference_grants("team-a")
    assert result[0]["metadata"]["name"] == "allow"
    assert seen == [(_GROUP, _VERSION, "referencegrants")]
