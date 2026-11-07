from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_services_namespaced_keeps_spec_status() -> None:
    """[services-list-200] the namespaced branch uses
    ``list_namespaced_service`` and, UNLIKE ``list_secrets``, does NOT
    strip any field — the data page's Ports/Pods tabs and the list's
    External IP cell read ``spec``/``status`` from the full ``to_dict``."""
    seen: list[str] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "web-svc", "namespace": "team-a",
                         "creation_timestamp": "2026-01-02T03:04:05Z",
                         "resource_version": "4242",
                         "labels": {"app": "web"}},
            "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                     "selector": {"app": "web"},
                     "ports": [{"name": "http", "port": 80,
                                "target_port": 8080, "protocol": "TCP"}]},
            "status": {"load_balancer": {"ingress": [{"ip": "203.0.113.5"}]}},
        }
    )
    v1 = SimpleNamespace(
        list_namespaced_service=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1]
    )
    result = _client(v1).list_services("team-a")
    assert result[0]["metadata"]["name"] == "web-svc"
    assert result[0]["spec"]["cluster_ip"] == "10.0.0.1"
    assert result[0]["status"]["load_balancer"]["ingress"][0]["ip"] == "203.0.113.5"
    assert seen == ["team-a"]


def test_list_services_all_namespaces_when_namespace_none() -> None:
    """[services-list-all-namespaces] ``None`` uses the all-namespaces
    call (the ``list_secrets`` branch)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-svc"}})
    v1 = SimpleNamespace(
        list_service_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[item]),
        )[1]
    )
    result = _client(v1).list_services(None)
    assert result[0]["metadata"]["name"] == "web-svc"
    assert seen == [True]


def test_list_services_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_service=list_all)).list_services("team-a")


def test_get_service_404_returns_empty_list() -> None:
    """[services-get-by-name] a miss is ``[]`` (the ``get_secret``
    contract)."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_namespaced_service=read)) \
        .get_service("team-a", "ghost") == []


def test_get_service_hit_returns_one_item_with_spec() -> None:
    item = SimpleNamespace(to_dict=lambda: {
        "metadata": {"name": "web-svc"},
        "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                 "selector": {"app": "web"}},
    })
    v1 = SimpleNamespace(read_namespaced_service=lambda name, ns: item)
    assert _client(v1).get_service("team-a", "web-svc") == [
        {"metadata": {"name": "web-svc"},
         "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                  "selector": {"app": "web"}}}
    ]


def test_get_service_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_service=read)) \
            .get_service("team-a", "web-svc")
