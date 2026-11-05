from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _ingress(name: str, ns: str) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": name,
            "namespace": ns,
            "creationTimestamp": "2026-01-02T03:04:05Z",
        },
        "spec": {
            "rules": [
                {
                    "host": "app.example.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "app",
                                        "port": {"number": 80},
                                    }
                                },
                            }
                        ]
                    },
                }
            ],
        },
        "status": {"loadBalancer": {"ingress": []}},
    }


def _client(networking: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._networking = networking
    return client


def test_list_ingresses_in_namespace() -> None:
    """[ingresses-list-200-in-namespace] a namespace is forwarded to
    ``list_namespaced_ingress`` and the FULL object (``to_dict`` snake_case,
    spec + status intact — no stripping) is returned."""
    seen: list[object] = []
    ingress = _ingress("web-ing", "team-a")
    networking = SimpleNamespace(
        list_namespaced_ingress=lambda namespace: (
            seen.append(namespace),
            SimpleNamespace(items=[SimpleNamespace(to_dict=lambda: ingress)]),
        )[1],
    )
    result = _client(networking).list_ingresses("team-a")
    assert result[0]["metadata"]["name"] == "web-ing"
    assert result[0]["spec"]["rules"][0]["host"] == "app.example.com"  # spec intact
    assert result[0]["status"]["loadBalancer"]["ingress"] == []  # status intact
    assert seen == ["team-a"]


def test_list_ingresses_all_namespaces_without_namespace() -> None:
    """[ingresses-list-all-namespaces-without-param] ``None`` uses the
    all-namespaces list call."""
    seen: list[object] = []
    networking = SimpleNamespace(
        list_ingress_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[]),
        )[1],
    )
    assert _client(networking).list_ingresses(None) == []
    assert seen == [True]


def test_list_ingresses_maps_500_to_unreachable() -> None:
    """[ingresses-list-500] a transport ApiException maps to
    ``ClusterUnreachableError`` (502)."""

    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_ingress_for_all_namespaces=list_all)).list_ingresses(None)


def test_get_ingress_hit_returns_one_full_item() -> None:
    """[ingresses-get-by-name] a hit is the full ``to_dict`` object; ``[]`` on a
    miss (the 0/1-item contract)."""
    ingress = _ingress("web-ing", "team-a")

    def read(name: str, namespace: str) -> object:
        return SimpleNamespace(to_dict=lambda: ingress)

    client = _client(SimpleNamespace(read_namespaced_ingress=read))
    result = client.get_ingress("team-a", "web-ing")
    assert result[0]["spec"]["rules"][0]["host"] == "app.example.com"  # full object
    assert result[0]["status"]["loadBalancer"]["ingress"] == []


def test_get_ingress_404_returns_empty_list() -> None:
    """[ingresses-get-by-name] a miss is ``[]``, mirroring ``get_secret``'s
    0/1-item contract."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_namespaced_ingress=read)).get_ingress(
        "team-a", "ghost"
    ) == []


def test_get_ingress_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_ingress=read)).get_ingress("team-a", "web-ing")
