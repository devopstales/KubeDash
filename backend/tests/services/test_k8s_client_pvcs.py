from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_pvc_namespaced() -> None:
    """[pvcs-list-200] the namespaced branch uses
    ``list_namespaced_persistent_volume_claim`` (the ``list_secrets``
    pattern)."""
    seen: list[str] = []
    item = SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": "data-pvc", "namespace": "team-a",
                         "creation_timestamp": "2026-01-02T03:04:05Z"},
            "spec": {"storage_class_name": "csi-fast", "volume_name": "pv-1",
                     "access_modes": ["ReadWriteOnce"], "volume_mode": "Filesystem"},
            "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
        }
    )
    v1 = SimpleNamespace(
        list_namespaced_persistent_volume_claim=lambda ns: (
            seen.append(ns),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(v1).list_persistent_volume_claims("team-a")
    assert result[0]["metadata"]["name"] == "data-pvc"
    assert result[0]["status"]["phase"] == "Bound"
    assert seen == ["team-a"]  # the namespace is forwarded, not dropped


def test_list_pvc_all_namespaces_when_namespace_none() -> None:
    """[pvcs-list-all-namespaces] ``None`` uses the all-namespaces call
    (the ``list_secrets`` branch)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "data-pvc"}})
    v1 = SimpleNamespace(
        list_persistent_volume_claim_for_all_namespaces=lambda: (
            seen.append(True),
            SimpleNamespace(items=[item]),
        )[1],
    )
    result = _client(v1).list_persistent_volume_claims(None)
    assert result[0]["metadata"]["name"] == "data-pvc"
    assert seen == [True]


def test_list_pvc_maps_500_to_unreachable() -> None:
    def list_all(namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(
            SimpleNamespace(list_namespaced_persistent_volume_claim=list_all)
        ).list_persistent_volume_claims("team-a")


def test_get_pvc_404_returns_empty_list() -> None:
    """[pvcs-get-by-name] a miss is ``[]`` (the ``get_resource_quota``
    contract)."""

    def read(name: str, namespace: str) -> None:
        raise ApiException(status=404)

    assert (
        _client(SimpleNamespace(read_namespaced_persistent_volume_claim=read))
        .get_persistent_volume_claim("team-a", "ghost")
        == []
    )


def test_get_pvc_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "data-pvc"}})
    v1 = SimpleNamespace(read_namespaced_persistent_volume_claim=lambda name, ns: item)
    assert _client(v1).get_persistent_volume_claim("team-a", "data-pvc") == [
        {"metadata": {"name": "data-pvc"}}
    ]


def test_get_pvc_other_api_error_maps_to_unreachable() -> None:
    def read(name: str, namespace: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(
            SimpleNamespace(read_namespaced_persistent_volume_claim=read)
        ).get_persistent_volume_claim("team-a", "data-pvc")


