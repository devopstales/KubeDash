from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_VERSION = "v1"


def _client(custom: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    # The CRD is present and served, cluster-scoped (the absent case is
    # tested separately).
    client.get_crd_served = lambda group, plural: (_VERSION, "Cluster")
    return client


def _sc(name: str) -> dict:
    return {
        "apiVersion": "snapshot.storage.k8s.io/v1",
        "kind": "VolumeSnapshotClass",
        "metadata": {
            "name": name,
            "creationTimestamp": "2026-01-02T03:04:05Z",
            "annotations": {"snapshot.storage.kubernetes.io/is-default-class": "true"},
            "labels": {"team": "a"},
        },
        "driver": "csi-driver.example.com",
        "deletionPolicy": "Delete",
        "parameters": {"blockVolume": "true", "fstype": "ext4"},
    }


def test_list_volume_snapshot_classes_ignores_namespace_full_object() -> None:
    """[volumesnapshotclasses-list-200] cluster-scoped: a namespace argument
    is accepted-and-ignored; the read always goes through
    ``list_cluster_custom_object`` and the FULL custom object (driver /
    deletionPolicy / parameters intact, camelCase) is returned (the Cilium
    cluster-scoped seam — NOT the lossy ``list_crd_instances`` projection)."""
    seen: list[object] = []
    sc = _sc("csi-default")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [sc]},
        )[1],
    )
    result = _client(custom).list_volume_snapshot_classes("team-a")  # ns ignored
    assert result[0]["metadata"]["name"] == "csi-default"
    assert result[0]["driver"] == "csi-driver.example.com"  # intact
    assert result[0]["deletionPolicy"] == "Delete"  # intact
    assert result[0]["parameters"] == {"blockVolume": "true", "fstype": "ext4"}  # intact
    assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshotclasses")]


def test_list_volume_snapshot_classes_crd_absent_is_empty() -> None:
    """[volumesnapshotclasses-crd-absent-is-empty] the CRD read is ``None``
    (snapshot operator not installed) -> ``[]`` (the Cilium absent
    contract), and the custom-object list is never called."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_volume_snapshot_classes("team-a") == []
    assert seen == []  # the list call was never made


def test_get_volume_snapshot_class_404_returns_empty_list() -> None:
    """[volumesnapshotclasses-get-by-name] a miss is ``[]``, mirroring
    ``get_cilium_network_policy``'s 0/1-item contract."""

    def get(group, version, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_cluster_custom_object=get)
    assert _client(custom).get_volume_snapshot_class("team-a", "ghost") == []


def test_get_volume_snapshot_class_hit_returns_one_full_item() -> None:
    sc = _sc("csi-default")
    custom = SimpleNamespace(get_cluster_custom_object=lambda *a, **k: sc)
    result = _client(custom).get_volume_snapshot_class("team-a", "csi-default")
    assert result[0]["driver"] == "csi-driver.example.com"  # full object
    assert result[0]["deletionPolicy"] == "Delete"
    assert result[0]["parameters"] == {"blockVolume": "true", "fstype": "ext4"}


def test_get_volume_snapshot_class_ignores_namespace() -> None:
    """[volumesnapshotclasses-get-ignores-namespace] cluster-scoped: the
    namespace argument is accepted-and-ignored; the read always goes through
    ``get_cluster_custom_object`` (the ``get_crd`` cluster-scoped pattern)."""
    seen: list[object] = []
    sc = _sc("csi-default")
    custom = SimpleNamespace(
        get_cluster_custom_object=lambda group, version, plural, name: (
            seen.append((group, version, plural, name)),
            sc,
        )[1],
    )
    result = _client(custom).get_volume_snapshot_class("team-a", "csi-default")  # ns ignored
    assert result[0]["metadata"]["name"] == "csi-default"
    assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshotclasses", "csi-default")]


def test_get_volume_snapshot_class_other_api_error_maps_to_unreachable() -> None:
    def get(group, version, plural, name):
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(get_cluster_custom_object=get)).get_volume_snapshot_class(
            "team-a", "csi-default"
        )
