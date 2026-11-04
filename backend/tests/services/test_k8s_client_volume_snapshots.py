from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_VERSION = "v1"


def _client(custom: object, scope: str = "Namespaced") -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    # The CRD is present and served (the absent case is tested separately).
    client.get_crd_served = lambda group, plural: (_VERSION, scope)
    return client


def _vs(name: str, namespace: str = "team-a") -> dict:
    return {
        "apiVersion": "snapshot.storage.k8s.io/v1",
        "kind": "VolumeSnapshot",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "creationTimestamp": "2026-01-02T03:04:05Z",
            "labels": {"team": "a"},
        },
        "spec": {
            "source": {"persistentVolumeClaimName": f"pvc-{name}"},
            "volumeSnapshotClassName": "csi-snap",
        },
        "status": {
            "readyToUse": True,
            "restoreSize": "1Gi",
            "boundVolumeSnapshotContentName": f"content-{name}",
            "creationTime": "2026-01-02T03:05:00Z",
        },
    }


def test_list_volume_snapshots_honors_namespace() -> None:
    """[volumesnapshots-list-200-in-namespace] the namespace is forwarded
    to ``list_namespaced_custom_object`` (the VPA namespaced-CRD pattern)
    and the FULL object (spec + status intact, camelCase) is returned (the
    Cilium pattern)."""
    seen: list[object] = []
    vs = _vs("snap-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [vs]},
        )[1],
    )
    result = _client(custom).list_volume_snapshots("team-a")
    assert result[0]["metadata"]["name"] == "snap-a"
    assert result[0]["spec"]["source"]["persistentVolumeClaimName"] == "pvc-snap-a"  # full object intact
    assert result[0]["status"]["readyToUse"] is True
    assert (
        result[0]["status"]["boundVolumeSnapshotContentName"] == "content-snap-a"
    )  # status intact
    assert seen == [("snapshot.storage.k8s.io", _VERSION, "team-a", "volumesnapshots")]


def test_list_volume_snapshots_all_namespaces_without_namespace() -> None:
    """[volumesnapshots-list-all-namespaces-without-param] no namespace ->
    ``list_cluster_custom_object`` (the all-namespaces branch; the page
    always sends a namespace, the API branch exists for other consumers)."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": []},
        )[1],
    )
    assert _client(custom).list_volume_snapshots(None) == []
    assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshots")]


def test_list_volume_snapshots_crd_absent_is_empty() -> None:
    """[volumesnapshots-crd-absent-is-empty] the CRD read is ``None``
    (snapshot operator not installed) -> ``[]`` (the Cilium absent
    contract), and the custom-object list is never called."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_volume_snapshots("team-a") == []
    assert seen == []  # the list call was never made


def test_list_volume_snapshots_cluster_scoped_revision_ignores_namespace() -> None:
    """A future cluster-scoped CRD revision: a namespace is accepted and
    ignored (the ``list_cluster_custom_object`` branch, mirroring
    ``list_crds`` / the SnapshotClass pair)."""
    seen: list[object] = []
    vs = _vs("snap-a")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [vs]},
        )[1],
    )
    result = _client(custom, scope="Cluster").list_volume_snapshots("team-a")
    assert result[0]["metadata"]["name"] == "snap-a"
    assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshots")]


def test_get_volume_snapshot_404_returns_empty_list() -> None:
    """[volumesnapshots-get-by-name] a miss is ``[]``, mirroring the
    namespaced getter's 0/1-item contract."""

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_volume_snapshot("team-a", "ghost") == []


def test_get_volume_snapshot_hit_returns_one_full_item() -> None:
    vs = _vs("snap-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: vs)
    result = _client(custom).get_volume_snapshot("team-a", "snap-a")
    assert result[0]["status"]["boundVolumeSnapshotContentName"] == "content-snap-a"  # full object


def test_get_volume_snapshot_other_api_error_maps_to_unreachable() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(get_namespaced_custom_object=get)).get_volume_snapshot(
            "team-a", "snap-a"
        )
