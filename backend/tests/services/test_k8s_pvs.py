from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def _pv(name: str, claim_ns: str | None = None, host_path: bool = False) -> SimpleNamespace:
    spec: dict[str, object] = {"capacity": {"storage": "100Mi"}}
    if claim_ns is not None:
        spec["claim_ref"] = {"name": f"claim-{name}", "namespace": claim_ns}
    if host_path:
        spec["host_path"] = {"path": f"/var/local-path/{name}"}
    return SimpleNamespace(
        to_dict=lambda: {
            "metadata": {"name": name},
            "spec": spec,
            "status": {"phase": "Bound" if claim_ns is not None else "Available"},
        }
    )


def test_list_persistent_volumes_no_namespace_returns_all() -> None:
    """[pvs-no-ns-all] without the namespace param the list is the full
    cluster list, unfiltered (the generic-route contract)."""
    items = [_pv("pv-1", "team-a"), _pv("pv-2", "team-b"), _pv("pv-free")]
    v1 = SimpleNamespace(list_persistent_volume=lambda: SimpleNamespace(items=items))
    result = _client(v1).list_persistent_volumes(None)
    assert [pv["metadata"]["name"] for pv in result] == ["pv-1", "pv-2", "pv-free"]


def test_list_persistent_volumes_claim_namespace_filter() -> None:
    """[pvs-claim-ns-filter] 4.1 parity with its two bugs fixed: a bound
    PV shows only for its claim's namespace; a FREE PV (claim_ref None —
    4.1 crashed on this and returned a partial list) shows for every
    namespace; a hostPath PV (4.1's stray continue skipped it) is kept."""
    items = [
        _pv("pv-a", "team-a"),
        _pv("pv-b", "team-b"),
        _pv("pv-free"),
        _pv("pv-host", "team-a", host_path=True),
    ]
    v1 = SimpleNamespace(list_persistent_volume=lambda: SimpleNamespace(items=items))
    result = _client(v1).list_persistent_volumes("team-a")
    assert [pv["metadata"]["name"] for pv in result] == ["pv-a", "pv-free", "pv-host"]


def test_list_persistent_volumes_missing_spec_treated_as_free() -> None:
    """[pvs-claim-ns-filter] a PV dict without a spec (or claim_ref) is a
    free PV — kept by the filter, never a KeyError."""
    bare = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "pv-bare"}})
    v1 = SimpleNamespace(list_persistent_volume=lambda: SimpleNamespace(items=[bare]))
    result = _client(v1).list_persistent_volumes("team-a")
    assert [pv["metadata"]["name"] for pv in result] == ["pv-bare"]


def test_list_persistent_volumes_maps_500_to_unreachable() -> None:
    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_persistent_volume=list_all)).list_persistent_volumes(None)


def test_get_persistent_volume_hit_returns_one_item() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "pv-1"}})
    v1 = SimpleNamespace(read_persistent_volume=lambda name: item)
    assert _client(v1).get_persistent_volume(None, "pv-1") == [{"metadata": {"name": "pv-1"}}]


def test_get_persistent_volume_404_returns_empty_list() -> None:
    """[pvs-get-by-name] a miss is ``[]``, mirroring
    ``get_storage_class``'s 0/1-item contract."""

    def read(_name: str) -> None:
        raise ApiException(status=404)

    assert _client(SimpleNamespace(read_persistent_volume=read)).get_persistent_volume(None, "gone") == []


def test_get_persistent_volume_ignores_namespace() -> None:
    """cluster-scoped: the namespace is accepted and ignored (the
    ``get_storage_class`` pattern)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "pv-1"}})
    v1 = SimpleNamespace(read_persistent_volume=lambda name: (seen.append(name), item)[1])
    _client(v1).get_persistent_volume("team-a", "pv-1")  # ns ignored
    assert seen == ["pv-1"]


def test_get_persistent_volume_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_persistent_volume=read)).get_persistent_volume(None, "pv-1")
