"""External-LB CRD kinds (MetalLB primary / Cilium fallback) —
service-tier provider-detection tests: MetalLB present -> the namespaced
metallb.io read tagged ``provider: "metallb"``; MetalLB absent + Cilium
present -> the cluster-scoped cilium.io read tagged ``provider: "cilium"``;
both absent -> ``[]`` (and bgpadvertisements is MetalLB-ONLY — no Cilium
branch). Getter 404 -> ``[]``; full custom-object shape."""
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_METALLB_VERSION = "v1beta1"
_CILIUM_VERSION = "v2"


def _client(served: dict[tuple[str, str], tuple[str, str] | None], custom: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: served.get((group, plural))
    return client


def _mlb_ip_pool(name: str) -> dict:
    return {
        "apiVersion": "metallb.io/v1beta1",
        "kind": "IPAddressPool",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"addresses": ["192.168.100.10-192.168.100.20"]},
    }


def _cilium_ip_pool(name: str) -> dict:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumLoadBalancerIPPool",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"cidr": "192.168.100.10/29"},
    }


def _mlb_l2(name: str) -> dict:
    return {
        "apiVersion": "metallb.io/v1beta1",
        "kind": "L2Advertisement",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"interfaces": [{"name": "eth1"}]},
    }


def _cilium_l2(name: str) -> dict:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumL2AnnouncementPolicy",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"interfaces": ["eth1"]},
    }


def _mlb_bgp(name: str) -> dict:
    return {
        "apiVersion": "metallb.io/v1beta1",
        "kind": "BGPPeer",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"myASN": 65000, "peerASN": 65001, "peerAddress": "10.0.0.1"},
    }


def _cilium_bgp(name: str) -> dict:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumBGPPeeringPolicy",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"nodeSelection": {}, "virtualRouters": []},
    }


def _mlb_bgp_adv(name: str) -> dict:
    return {
        "apiVersion": "metallb.io/v1beta2",
        "kind": "BGPAdvertisement",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"aggregationBit": 2, "clusterIPs": []},
    }


def test_list_ipaddresspools_metallb_present() -> None:
    """[exlb-ipaddresspools-list-200-provider-detect] MetalLB present -> the
    namespaced metallb.io read with the CRD's own served version, and every
    item is tagged ``provider: "metallb"``."""
    served = {("metallb.io", "ipaddresspools"): (_METALLB_VERSION, "Cluster")}
    seen: list[object] = []
    pool = _mlb_ip_pool("team-a-pool")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [pool]},
        )[1]
    )
    result = _client(served, custom).list_ipaddresspools("team-a")
    [item] = result
    assert item["metadata"]["name"] == "team-a-pool"
    assert item["spec"]["addresses"] == ["192.168.100.10-192.168.100.20"]
    assert item["provider"] == "metallb"
    assert seen == [("metallb.io", _METALLB_VERSION, "team-a", "ipaddresspools")]


def test_list_ipaddresspools_cilium_fallback() -> None:
    """[exlb-provider-fallback-cilium] MetalLB absent + Cilium present -> the
    CLUSTER-scoped cilium.io read (ciliumloadbalancerippools), every item
    tagged ``provider: "cilium"``."""
    served = {
        ("metallb.io", "ipaddresspools"): None,
        ("cilium.io", "ciliumloadbalancerippools"): (_CILIUM_VERSION, "Cluster"),
    }
    seen: list[object] = []
    pool = _cilium_ip_pool("cilium-pool")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [pool]},
        )[1]
    )
    result = _client(served, custom).list_ipaddresspools("team-a")
    [item] = result
    assert item["metadata"]["name"] == "cilium-pool"
    assert item["spec"]["cidr"] == "192.168.100.10/29"
    assert item["provider"] == "cilium"
    assert seen == [("cilium.io", _CILIUM_VERSION, "ciliumloadbalancerippools")]


def test_list_ipaddresspools_both_absent_empty() -> None:
    """[exlb-provider-absent-empty] both providers absent -> [] (the custom
    read is never made)."""
    served = {
        ("metallb.io", "ipaddresspools"): None,
        ("cilium.io", "ciliumloadbalancerippools"): None,
    }
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
    )
    assert _client(served, custom).list_ipaddresspools("team-a") == []
    assert seen == []


def test_list_ipaddresspools_metallb_500_maps_to_unreachable() -> None:
    served = {("metallb.io", "ipaddresspools"): (_METALLB_VERSION, "Cluster")}

    def list_ns(group, version, namespace, plural) -> None:
        raise ApiException(status=500)

    custom = SimpleNamespace(list_namespaced_custom_object=list_ns)
    with pytest.raises(ClusterUnreachableError):
        _client(served, custom).list_ipaddresspools("team-a")


def test_get_ipaddresspool_metallb_hit() -> None:
    served = {("metallb.io", "ipaddresspools"): (_METALLB_VERSION, "Cluster")}
    pool = _mlb_ip_pool("team-a-pool")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: pool)
    [item] = _client(served, custom).get_ipaddresspool("team-a", "team-a-pool")
    assert item["provider"] == "metallb"
    assert item["spec"]["addresses"] == ["192.168.100.10-192.168.100.20"]


def test_get_ipaddresspool_cilium_fallback_hit() -> None:
    served = {
        ("metallb.io", "ipaddresspools"): None,
        ("cilium.io", "ciliumloadbalancerippools"): (_CILIUM_VERSION, "Cluster"),
    }
    pool = _cilium_ip_pool("cilium-pool")
    custom = SimpleNamespace(get_cluster_custom_object=lambda *a, **k: pool)
    [item] = _client(served, custom).get_ipaddresspool("team-a", "cilium-pool")
    assert item["provider"] == "cilium"
    assert item["spec"]["cidr"] == "192.168.100.10/29"


def test_get_ipaddresspool_404_returns_empty_list() -> None:
    served = {("metallb.io", "ipaddresspools"): (_METALLB_VERSION, "Cluster")}

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(served, custom).get_ipaddresspool("team-a", "ghost") == []


def test_list_l2advertisements_metallb_present() -> None:
    served = {("metallb.io", "l2advertisements"): (_METALLB_VERSION, "Cluster")}
    seen: list[object] = []
    l2 = _mlb_l2("team-a-l2")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [l2]},
        )[1]
    )
    result = _client(served, custom).list_l2advertisements("team-a")
    [item] = result
    assert item["provider"] == "metallb"
    assert item["spec"]["interfaces"] == [{"name": "eth1"}]
    assert seen == [("metallb.io", _METALLB_VERSION, "team-a", "l2advertisements")]


def test_list_l2advertisements_cilium_fallback() -> None:
    served = {
        ("metallb.io", "l2advertisements"): None,
        ("cilium.io", "ciliuml2announcementpolicies"): (_CILIUM_VERSION, "Cluster"),
    }
    seen: list[object] = []
    l2 = _cilium_l2("cilium-l2")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [l2]},
        )[1]
    )
    result = _client(served, custom).list_l2advertisements("team-a")
    [item] = result
    assert item["provider"] == "cilium"
    assert seen == [("cilium.io", _CILIUM_VERSION, "ciliuml2announcementpolicies")]


def test_list_l2advertisements_both_absent_empty() -> None:
    served = {
        ("metallb.io", "l2advertisements"): None,
        ("cilium.io", "ciliuml2announcementpolicies"): None,
    }
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
    )
    assert _client(served, custom).list_l2advertisements("team-a") == []
    assert seen == []


def test_get_l2advertisement_404_returns_empty_list() -> None:
    served = {("metallb.io", "l2advertisements"): (_METALLB_VERSION, "Cluster")}

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(served, custom).get_l2advertisement("team-a", "ghost") == []


def test_list_bgppeers_metallb_present() -> None:
    served = {("metallb.io", "bgppeers"): (_METALLB_VERSION, "Cluster")}
    seen: list[object] = []
    bgp = _mlb_bgp("team-a-peer")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [bgp]},
        )[1]
    )
    result = _client(served, custom).list_bgppeers("team-a")
    [item] = result
    assert item["provider"] == "metallb"
    assert item["spec"]["peerASN"] == 65001
    assert seen == [("metallb.io", _METALLB_VERSION, "team-a", "bgppeers")]


def test_list_bgppeers_cilium_fallback() -> None:
    served = {
        ("metallb.io", "bgppeers"): None,
        ("cilium.io", "ciliumbgppeeringpolicies"): (_CILIUM_VERSION, "Cluster"),
    }
    seen: list[object] = []
    bgp = _cilium_bgp("cilium-bgp")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [bgp]},
        )[1]
    )
    result = _client(served, custom).list_bgppeers("team-a")
    [item] = result
    assert item["provider"] == "cilium"
    assert seen == [("cilium.io", _CILIUM_VERSION, "ciliumbgppeeringpolicies")]


def test_list_bgppeers_both_absent_empty() -> None:
    served = {
        ("metallb.io", "bgppeers"): None,
        ("cilium.io", "ciliumbgppeeringpolicies"): None,
    }
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
    )
    assert _client(served, custom).list_bgppeers("team-a") == []
    assert seen == []


def test_get_bgppeer_404_returns_empty_list() -> None:
    served = {("metallb.io", "bgppeers"): (_METALLB_VERSION, "Cluster")}

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(served, custom).get_bgppeer("team-a", "ghost") == []


def test_list_bgpadvertisements_metallb_present() -> None:
    served = {("metallb.io", "bgpadvertisements"): (_METALLB_VERSION, "Cluster")}
    seen: list[object] = []
    adv = _mlb_bgp_adv("team-a-adv")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [adv]},
        )[1]
    )
    result = _client(served, custom).list_bgpadvertisements("team-a")
    [item] = result
    assert item["provider"] == "metallb"
    assert item["spec"]["aggregationBit"] == 2
    assert seen == [("metallb.io", _METALLB_VERSION, "team-a", "bgpadvertisements")]


def test_list_bgpadvertisements_metallb_absent_empty() -> None:
    """[exlb-bgpadvertisements-metallb-only] MetalLB absent -> [] even with
    Cilium present (NO Cilium branch for this kind — the cluster read is
    never made)."""
    served = {
        ("metallb.io", "bgpadvertisements"): None,
        ("cilium.io", "ciliumbgppeeringpolicies"): (_CILIUM_VERSION, "Cluster"),
    }
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
    )
    assert _client(served, custom).list_bgpadvertisements("team-a") == []
    assert seen == []


def test_get_bgpadvertisement_metallb_hit() -> None:
    served = {("metallb.io", "bgpadvertisements"): (_METALLB_VERSION, "Cluster")}
    adv = _mlb_bgp_adv("team-a-adv")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: adv)
    [item] = _client(served, custom).get_bgpadvertisement("team-a", "team-a-adv")
    assert item["provider"] == "metallb"
    assert item["spec"]["aggregationBit"] == 2


def test_get_bgpadvertisement_404_returns_empty_list() -> None:
    served = {("metallb.io", "bgpadvertisements"): (_METALLB_VERSION, "Cluster")}

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(served, custom).get_bgpadvertisement("team-a", "ghost") == []
