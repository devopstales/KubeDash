import json
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


# --- pvc_usage: the kubelet /stats/summary aggregation (4.1 k8sPVCMetric) ---

_STATS_A = json.dumps(
    {
        "pods": [
            {
                "volume": [
                    {
                        "pvcRef": {"name": "data-pvc", "namespace": "team-a"},
                        "capacityBytes": "1000",
                        "usedBytes": "400",
                        "availableBytes": "600",
                    },
                    {
                        "pvcRef": {"name": "data-pvc", "namespace": "team-a"},
                        "capacityBytes": "1000",
                        "usedBytes": "100",
                        "availableBytes": "900",
                    },
                ]
            },
            {
                "volume": [
                    {
                        "pvcRef": {"name": "other-ns-pvc", "namespace": "kube-system"},
                        "capacityBytes": "500",
                        "usedBytes": "1",
                        "availableBytes": "499",
                    }
                ]
            },
        ]
    }
)


def _stats_client(stats_by_node: dict[str, object]) -> K8sClient:
    def proxy(name, path=None, **kwargs):
        return stats_by_node[name]

    client = object.__new__(K8sClient)
    client._v1 = SimpleNamespace(
        list_node=lambda: SimpleNamespace(
            items=[
                SimpleNamespace(to_dict=lambda n=n: {"metadata": {"name": n}})
                for n in stats_by_node
            ]
        ),
        connect_get_node_proxy_with_path=proxy,
    )
    return client


def test_pvc_usage_aggregates_per_pvc_in_namespace() -> None:
    """[pvc-usage-happy-path] entries are summed PER PVC per namespace;
    other namespaces are excluded; percentage = used/capacity*100."""
    available, items = _stats_client({"n1": _STATS_A}).pvc_usage("team-a")
    assert available is True
    assert items == [
        {
            "name": "data-pvc",
            "capacity_bytes": 2000,
            "used_bytes": 500,
            "available_bytes": 1500,
            "percentage_used": 25.0,
        }
    ]


def test_pvc_usage_zero_capacity_is_zero_percent() -> None:
    """4.1's ``usedBytes / capacityBytes`` would divide by zero; 5.0
    reports 0.0 (the guard)."""
    stats = json.dumps(
        {
            "pods": [
                {
                    "volume": [
                        {
                            "pvcRef": {"name": "empty-pvc", "namespace": "team-a"},
                            "capacityBytes": "0",
                            "usedBytes": "0",
                            "availableBytes": "0",
                        }
                    ]
                }
            ]
        }
    )
    available, items = _stats_client({"n1": stats}).pvc_usage("team-a")
    assert available is True
    assert items[0]["percentage_used"] == 0.0


def test_pvc_usage_skips_unhealthy_nodes() -> None:
    """[pvc-usage-partial-nodes] a node whose stats call raises is
    skipped; the healthy subset is returned, ``available`` stays True."""

    def raise_500(name, path=None, **kwargs):
        raise ApiException(status=500)

    client = object.__new__(K8sClient)
    client._v1 = SimpleNamespace(
        list_node=lambda: SimpleNamespace(
            items=[
                SimpleNamespace(to_dict=lambda: {"metadata": {"name": "n1"}}),
                SimpleNamespace(to_dict=lambda: {"metadata": {"name": "bad"}}),
            ]
        ),
        connect_get_node_proxy_with_path=lambda name, path=None, **kw: (
            _STATS_A if name == "n1" else raise_500(name, path)
        ),
    )
    available, items = client.pvc_usage("team-a")
    assert available is True
    assert items[0]["name"] == "data-pvc"


def test_pvc_usage_all_nodes_unhealthy_is_empty() -> None:
    """[pvc-usage-kubelet-degrade] zero healthy nodes → ``(False, [])`` —
    the ADR-0003 query-only degrade, never an exception."""

    def raise_404(name, path=None, **kwargs):
        raise ApiException(status=404)

    client = object.__new__(K8sClient)
    client._v1 = SimpleNamespace(
        list_node=lambda: SimpleNamespace(
            items=[SimpleNamespace(to_dict=lambda: {"metadata": {"name": "bad"}})]
        ),
        connect_get_node_proxy_with_path=raise_404,
    )
    available, items = client.pvc_usage("team-a")
    assert available is False
    assert items == []


def test_pvc_usage_parses_client_repr_body() -> None:
    """The kubernetes client's ``str``-typed node-proxy return hands back the
    stats body as ``str(dict)`` — a PYTHON REPR (single quotes, ``True``/
    ``None``), not JSON. 4.1 ``eval()``ed it; 5.0 must parse it without
    ``eval`` (the live adapter returns this exact shape)."""
    stats = str(
        {
            "node": {"nodeName": "n1"},
            "pods": [
                {
                    "volume": [
                        {
                            "pvcRef": {"name": "data-pvc", "namespace": "team-a"},
                            "capacityBytes": "1000",
                            "usedBytes": "250",
                            "availableBytes": "750",
                        }
                    ]
                }
            ],
        }
    )
    # Sanity: this is NOT valid JSON (single quotes) — the bug the floor caught.
    with pytest.raises(ValueError):
        json.loads(stats)
    available, items = _stats_client({"n1": stats}).pvc_usage("team-a")
    assert available is True
    assert items == [
        {
            "name": "data-pvc",
            "capacity_bytes": 1000,
            "used_bytes": 250,
            "available_bytes": 750,
            "percentage_used": 25.0,
        }
    ]
