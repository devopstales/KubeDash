from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_VERSION = "v1"


def _client(custom: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    # The CRD is present and served (the absent case is tested separately).
    client.get_crd_served = lambda group, plural: (_VERSION, "Namespaced")
    return client


def _vpa(name: str, ns: str) -> dict:
    return {
        "apiVersion": "autoscaling.k8s.io/v1",
        "kind": "VerticalPodAutoscaler",
        "metadata": {
            "name": name,
            "namespace": ns,
            "creationTimestamp": "2026-01-02T03:04:05Z",
        },
        "spec": {
            "targetRef": {"kind": "Deployment", "name": name, "apiVersion": "apps/v1"},
            "updatePolicy": {"updateMode": "Auto"},
            "resourcePolicy": {
                "containerPolicies": [
                    {
                        "containerName": "app",
                        "minAllowed": {"memory": "128Mi"},
                        "maxAllowed": {"memory": "1Gi"},
                        "mode": "Auto",
                    }
                ]
            },
        },
        "status": {
            "conditions": [
                {
                    "type": "RecommendationProvided",
                    "status": "True",
                    "reason": "RecommendationAvailable",
                    "message": "ok",
                    "lastTransitionTime": "2026-01-02T03:04:06Z",
                }
            ]
        },
    }


def test_list_vertical_pod_autoscalers_in_namespace() -> None:
    """[verticalpodautoscalers-list-200-in-namespace] a namespace is
    forwarded to ``list_namespaced_custom_object`` and the FULL object
    (spec + status intact, camelCase) is returned (the Cilium pattern)."""
    seen: list[object] = []
    vpa = _vpa("web-vpa", "team-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [vpa]},
        )[1],
    )
    result = _client(custom).list_vertical_pod_autoscalers("team-a")
    assert result[0]["metadata"]["name"] == "web-vpa"
    assert result[0]["spec"]["targetRef"]["kind"] == "Deployment"  # spec intact
    assert (
        result[0]["status"]["conditions"][0]["type"] == "RecommendationProvided"
    )  # status intact
    assert seen == [("autoscaling.k8s.io", _VERSION, "team-a", "verticalpodautoscalers")]


def test_list_vertical_pod_autoscalers_all_namespaces_without_namespace() -> None:
    """[verticalpodautoscalers-list-all-namespaces-without-param] ``None``
    uses the all-namespaces custom-object call (the Cilium branch)."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append(True),
            {"items": []},
        )[1],
    )
    assert _client(custom).list_vertical_pod_autoscalers(None) == []
    assert seen == [True]


def test_list_vertical_pod_autoscalers_crd_absent_is_empty() -> None:
    """[verticalpodautoscalers-crd-absent-is-empty] the CRD read is
    ``None`` (operator not installed) -> ``[]`` (the Cilium absent
    contract), and the custom-object list is never called."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_vertical_pod_autoscalers("team-a") == []
    assert seen == []  # the list call was never made


def test_get_vertical_pod_autoscaler_404_returns_empty_list() -> None:
    """[verticalpodautoscalers-get-by-name] a miss is ``[]``, mirroring
    ``get_cilium_network_policy``'s 0/1-item contract."""

    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_vertical_pod_autoscaler("team-a", "ghost") == []


def test_get_vertical_pod_autoscaler_hit_returns_one_full_item() -> None:
    vpa = _vpa("web-vpa", "team-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: vpa)
    result = _client(custom).get_vertical_pod_autoscaler("team-a", "web-vpa")
    assert result[0]["spec"]["targetRef"]["name"] == "web-vpa"  # full object


def test_get_vertical_pod_autoscaler_other_api_error_maps_to_unreachable() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(get_namespaced_custom_object=get)).get_vertical_pod_autoscaler(
            "team-a", "web-vpa"
        )
