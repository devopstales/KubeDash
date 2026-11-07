from types import SimpleNamespace

from app.services.k8s_client import K8sClient


def _client(v1: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._v1 = v1
    return client


def test_list_pods_forwards_label_selector() -> None:
    """[pods-labelselector-filters] the ``label_selector`` is passed
    through to ``list_namespaced_pod`` (4.1's ``k8sPodSelectorListGet``
    behavior, re-implemented as a pass-through param)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
    v1 = SimpleNamespace(
        list_namespaced_pod=lambda ns, label_selector=None: (
            seen.append(label_selector), SimpleNamespace(items=[item]))[1]
    )
    result = _client(v1).list_pods("team-a", label_selector="app=web")
    assert result[0]["metadata"]["name"] == "web-abc"
    assert seen == ["app=web"]


def test_list_pods_no_label_selector_unchanged() -> None:
    """[pods-labelselector-absent-unchanged] without a ``label_selector``
    the call is the existing unfiltered list (``label_selector=None``)."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
    v1 = SimpleNamespace(
        list_namespaced_pod=lambda ns, label_selector=None: (
            seen.append(label_selector), SimpleNamespace(items=[item]))[1]
    )
    _client(v1).list_pods("team-a")
    assert seen == [None]
