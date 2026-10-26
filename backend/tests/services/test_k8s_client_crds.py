"""K8sClient CRD reads — CustomObjectsApi seam (apiextensions.k8s.io/v1).

Same unit pattern as test_k8s_client_namespaces.py: ``object.__new__`` skips
the kubernetes loader. The real ``CustomObjectsApi`` is used, bound to a fake
``ApiClient`` exposing the ``select_header_*``/``param_serialize``/
``_call_with_legacy_options`` contract (the same seam ``node_usage`` relies on
for metrics.k8s.io).
"""
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_CRD_BODY = {
    "items": [
        {
            "metadata": {"name": "applications.argoproj.io"},
            "spec": {
                "group": "argoproj.io",
                "names": {"kind": "Application", "plural": "applications"},
                "scope": "Namespaced",
                "versions": [
                    {"name": "v1alpha1", "served": True, "storage": True},
                    {"name": "v1", "served": True, "storage": False},
                ],
            },
        }
    ]
}


class _FakeApiClient:
    """Fake ``ApiClient`` for the real ``CustomObjectsApi`` (kubernetes 37).

    ``_call_with_legacy_options`` returns the body dict (or raises), matching
    the generated method's return contract. ``param_serialize`` records the
    request path so tests can assert the right resource was hit.
    """

    def __init__(self, body: dict | None, raises: Exception | None) -> None:
        self.body = body or {}
        self.raises = raises
        self.paths: list[str] = []

    def select_header_accept(self, _accept: list[str]) -> str:
        return "application/json"

    def select_header_content_type(self, _content_types: list[str]) -> str:
        return "application/json"

    def param_serialize(self, *args: object, **kwargs: object) -> object:
        # The generated methods pass the ``path_params`` dict (e.g.
        # ``{group, version, plural, name?}``) as a kwarg — that is the
        # assertion surface for "the right resource was hit".
        pp = dict(kwargs.get("path_params") or {})
        self.paths.append(pp)
        path = str(kwargs.get("resource_path", ""))
        return (None, "http://x" + path, [("GET",)])

    def _call_with_legacy_options(self, *args: object, **kwargs: object) -> tuple:
        # The generated ``CustomObjectsApi`` methods return the 3-tuple
        # ``(data, status, headers)`` — the production code unwraps it.
        if self.raises:
            raise self.raises
        return (self.body, 200, {})


def _client(body: dict | None = None, raises: Exception | None = None) -> tuple[K8sClient, _FakeApiClient]:
    client = object.__new__(K8sClient)
    fake = _FakeApiClient(body, raises)
    client._api_client = fake
    return client, fake


def test_list_crds_returns_items() -> None:
    client, fake = _client(_CRD_BODY)
    items = client.list_crds(None)
    assert fake.paths == [{"group": "apiextensions.k8s.io", "version": "v1", "plural": "customresourcedefinitions"}]
    assert len(items) == 1
    assert items[0]["spec"]["group"] == "argoproj.io"


def test_list_crds_maps_non_2xx_tuple_to_unreachable() -> None:
    # The real ``CustomObjectsApi`` only raises for 401; a 500 comes back in
    # the (data, status, headers) tuple and the production code maps it.
    client, _ = _client(None)
    client._api_client._call_with_legacy_options = (
        lambda *a, **k: ({"items": []}, 500, {})
    )
    with pytest.raises(ClusterUnreachableError):
        client.list_crds(None)


def test_list_crds_maps_raised_401_to_unreachable() -> None:
    # A 401 IS raised by the generated method — the except-ApiException path.
    client, _ = _client(None, raises=ApiException(status=401))
    with pytest.raises(ClusterUnreachableError):
        client.list_crds(None)


_CRD_SINGLE = _CRD_BODY["items"][0]


def test_get_crd_returns_single_item() -> None:
    client, fake = _client(_CRD_SINGLE)
    items = client.get_crd(None, "applications.argoproj.io")
    assert fake.paths == [
        {
            "group": "apiextensions.k8s.io",
            "version": "v1",
            "plural": "customresourcedefinitions",
            "name": "applications.argoproj.io",
        }
    ]
    assert len(items) == 1
    assert items[0]["metadata"]["name"] == "applications.argoproj.io"


def test_get_crd_404_returns_empty_list() -> None:
    client, _ = _client(None, raises=ApiException(status=404))
    assert client.get_crd(None, "gone.example.io") == []


def test_get_crd_maps_transport_error_to_unreachable() -> None:
    client, _ = _client(None, raises=ApiException(status=500))
    with pytest.raises(ClusterUnreachableError):
        client.get_crd(None, "applications.argoproj.io")


def test_list_crd_instances_cluster_scoped_ignores_namespace() -> None:
    client, fake = _client({"items": [{"metadata": {"name": "a1"}}]})
    items = client.list_crd_instances("argoproj.io", "v1", "applications", None)
    assert fake.paths == [{"group": "argoproj.io", "version": "v1", "plural": "applications"}]
    assert items[0]["name"] == "a1"


def test_list_crd_instances_namespaced_uses_namespace() -> None:
    client, fake = _client({"items": [{"metadata": {"name": "a1", "namespace": "team-a"}}]})
    client.list_crd_instances("argoproj.io", "v1", "applications", "team-a")
    assert fake.paths == [
        {"group": "argoproj.io", "version": "v1", "namespace": "team-a", "plural": "applications"}
    ]


def test_list_crd_instances_projects_ready_condition_first() -> None:
    body = {
        "items": [
            {
                "metadata": {"name": "a1", "namespace": "team-a", "creationTimestamp": "2026-01-02T03:04:05Z"},
                "status": {
                    "conditions": [
                        {"type": "Available", "status": "False", "reason": "Wait", "message": "not yet"},
                        {"type": "Ready", "status": "True", "reason": "Ok", "message": "all good"},
                    ],
                },
            },
        ]
    }
    client, _ = _client(body)
    [row] = client.list_crd_instances("g.io", "v1", "things", "team-a")
    assert row == {
        "name": "a1",
        "namespace": "team-a",
        "status": "True",
        "type": "Ready",
        "reason": "Ok",
        "message": "all good",
        "created": "2026-01-02T03:04:05Z",
    }


def test_list_crd_instances_falls_back_to_first_condition_then_phase() -> None:
    body = {
        "items": [
            {
                "metadata": {"name": "b1"},
                "status": {
                    "conditions": [{"type": "Degraded", "status": "True", "reason": "R", "message": "M"}],
                },
            },
            {"metadata": {"name": "c1"}, "status": {"phase": "Succeeded"}},
        ]
    }
    client, _ = _client(body)
    [first, second] = client.list_crd_instances("g.io", "v1", "things", None)
    assert (first["type"], first["status"], first["reason"]) == ("Degraded", "True", "R")
    assert (second["type"], second["status"]) == ("", "Succeeded")
