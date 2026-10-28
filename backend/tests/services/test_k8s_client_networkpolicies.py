from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(networking: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._networking = networking
    return client


def test_list_network_policies_namespaced_hits_namespaced_api() -> None:
    """[networkpolicies-list-namespaced] the namespaced list hits the
    namespaced NetworkingV1Api method with the query namespace."""
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "deny-all"}})

    def list_namespaced(ns: str) -> SimpleNamespace:
        seen.append(ns)
        return SimpleNamespace(items=[item])

    networking = SimpleNamespace(
        list_namespaced_network_policy=list_namespaced,
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[]),
    )
    result = _client(networking).list_network_policies("team-a")
    assert result == [{"metadata": {"name": "deny-all"}}]
    assert seen == ["team-a"]


def test_list_network_policies_no_namespace_lists_all() -> None:
    """[networkpolicies-list-all-namespaces] no namespace query takes the
    all-namespaces branch; the namespaced method is never called."""
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "np"}})

    def never_called(_ns: str) -> object:
        raise AssertionError("must not be called")

    networking = SimpleNamespace(
        list_namespaced_network_policy=never_called,
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[item]),
    )
    result = _client(networking).list_network_policies(None)
    assert result == [{"metadata": {"name": "np"}}]


def test_get_network_policy_404_returns_empty_list() -> None:
    """[networkpolicies-get-by-name] a missing policy is ``[]``, mirroring
    ``get_secret``'s 0/1-item contract."""
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=404)

    networking = SimpleNamespace(read_namespaced_network_policy=read)
    assert _client(networking).get_network_policy("team-a", "gone") == []


def test_get_network_policy_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=500)

    client = _client(SimpleNamespace(read_namespaced_network_policy=read))
    with pytest.raises(ClusterUnreachableError):
        client.get_network_policy("team-a", "np")


def test_list_network_policies_maps_500_to_unreachable() -> None:
    def list_namespaced(_ns: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_network_policy=list_namespaced)).list_network_policies("team-a")


# ---------------------------------------------------------------------------
# Cilium kinds (R2): served-version autodetect + absence degrade.
#
# The multi-call fake below is the door check's pinned contract: it models
# "CRD absent (404 ApiException from the generated read)" and "cluster
# unreachable (live (data, status, headers) tuple)" DISTINCTLY in one
# client instance, dispatching on the resource_path plural recorded by
# ``param_serialize`` (pattern: test_k8s_client_crds.py:35-68).
# ---------------------------------------------------------------------------

_CNP_CRD = {
    "metadata": {"name": "ciliumnetworkpolicies.cilium.io"},
    "spec": {
        "group": "cilium.io",
        "names": {"plural": "ciliumnetworkpolicies"},
        "scope": "Namespaced",
        "versions": [
            # v2alpha1 — NOT the 4.1-hardcoded v2: pins autodetection.
            {"name": "v2alpha1", "served": True, "storage": True},
        ],
    },
}

_CCNP_CRD = {
    "metadata": {"name": "ciliumclusterwidenetworkpolicies.cilium.io"},
    "spec": {
        "group": "cilium.io",
        "names": {"plural": "ciliumclusterwidenetworkpolicies"},
        "scope": "Cluster",
        "versions": [
            {"name": "v2alpha1", "served": True, "storage": True},
        ],
    },
}

_CNP_ITEM = {
    "metadata": {"name": "cnp", "namespace": "team-a"},
    "spec": {"endpointSelector": {}, "ingress": [{"from": []}]},
}

_CCNP_ITEM = {"metadata": {"name": "ccnp"}, "spec": {"endpointSelector": {}, "egress": []}}


class _FakeMultiCallApiClient:
    """Fake ``ApiClient`` for the real ``CustomObjectsApi`` (kubernetes 37).

    ``param_serialize`` records the request path (the ``path_params`` dict)
    so the CRD read (``customresourcedefinitions``) and the instance list
    (``ciliumnetworkpolicies``) are modeled DISTINCTLY in one client.
    ``_call_with_legacy_options`` returns the per-plural body, or raises the
    per-plural exception. The non-raised error shape is the LIVE apiserver
    shape: the ``CustomObjectsApi`` generated methods only raise for 401
    (their ``_response_types_map``); every other status comes back in the
    ``(data, status, headers)`` tuple that ``_crd_body`` maps to
    ``ClusterUnreachableError``.
    """

    def __init__(
        self,
        crd: dict | None = None,
        crd_read_404: bool = False,
        custom_list: object | None = None,
        custom_list_raises: Exception | None = None,
    ) -> None:
        self.crd = crd or {}
        self.crd_read_404 = crd_read_404
        self.custom_list = custom_list
        self.custom_list_raises = custom_list_raises
        self.custom_paths: list[dict] = []
        self._pending: dict | None = None

    def select_header_accept(self, _accept: list[str]) -> str:
        return "application/json"

    def select_header_content_type(self, _content_types: list[str]) -> str:
        return "application/json"

    def param_serialize(self, *args: object, **kwargs: object) -> object:
        pp = dict(kwargs.get("path_params") or {})
        # The CRD read (get_crd) and the instance read/list are modeled
        # DISTINCTLY: key the response by the plural each call names.
        self._pending = pp
        if pp.get("plural") == "customresourcedefinitions":
            self.crd_read_path = pp
        else:
            self.custom_paths.append(pp)
        return (None, "http://x" + str(kwargs.get("resource_path", "")), [("GET",)])

    def _call_with_legacy_options(self, *args: object, **kwargs: object) -> tuple:
        pp = self._pending
        if pp is None:
            raise AssertionError("call before param_serialize — fake wiring bug")
        if pp.get("plural") == "customresourcedefinitions":
            # The CRD read: the generated method returns the (data, status,
            # headers) tuple; 404 is RAISED by the generated method (the
            # legacy REST layer raises non-2xx) — modeled as a raised
            # ApiException(404).
            if self.crd_read_404:
                raise ApiException(status=404)
            return (self.crd, 200, {})
        # The instance read/list:
        if self.custom_list_raises is not None:
            raise self.custom_list_raises
        if self.custom_list is None:
            return ({"items": []}, 200, {})
        return self.custom_list


def _client_with_custom(
    crd: dict | None = None,
    crd_read_404: bool = False,
    custom_list: object | None = None,
    custom_list_raises: Exception | None = None,
    record_custom_calls: bool = False,
) -> K8sClient:
    """``object.__new__(K8sClient)`` with ``_api_client`` bound to a
    per-path ``_FakeMultiCallApiClient`` (pattern:
    backend/tests/services/test_k8s_client_crds.py:35-68). ``record_custom_calls``
    is accepted for the brief's signature; the fake always records the
    instance-list calls (``custom_paths``) — the tests read them directly."""
    client = object.__new__(K8sClient)
    client._api_client = _FakeMultiCallApiClient(
        crd=crd,
        crd_read_404=crd_read_404,
        custom_list=custom_list,
        custom_list_raises=custom_list_raises,
    )
    return client


def test_get_crd_served_resolves_served_version_and_scope() -> None:
    # [cilium-list-uses-served-version] CRD served on v2alpha1 (NOT v2) —
    # pins autodetection: no hardcoded version.
    client = _client_with_custom(crd=_CNP_CRD, custom_list=({"items": []}, 200, {}))
    assert client.get_crd_served("cilium.io", "ciliumnetworkpolicies") == ("v2alpha1", "Namespaced")


def test_get_crd_served_absent_returns_none() -> None:
    # [cilium-crds-absent-empty] CRD read 404 -> None (Cilium not installed),
    # NOT an exception.
    client = _client_with_custom(crd_read_404=True)
    assert client.get_crd_served("cilium.io", "ciliumnetworkpolicies") is None


def test_get_crd_served_no_served_version_raises() -> None:
    # A CRD that exists but declares no served version is mis-registered
    # Cilium, not "absent": ClusterUnreachableError (502).
    crd = {
        "metadata": {"name": "ciliumnetworkpolicies.cilium.io"},
        "spec": {
            "group": "cilium.io",
            "names": {"plural": "ciliumnetworkpolicies"},
            "scope": "Namespaced",
            "versions": [{"name": "v2alpha1", "served": False, "storage": True}],
        },
    }
    client = _client_with_custom(crd=crd)
    with pytest.raises(ClusterUnreachableError):
        client.get_crd_served("cilium.io", "ciliumnetworkpolicies")


def test_list_cilium_network_policies_absent_crds_empty() -> None:
    # [cilium-crds-absent-empty] get_crd_served is None -> [] WITHOUT calling
    # the custom list (one less 404 to interpret).
    client = _client_with_custom(crd_read_404=True, record_custom_calls=True)
    assert client.list_cilium_network_policies("team-a") == []
    # The instance-list call was never made.
    assert client._api_client.custom_paths == []


def test_list_cilium_network_policies_full_items() -> None:
    # [cilium-list-uses-served-version] items come back to_dict()-shaped with
    # spec intact; the served version (v2alpha1) is what the custom list uses.
    client = _client_with_custom(
        crd=_CNP_CRD, custom_list=({"items": [_CNP_ITEM]}, 200, {})
    )
    rows = client.list_cilium_network_policies("team-a")
    assert rows[0]["spec"]["ingress"] == [{"from": []}]
    assert rows[0]["metadata"]["name"] == "cnp"
    # The custom list was called with the served version, not a hardcoded one.
    [call] = client._api_client.custom_paths
    assert call["version"] == "v2alpha1"
    assert call["namespace"] == "team-a"
    assert call["plural"] == "ciliumnetworkpolicies"


def test_list_cilium_clusterwide_ignores_namespace() -> None:
    # [cilium-clusterwide-ignores-namespace] the namespace argument is
    # accepted but the cluster list is used (no namespace in the path).
    client = _client_with_custom(
        crd=_CCNP_CRD, custom_list=({"items": [_CCNP_ITEM]}, 200, {})
    )
    rows = client.list_cilium_clusterwide_network_policies("team-a")
    assert rows[0]["metadata"]["name"] == "ccnp"
    [call] = client._api_client.custom_paths
    assert "namespace" not in call
    assert call["plural"] == "ciliumclusterwidenetworkpolicies"


def test_get_cilium_network_policy_returns_item() -> None:
    # [cilium-get-by-name] a hit returns the one item, spec intact.
    client = _client_with_custom(
        crd=_CNP_CRD, custom_list=({"metadata": {"name": "cnp", "namespace": "team-a"}}, 200, {})
    )
    rows = client.get_cilium_network_policy("team-a", "cnp")
    assert len(rows) == 1
    assert rows[0]["metadata"]["name"] == "cnp"


def test_get_cilium_network_policy_404_returns_empty() -> None:
    # [cilium-get-by-name] a miss (404) is [], mirroring get_secret.
    client = _client_with_custom(crd=_CNP_CRD, custom_list_raises=ApiException(status=404))
    assert client.get_cilium_network_policy("team-a", "ghost") == []


def test_get_cilium_network_policy_absent_crds_empty() -> None:
    # [cilium-get-by-name] CRD absent -> [] (Cilium not installed).
    client = _client_with_custom(crd_read_404=True, record_custom_calls=True)
    assert client.get_cilium_network_policy("team-a", "cnp") == []
    assert client._api_client.custom_paths == []


def test_cilium_custom_error_500_maps_to_unreachable() -> None:
    # [cilium-crds-error-502] the live shape: (body, 500, {}) tuple from the
    # custom list -> ClusterUnreachableError.
    client = _client_with_custom(crd=_CNP_CRD, custom_list=({"items": []}, 500, {}))
    with pytest.raises(ClusterUnreachableError):
        client.list_cilium_network_policies("team-a")


def test_cilium_custom_401_raised_maps_to_unreachable() -> None:
    # [cilium-crds-error-502] the only status the generated method raises
    # (401) is also a transport failure -> ClusterUnreachableError.
    client = _client_with_custom(crd=_CNP_CRD, custom_list_raises=ApiException(status=401))
    with pytest.raises(ClusterUnreachableError):
        client.list_cilium_network_policies("team-a")
