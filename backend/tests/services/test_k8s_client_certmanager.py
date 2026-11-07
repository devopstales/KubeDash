"""cert-manager.io CRD kinds — service-tier tests for the CRD-seam methods
(the ``list_cilium_network_policies`` pattern): the CRD's OWN served version
is the version authority, the scope dispatch (clusterissuers ->
``list_cluster_custom_object``, the namespaced three ->
``list_namespaced_custom_object``), CRD absent -> ``[]``, getter 404 ->
``[]``, full custom-object shape (camelCase, spec/status intact)."""
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient

_GROUP = "cert-manager.io"
_VERSION = "v1"


def _client(custom: object, scope: str = "Namespaced") -> K8sClient:
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    # The CRD is present and served (the absent case is tested separately).
    client.get_crd_served = lambda group, plural: (_VERSION, scope)
    return client


def _clusterissuer(name: str) -> dict:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "ClusterIssuer",
        "metadata": {"name": name, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {
            "acme": {
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "privateKeySecretRef": {"name": f"{name}-key"},
                "solvers": [{"http01": {"ingress": {"class": "nginx"}}}],
            }
        },
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }


def _issuer(name: str, ns: str) -> dict:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "Issuer",
        "metadata": {"name": name, "namespace": ns, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {
            "acme": {
                "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "privateKeySecretRef": {"name": f"{name}-key"},
                "solvers": [{"http01": {"ingress": {"class": "nginx"}}}],
            }
        },
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }


def _certificaterequest(name: str, ns: str) -> dict:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "CertificateRequest",
        "metadata": {"name": name, "namespace": ns, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {"request": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS1SRVFVRVNULS0tLS0="},
        "status": {
            "conditions": [{"type": "Ready", "status": "True", "reason": "Approved"}],
            "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        },
    }


def _certificate(name: str, ns: str) -> dict:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "Certificate",
        "metadata": {"name": name, "namespace": ns, "creationTimestamp": "2026-01-02T03:04:05Z"},
        "spec": {
            "secretName": f"{name}-tls",
            "issuerRef": {"name": "letsencrypt-team", "kind": "Issuer"},
            "dnsNames": ["app.example.com"],
        },
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "notAfter": "2026-07-02T03:04:05Z",
            "renewalTime": "2026-06-02T03:04:05Z",
        },
    }


def test_list_clusterissuers_uses_served_version_cluster_scoped() -> None:
    """[certmanager-clusterissuers-list-200] clusterissuers is CLUSTER-scoped:
    the list goes through ``list_cluster_custom_object`` with the CRD's own
    served version, and the FULL custom object (spec + status, camelCase)
    is returned."""
    seen: list[object] = []
    ci = _clusterissuer("letsencrypt-prod")
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda group, version, plural: (
            seen.append((group, version, plural)),
            {"items": [ci]},
        )[1]
    )
    result = _client(custom, scope="Cluster").list_clusterissuers(None)
    assert result[0]["metadata"]["name"] == "letsencrypt-prod"
    assert result[0]["spec"]["acme"]["server"] == "https://acme-v02.api.letsencrypt.org/directory"
    assert result[0]["status"]["conditions"][0]["type"] == "Ready"
    assert seen == [(_GROUP, _VERSION, "clusterissuers")]


def test_list_clusterissuers_crd_absent_is_empty() -> None:
    """[certmanager-crd-absent-empty] the CRD read is ``None`` (cert-manager
    not installed) -> ``[]``, and the custom-object list is never called."""
    seen: list[object] = []
    custom = SimpleNamespace(
        list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_clusterissuers(None) == []
    assert seen == []  # the list call was never made


def test_list_clusterissuers_maps_500_to_unreachable() -> None:
    def list_cluster(group, version, plural) -> None:
        raise ApiException(status=500)

    custom = SimpleNamespace(list_cluster_custom_object=list_cluster)
    with pytest.raises(ClusterUnreachableError):
        _client(custom, scope="Cluster").list_clusterissuers(None)


def test_get_clusterissuer_404_returns_empty_list() -> None:
    """[certmanager-get-by-name] a miss is ``[]`` (the 0/1-item contract)."""

    def get(group, version, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_cluster_custom_object=get)
    assert _client(custom, scope="Cluster").get_clusterissuer("default", "ghost") == []


def test_get_clusterissuer_hit_returns_one_full_item() -> None:
    ci = _clusterissuer("letsencrypt-prod")
    custom = SimpleNamespace(get_cluster_custom_object=lambda *a, **k: ci)
    result = _client(custom, scope="Cluster").get_clusterissuer("default", "letsencrypt-prod")
    assert result[0]["spec"]["acme"]["privateKeySecretRef"]["name"] == "letsencrypt-prod-key"
    assert result[0]["status"]["conditions"][0]["type"] == "Ready"


def test_list_issuers_in_namespace() -> None:
    """[certmanager-issuers-list-200] a namespace is forwarded to
    ``list_namespaced_custom_object`` and the FULL custom object is
    returned (the namespaced three mirror
    ``list_cilium_network_policies``)."""
    seen: list[object] = []
    issuer = _issuer("letsencrypt-team", "team-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [issuer]},
        )[1]
    )
    result = _client(custom).list_issuers("team-a")
    assert result[0]["metadata"]["name"] == "letsencrypt-team"
    assert result[0]["metadata"]["namespace"] == "team-a"
    assert result[0]["status"]["conditions"][0]["type"] == "Ready"
    assert seen == [(_GROUP, _VERSION, "team-a", "issuers")]


def test_list_issuers_crd_absent_is_empty() -> None:
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_issuers("team-a") == []
    assert seen == []


def test_get_issuer_404_returns_empty_list() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_issuer("team-a", "ghost") == []


def test_get_issuer_hit_returns_one_full_item() -> None:
    issuer = _issuer("letsencrypt-team", "team-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: issuer)
    result = _client(custom).get_issuer("team-a", "letsencrypt-team")
    assert result[0]["spec"]["acme"]["privateKeySecretRef"]["name"] == "letsencrypt-team-key"
    assert result[0]["status"]["conditions"][0]["type"] == "Ready"


def test_list_certificaterequests_in_namespace() -> None:
    """[certmanager-certificaterequests-list-200] the namespaced dispatch,
    full custom object (spec.request + status.certificate intact)."""
    seen: list[object] = []
    req = _certificaterequest("tls-cert-req", "team-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [req]},
        )[1]
    )
    result = _client(custom).list_certificaterequests("team-a")
    assert result[0]["metadata"]["name"] == "tls-cert-req"
    assert result[0]["status"]["conditions"][0]["reason"] == "Approved"
    assert seen == [(_GROUP, _VERSION, "team-a", "certificaterequests")]


def test_list_certificaterequests_crd_absent_is_empty() -> None:
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_certificaterequests("team-a") == []
    assert seen == []


def test_get_certificaterequest_404_returns_empty_list() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_certificaterequest("team-a", "ghost") == []


def test_get_certificaterequest_hit_returns_one_full_item() -> None:
    req = _certificaterequest("tls-cert-req", "team-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: req)
    result = _client(custom).get_certificaterequest("team-a", "tls-cert-req")
    assert result[0]["spec"]["request"].startswith("LS0tLS1CRUdJTi")
    assert result[0]["status"]["certificate"].startswith("LS0tLS1CRUdJTi")


def test_list_certificates_in_namespace() -> None:
    """[certmanager-certificates-list-200] the namespaced dispatch, full
    custom object (spec.dnsNames + status conditions/notAfter intact)."""
    seen: list[object] = []
    cert = _certificate("tls-cert", "team-a")
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda group, version, namespace, plural: (
            seen.append((group, version, namespace, plural)),
            {"items": [cert]},
        )[1]
    )
    result = _client(custom).list_certificates("team-a")
    assert result[0]["metadata"]["name"] == "tls-cert"
    assert result[0]["spec"]["dnsNames"] == ["app.example.com"]
    assert seen == [(_GROUP, _VERSION, "team-a", "certificates")]


def test_list_certificates_crd_absent_is_empty() -> None:
    seen: list[object] = []
    custom = SimpleNamespace(
        list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
    )
    client = object.__new__(K8sClient)
    client._custom = lambda: custom
    client.get_crd_served = lambda group, plural: None
    assert client.list_certificates("team-a") == []
    assert seen == []


def test_get_certificate_404_returns_empty_list() -> None:
    def get(group, version, namespace, plural, name):
        raise ApiException(status=404)

    custom = SimpleNamespace(get_namespaced_custom_object=get)
    assert _client(custom).get_certificate("team-a", "ghost") == []


def test_get_certificate_hit_returns_one_full_item() -> None:
    cert = _certificate("tls-cert", "team-a")
    custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: cert)
    result = _client(custom).get_certificate("team-a", "tls-cert")
    assert result[0]["spec"]["dnsNames"] == ["app.example.com"]
    assert result[0]["status"]["conditions"][0]["type"] == "Ready"
