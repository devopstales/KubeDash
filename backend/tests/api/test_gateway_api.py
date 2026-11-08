"""R7 — Ingress → Gateway API converter endpoint: POST /api/v1/clusters/<id>/gateway-api/convert."""

import importlib
from typing import Any

import pytest

from app.services import rbac as rbac_service

KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    "contexts:\n"
    "- name: c\n"
    "  context:\n"
    "    cluster: c\n"
    "    user: u\n"
    "current-context: c\n"
    "users:\n"
    "- name: u\n"
    "  user: {}\n"
)

INGRESS: dict[str, Any] = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "Ingress",
    "metadata": {"name": "web", "namespace": "team-a", "annotations": {}},
    "spec": {
        "ingressClassName": "nginx",
        "rules": [
            {
                "host": "a.example.com",
                "http": {
                    "paths": [
                        {
                            "path": "/api",
                            "path_type": "Prefix",
                            "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                        }
                    ]
                },
            }
        ],
    },
}


class _FakeK8s:
    def __init__(self) -> None:
        self.ingress: dict[str, Any] | None = None
        self.get_calls: list[tuple[str, str]] = []

    def get_ingress(self, namespace: str, name: str) -> list[dict[str, Any]]:
        self.get_calls.append((namespace, name))
        if self.ingress is None:
            return []
        meta = self.ingress.get("metadata") or {}
        if meta.get("name") != name or meta.get("namespace") != namespace:
            return []
        return [self.ingress]


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> _FakeK8s:
    import app.services.k8s_client as kc

    fake = _FakeK8s()
    pool = kc.K8sClientPool(factory=lambda plain: fake)
    ga = importlib.import_module("app.api.gateway_api")
    monkeypatch.setitem(ga.__dict__, "pool", pool)
    return fake


def _allow_sar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rbac_service, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rbac_service, "_cache_set", lambda e, k, v: None)
    monkeypatch.setattr(rbac_service, "_sar_allowed", lambda *a, **k: True)


def _register(api_client, headers, name: str = "prod") -> object:
    return api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )


def test_convert_emits_gateway_api_resources(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    fake_k8s.ingress = INGRESS
    r = api_client.post(
        "/api/v1/clusters/1/gateway-api/convert",
        json={"ingressName": "web", "namespace": "team-a"},
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["source"] == "ingress"
    assert body["gatewayClassName"] == "eg"
    assert [x["kind"] for x in body["resources"]] == ["GatewayClass", "Gateway", "HTTPRoute"]
    assert body["warnings"] == []


def test_convert_missing_ingress_404(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    fake_k8s.ingress = None
    r = api_client.post(
        "/api/v1/clusters/1/gateway-api/convert",
        json={"ingressName": "ghost", "namespace": "team-a"},
        headers=h,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_convert_sar_denied_403(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    monkeypatch.setattr(rbac_service, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rbac_service, "_cache_set", lambda e, k, v: None)
    monkeypatch.setattr(rbac_service, "_sar_allowed", lambda *a, **k: False)

    r = api_client.post(
        "/api/v1/clusters/1/gateway-api/convert",
        json={"ingressName": "web", "namespace": "team-a"},
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert fake_k8s.get_calls == []
