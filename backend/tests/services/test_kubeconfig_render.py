"""ADR-0011 (TICKET-05, tracer 2) — the kubeconfig renderer, pure unit.

The load-bearing property (ADR-0011): the downloaded YAML's ``users[]`` is
EXACTLY ONE shared exec-plugin entry — NO ``token`` / ``tokenFile`` /
``oidc-*`` keys anywhere. SATISFIES:
user-downloads-a-multi-cluster-kubeconfig (renderer half);
user-bound-to-one-cluster-gets-a-single-context-kubeconfig (renderer half);
the-kubeconfig-never-embeds-a-token.
"""
import base64

import yaml

from app.services import kubeconfig_render

CA_B64 = base64.b64encode(b"FAKE-CA-PEM").decode()
CA2_B64 = base64.b64encode(b"FAKE-CA2-PEM").decode()
SERVER = "https://kubedash.example.com"


def _load(yml: str) -> dict:
    doc = yaml.safe_load(yml)
    assert isinstance(doc, dict)
    return doc


def test_single_cluster_single_namespace() -> None:
    """SATISFIES user-bound-to-one-cluster-gets-a-single-context-kubeconfig
    (renderer half): 1 cluster, 1 context (namespace present), 1 shared exec
    user, current-context = the context."""
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[{"name": "kubedash-prod", "server": "https://api.prod:6443", "ca_data_b64": CA_B64}],
        contexts=[{"name": "kubedash-prod", "namespace": "production"}],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    assert doc["apiVersion"] == "v1"
    assert doc["kind"] == "Config"
    assert len(doc["clusters"]) == 1
    c = doc["clusters"][0]
    assert c["name"] == "kubedash-prod"
    assert c["cluster"]["server"] == "https://api.prod:6443"
    assert c["cluster"]["certificate-authority-data"] == CA_B64
    assert len(doc["contexts"]) == 1
    ctx = doc["contexts"][0]
    assert ctx["name"] == "kubedash-prod"
    assert ctx["context"]["cluster"] == "kubedash-prod"
    assert ctx["context"]["user"] == "kubedash"
    assert ctx["context"]["namespace"] == "production"
    assert doc["current-context"] == "kubedash-prod"
    assert _assert_single_shared_exec_user(doc, SERVER)


def test_multi_cluster_multi_namespace() -> None:
    """SATISFIES user-downloads-a-multi-cluster-kubeconfig (renderer half):
    2 clusters, 2 contexts, still ONE shared user entry."""
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[
            {"name": "kubedash-production", "server": "https://api.production.example.com:6443",
             "ca_data_b64": CA_B64},
            {"name": "kubedash-staging", "server": "https://api.staging.example.com:6443",
             "ca_data_b64": CA2_B64},
        ],
        contexts=[
            {"name": "kubedash-production", "namespace": "production"},
            {"name": "kubedash-staging", "namespace": "staging"},
        ],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    assert [c["name"] for c in doc["clusters"]] == ["kubedash-production", "kubedash-staging"]
    assert doc["clusters"][0]["cluster"]["server"] == "https://api.production.example.com:6443"
    assert doc["clusters"][0]["cluster"]["certificate-authority-data"] == CA_B64
    assert doc["clusters"][1]["cluster"]["server"] == "https://api.staging.example.com:6443"
    assert doc["clusters"][1]["cluster"]["certificate-authority-data"] == CA2_B64
    assert [c["name"] for c in doc["contexts"]] == ["kubedash-production", "kubedash-staging"]
    assert doc["contexts"][0]["context"] == {
        "cluster": "kubedash-production", "user": "kubedash", "namespace": "production",
    }
    assert doc["contexts"][1]["context"] == {
        "cluster": "kubedash-staging", "user": "kubedash", "namespace": "staging",
    }
    assert doc["current-context"] == "kubedash-production"  # the FIRST context
    _assert_single_shared_exec_user(doc, SERVER)


def test_same_cluster_two_namespaces_two_contexts_one_cluster_entry() -> None:
    """TRIANGULATE: two bindings on the SAME cluster → two context entries
    (each with its own namespace), but ONE cluster entry (one per cluster,
    not per binding). Both contexts reference the same cluster name — that
    is the §5B shape the service produces (context name = cluster entry name
    = ``kubedash-<cluster.name>``)."""
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[{"name": "kubedash-prod", "server": "https://api.prod:6443", "ca_data_b64": CA_B64}],
        contexts=[
            {"name": "kubedash-prod", "namespace": "team-a"},
            {"name": "kubedash-prod", "namespace": "team-b"},
        ],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    assert len(doc["clusters"]) == 1
    assert len(doc["contexts"]) == 2
    assert doc["contexts"][0]["context"]["namespace"] == "team-a"
    assert doc["contexts"][1]["context"]["namespace"] == "team-b"
    assert doc["contexts"][0]["context"]["cluster"] == "kubedash-prod"
    assert doc["contexts"][1]["context"]["cluster"] == "kubedash-prod"
    _assert_single_shared_exec_user(doc, SERVER)


def test_cluster_scoped_binding_omits_namespace_key() -> None:
    """A cluster-scoped binding (namespace='') → the context has NO
    ``namespace`` key at all (not an empty string)."""
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[{"name": "kubedash-prod", "server": "https://api.prod:6443", "ca_data_b64": CA_B64}],
        contexts=[{"name": "kubedash-prod", "namespace": ""}],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    ctx = doc["contexts"][0]["context"]
    assert "namespace" not in ctx
    assert ctx == {"cluster": "kubedash-prod", "user": "kubedash"}
    _assert_single_shared_exec_user(doc, SERVER)


def test_empty_ca_omits_certificate_authority_data_key() -> None:
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[{"name": "kubedash-prod", "server": "https://api.prod:6443", "ca_data_b64": ""}],
        contexts=[{"name": "kubedash-prod", "namespace": "ns"}],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    assert "certificate-authority-data" not in doc["clusters"][0]["cluster"]


def test_no_token_anywhere() -> None:
    """SATISFIES the-kubeconfig-never-embeds-a-token: parse the YAML back and
    walk EVERY mapping — no ``token`` / ``tokenFile`` / ``oidc-*`` key, and
    ``users[0].user`` is EXACTLY ``{"exec": {...}}`` (the exec is the ONLY key)."""
    yml = kubeconfig_render.render_kubeconfig(
        clusters=[
            {"name": "kubedash-production", "server": "https://p:6443", "ca_data_b64": CA_B64},
            {"name": "kubedash-staging", "server": "https://s:6443", "ca_data_b64": CA2_B64},
        ],
        contexts=[
            {"name": "kubedash-production", "namespace": "production"},
            {"name": "kubedash-staging", "namespace": ""},
        ],
        plugin_server=SERVER,
    )
    doc = _load(yml)
    _assert_no_token_keys(doc)
    user = doc["users"][0]["user"]
    assert set(user) == {"exec"}


def _assert_no_token_keys(node: object) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            assert key not in ("token", "tokenFile"), f"forbidden key {key!r}"
            assert not str(key).startswith("oidc-"), f"forbidden key {key!r}"
            _assert_no_token_keys(value)
    elif isinstance(node, list):
        for item in node:
            _assert_no_token_keys(item)


def _assert_single_shared_exec_user(doc: dict, server: str) -> dict:
    """Exactly ONE user entry, named ``kubedash``, exec-only — ADR-0011."""
    assert len(doc["users"]) == 1
    user = doc["users"][0]
    assert user["name"] == "kubedash"
    u = user["user"]
    assert set(u) == {"exec"}
    exec_ = u["exec"]
    assert exec_["apiVersion"] == "client.authentication.k8s.io/v1"
    assert exec_["command"] == "kubectl"
    assert exec_["args"] == ["kubedash", "get-token", f"--server={server}"]
    _assert_no_token_keys(doc)
    return exec_
