"""ADR-0011 (TICKET-05, tracer 2) — GET /api/v1/kubeconfig, the Docker-free
sqlite tier (same fixtures + pattern as tests/api/test_clusters.py).

The downloaded body is the YAML attachment — Content-Type
``application/yaml`` + ``Content-Disposition: attachment;
filename="kubedash-kubeconfig.yaml"``; the error paths are the stable
envelope (404 NO_BINDINGS, 500 INTERNAL_ERROR). SATISFIES:
user-downloads-a-multi-cluster-kubeconfig (API half);
user-bound-to-one-cluster-gets-a-single-context-kubeconfig (API half);
user-with-no-bindings-gets-a-404 (API half);
the-kubeconfig-never-embeds-a-token (API half).
"""
import base64
from typing import Any

import yaml

CA_PEM = b"API-TEST-CA"

#: A registry kubeconfig the renderer can extract server + CA from.
KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    f"    certificate-authority-data: {base64.b64encode(CA_PEM).decode()}\n"
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
KUBECONFIG2 = KUBECONFIG.replace("1.2.3.4", "5.6.7.8")


def _register(api_client, headers: dict[str, str], name: str, kc: str) -> dict[str, Any]:
    r = api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": f"https://{name}.example.com:6443",
            "kubeconfig": kc,
            "context": name,
        },
        headers=headers,
    )
    assert r.status_code in (200, 201), r.get_json()
    return r.get_json()


def _add_binding(api_app, sub: str, cluster_id: int, namespace: str | None) -> None:
    """A second, namespace-scoped binding on a registered cluster (POST
    /clusters auto-binds with namespace=None — this is the explicit
    per-namespace binding the kubeconfig must render as its own context)."""
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.user import User

    with api_app.app_context():
        u = db.session.execute(db.select(User).filter_by(sub=sub)).scalar_one()
        db.session.add(
            ClusterBinding(user_id=u.id, cluster_id=cluster_id, role="viewer",
                           namespace=namespace, template="viewer")
        )
        db.session.commit()


def test_bound_user_downloads_multi_cluster_yaml(
    api_app, api_client, auth_client, monkeypatch
) -> None:
    """SATISFIES user-downloads-a-multi-cluster-kubeconfig (API half) +
    user-bound-to-one-cluster-gets-a-single-context-kubeconfig (API half):
    the attachment headers, valid YAML, one context per binding, CA inlined,
    exec-only user."""
    monkeypatch.setenv("KUBEDASH_PLUGIN_SERVER", "https://kubedash.example.com")
    import app.core.config as _config

    _config._settings = None
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    prod = _register(api_client, h, "prod", KUBECONFIG)
    staging = _register(api_client, h, "staging", KUBECONFIG2)
    # A second binding on prod, in its own namespace → a second context.
    _add_binding(api_app, "sub-oidc-1", prod["id"], "team-a")

    r = api_client.get("/api/v1/kubeconfig", headers=h)
    assert r.status_code == 200, r.get_json()
    assert r.content_type == "application/yaml"
    assert r.headers["Content-Disposition"] == (
        'attachment; filename="kubedash-kubeconfig.yaml"'
    )
    doc = yaml.safe_load(r.data)
    # One cluster entry per distinct cluster, one context PER BINDING.
    assert [c["name"] for c in doc["clusters"]] == ["kubedash-prod", "kubedash-staging"]
    assert doc["clusters"][0]["cluster"]["certificate-authority-data"] == (
        base64.b64encode(CA_PEM).decode()
    )
    assert len(doc["contexts"]) == 3
    # One context per binding: the two cluster-scoped auto-binds omit the key,
    # the explicit one carries team-a.
    assert [c["context"].get("namespace") for c in doc["contexts"]] == [None, "team-a", None]
    # ADR-0011 (the load-bearing property): one shared exec user, NO token.
    users = doc["users"]
    assert len(users) == 1
    user = users[0]["user"]
    assert set(user) == {"exec"}
    assert user["exec"]["args"] == [
        "kubedash", "get-token", "--server=https://kubedash.example.com",
    ]
    for c in doc["contexts"]:
        assert "token" not in c["context"] and "tokenFile" not in c["context"]


def test_cluster_scoped_binding_only_omits_namespace(api_app, api_client, auth_client, monkeypatch) -> None:
    """A user with ONLY the auto cluster-scoped binding → the context has no
    ``namespace`` key."""
    monkeypatch.setenv("KUBEDASH_PLUGIN_SERVER", "https://kubedash.example.com")
    import app.core.config as _config

    _config._settings = None
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h, "solo", KUBECONFIG)
    r = api_client.get("/api/v1/kubeconfig", headers=h)
    assert r.status_code == 200, r.get_json()
    doc = yaml.safe_load(r.data)
    assert "namespace" not in doc["contexts"][0]["context"]
    assert doc["current-context"] == "kubedash-solo"


def test_no_bindings_404(api_client, auth_client, api_app, monkeypatch) -> None:
    """SATISFIES user-with-no-bindings-gets-a-404 (API half): a bound-to-
    nothing user gets 404 NO_BINDINGS."""
    monkeypatch.setenv("KUBEDASH_PLUGIN_SERVER", "https://kubedash.example.com")
    import app.core.config as _config

    _config._settings = None
    auth_client.login()
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with api_app.app_context():
        u2 = User(sub="unbound-kc", email="unbound-kc@example.com")
        db.session.add(u2)
        db.session.commit()
        access, _ = issue_token_pair(u2)
    r = api_client.get("/api/v1/kubeconfig", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "NO_BINDINGS"


def test_plugin_server_unset_500(api_client, auth_client, api_app, monkeypatch) -> None:
    """``KUBEDASH_PLUGIN_SERVER`` unset → 500 INTERNAL_ERROR (never an empty
    ``--server=``)."""
    monkeypatch.delenv("KUBEDASH_PLUGIN_SERVER", raising=False)
    import app.core.config as _config

    _config._settings = None
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h, "prod500", KUBECONFIG)
    r = api_client.get("/api/v1/kubeconfig", headers=h)
    assert r.status_code == 500
    assert r.get_json()["error"]["code"] == "INTERNAL_ERROR"
    assert "KUBEDASH_PLUGIN_SERVER" in r.get_json()["error"]["message"]
