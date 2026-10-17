"""R3 — cluster registry API: encrypted kubeconfig, binding gate, pool seam.

Docker-free: sqlite + fake redis (the app fixture in tests/api/conftest.py).
The k8s call path is exercised through a ``FakeK8s`` double injected via the
pool's ``factory`` kwarg — the same seam Task 5's pod listing uses.
"""
import socket
import time

import pytest

# A minimal kubeconfig the kubernetes client can load (cluster entry present
# so KubeConfig.from_custom_yaml works; TLS fields are irrelevant — the fake
# client never dials).
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


class FakeK8s:
    """Double standing in for a live K8sClient. Records construction args and
    reports the configured readyz result."""

    def __init__(self, kubeconfig: bytes, readyz_result: bool = False) -> None:
        self.kubeconfig = kubeconfig
        self._readyz_result = readyz_result
        FakeK8s.last = self

    def list_pods(self, namespace: str | None) -> list[dict]:
        return []

    def readyz(self) -> bool:
        return self._readyz_result


@pytest.fixture()
def fake_k8s(app, monkeypatch) -> bool:
    """Inject the FakeK8s factory into the module pool and return a switch.

    ``app`` is a fixture (function-scoped) here so the patch applies per test.
    """
    import app.services.k8s_client as kc

    state = {"readyz": False}
    # setitem: swap the attribute on the shared module object (no restore
    # churn on the module; monkeypatch undoes it at teardown).
    monkeypatch.setitem(
        kc.__dict__,
        "pool",
        kc.K8sClientPool(factory=lambda plain: FakeK8s(plain, state["readyz"])),
    )
    return state


def _register(client, headers, name="prod") -> object:
    return client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )


def test_register_stores_encrypted_and_roundtrips(app, client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = _register(client, h)
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["name"] == "prod"
    assert body["id"] is not None

    with app.app_context():
        from app.extensions import db
        from app.models.cluster import Cluster
        from app.services.k8s_client import decrypt_kubeconfig

        row = db.session.get(Cluster, body["id"])
        # At-rest form hides the plaintext and carries the OD-2 version byte.
        assert b"apiVersion" not in row.kubeconfig_enc
        assert row.kubeconfig_enc[0] == 0x01
        assert decrypt_kubeconfig(row.kubeconfig_enc) == KUBECONFIG.encode()
        # Auto-binding: the registering user is bound as admin.
        from app.models.binding import ClusterBinding
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        b = db.session.execute(
            db.select(ClusterBinding).filter_by(user_id=u.id, cluster_id=row.id)
        ).scalar_one()
        assert b.role == "admin"


def test_register_and_list_bound(client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = _register(client, h)
    assert r.status_code in (200, 201)
    r2 = client.get("/api/v1/clusters", headers=h)
    names = [c["name"] for c in r2.get_json()]
    assert "prod" in names


def test_duplicate_name_409(client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    assert _register(client, h, name="dup").status_code in (200, 201)
    r = _register(client, h, name="dup")
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_invalid_kubeconfig_422(client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = client.post(
        "/api/v1/clusters",
        json={
            "name": "bad",
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": "::not-yaml",
            "context": "bad",
        },
        headers=h,
    )
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"


def test_unbound_user_does_not_see_cluster(client, auth_client, app) -> None:
    auth_client.login()
    assert _register(client, {"Authorization": f"Bearer {auth_client.jwt}"}).status_code in (
        200,
        201,
    )
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with app.app_context():
        u2 = User(sub="stranger", email="s@example.com")
        db.session.add(u2)
        db.session.commit()
        access, _ = issue_token_pair(u2)  # inside the app context
    r = client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.get_json() == []


def test_get_unbound_cluster_404(client, auth_client, app) -> None:
    """The binding gate: a cluster that EXISTS but the caller is not bound to
    is indistinguishable from a missing one — 404 CLUSTER_NOT_FOUND."""
    auth_client.login()
    _register(client, {"Authorization": f"Bearer {auth_client.jwt}"})
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with app.app_context():
        u2 = User(sub="stranger2", email="s2@example.com")
        db.session.add(u2)
        db.session.commit()
        access, _ = issue_token_pair(u2)
    r = client.get("/api/v1/clusters/1", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_health_up_with_fake_k8s(client, auth_client, fake_k8s) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    assert _register(client, h).status_code in (200, 201)
    fake_k8s["readyz"] = True
    r = client.get("/api/v1/clusters/1/health", headers=h)
    assert r.status_code == 200
    assert r.get_json() == {"status": "up"}


def test_health_down_maps_to_502(client, auth_client, fake_k8s) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    assert _register(client, h).status_code in (200, 201)
    r = client.get("/api/v1/clusters/1/health", headers=h)  # readyz() = False
    assert r.status_code == 502
    assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"


def test_pool_decodes_stored_ciphertext(app, client, auth_client) -> None:
    """The pool must decrypt the at-rest form and hand the PLAINTEXT kubeconfig
    to the factory (the real K8sClient builds from it)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    assert _register(client, h).status_code in (200, 201)
    client.get("/api/v1/clusters/1/health", headers=h)  # forces pool.get()
    assert FakeK8s.last is not None
    assert FakeK8s.last.kubeconfig == KUBECONFIG.encode()


def test_health_blackholed_server_returns_within_budget(client, auth_client, fake_k8s) -> None:
    """A refused port is fast; a BLACKHOLED port (accepts, never responds)
    must still return within the 5 s probe budget (briefing edge case).

    FakeK8s is bypassed here: K8sClient.readyz() itself dials the blackhole.
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)  # accepts (default backlog) but never reads
    port = sock.getsockname()[1]
    try:
        auth_client.login()
        h = {"Authorization": f"Bearer {auth_client.jwt}"}
        r = client.post(
            "/api/v1/clusters",
            json={
                "name": "blackhole",
                "api_server": f"https://127.0.0.1:{port}",
                "kubeconfig": KUBECONFIG,
                "context": "blackhole",
            },
            headers=h,
        )
        assert r.status_code in (200, 201)
        # Point the real K8sClient at the blackhole: override the pool with the
        # REAL factory (the fake one would never dial).
        import app.services.k8s_client as kc

        kc.pool = kc.K8sClientPool()  # default factory = K8sClient
        t0 = time.monotonic()
        r = client.get("/api/v1/clusters/1/health", headers=h)
        assert r.status_code == 502
        assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"
        assert time.monotonic() - t0 < 8  # 5 s budget + slack
    finally:
        sock.close()


def test_readyz_url_uses_host_verbatim_and_ca(monkeypatch) -> None:
    import app.services.k8s_client as kc

    captured: dict[str, object] = {}

    class FakeResp:
        status_code = 200

    class FakeHttpx:
        @staticmethod
        def get(url, timeout, verify):
            captured.update(url=url, timeout=timeout, verify=verify)
            return FakeResp()

    monkeypatch.setattr("httpx.get", FakeHttpx.get)
    k = kc.K8sClient.__new__(kc.K8sClient)
    k._host = "https://api.example.com:6443"
    k._verify = b"CA-BYTES"
    assert k.readyz() is True
    assert captured["url"] == "https://api.example.com:6443/readyz"  # no double scheme
    assert captured["timeout"] == 5.0
    assert captured["verify"] == b"CA-BYTES"
