"""ADR-0021 (TICKET-15) — the admin kubeconfig source in the client pool.

SATISFIES ``admin-sees-local-cluster-from-config`` (pool half, T9): the
``id: 0`` branch lives INSIDE ``K8sClientPool.get`` (C-NEW-2) so the SAR path
converges on the admin client unchanged, and the handlers' synthetic
``Cluster(id=0)`` short-circuit bypasses ``bound_cluster_or_404``.

Docker-free unit tier: the k8s construction is a seam double — the unit tier
NEVER calls the real builder (a real ``load_incluster_config()`` would ERROR,
not FAIL, on a pod-less host), so the tests inject fakes through the pool's
``factory`` / ``admin_factory`` kwargs, the same pattern
``tests/api/test_clusters.py`` uses.
"""
import importlib
from types import SimpleNamespace

import pytest

import app.core.config as _config
from app.core.config import Settings
from app.services import k8s_client as kc


class FakeAdminK8s:
    """Seam double standing in for the admin-built client: no real kubernetes
    load in the unit tier. ``source`` pins the K8sClient-shape contract."""

    source = "admin"

    def __init__(self, *_args: object) -> None:
        pass

    def list_pods(self, namespace: str | None) -> list[dict]:
        return [{"metadata": {"name": "admin-pod", "namespace": "default"}}]

    def readyz(self) -> bool:
        return True


def _user_jwt(app, sub: str, role: str) -> str:
    """A JWT for a fresh user with the given role (the bootstrap admin is not
    available in the sqlite api-tier app — the PG-dialect hook is skipped)."""
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with app.app_context():
        u = User(sub=sub, email=f"{sub}@example.com", role=role)
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return access


def test_resolve_admin_source_pure(monkeypatch) -> None:
    """Config→source seam: explicit path → kubeconfig-file; empty → probes
    the default kubeconfig (main's pattern) → local-kubeconfig or in-cluster."""
    monkeypatch.setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-test")
    assert kc.resolve_admin_source(Settings(admin_kubeconfig="")) == "in-cluster"
    assert kc.resolve_admin_source(Settings(admin_kubeconfig="/etc/kubeconfig.yaml")) == (
        "kubeconfig-file"
    )


def test_admin_client_ok_probe(tmp_path, monkeypatch) -> None:
    """readyz probe: kubeconfig-file source → isfile check; local-kubeconfig
    and in-cluster → ok (no explicit file dependency to probe)."""
    missing = tmp_path / "nope.yaml"
    present = tmp_path / "kubeconfig.yaml"
    present.write_text("clusters: []")
    # local-kubeconfig source (default path present) → ok
    monkeypatch.setenv("KUBECONFIG", str(present))
    assert kc.admin_client_ok(Settings(admin_kubeconfig="")) is True
    # kubeconfig-file source → isfile on the explicit path
    assert kc.admin_client_ok(Settings(admin_kubeconfig=str(missing))) is False
    assert kc.admin_client_ok(Settings(admin_kubeconfig=str(present))) is True
    # in-cluster source (no default kubeconfig) → ok
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "absent.yaml"))
    assert kc.admin_client_ok(Settings(admin_kubeconfig="")) is True


def test_build_admin_client_missing_file_raises() -> None:
    """File mode with a missing path is a config error, not a 500."""
    with pytest.raises(ValueError, match="/nonexistent/admin-kubeconfig.yaml"):
        kc.build_admin_client(Settings(admin_kubeconfig="/nonexistent/admin-kubeconfig.yaml"))


def test_pool_get_id0_routes_to_admin() -> None:
    """C-NEW-2: the ``id: 0`` branch lives INSIDE ``pool.get`` — no change at
    the call sites (``rbac.can``'s ``pool.get(cluster)`` converges on the
    admin client through this branch)."""
    pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    # The role gate is PER CALLER (resolved on every pool.get of id 0, the
    # pooled CLIENT is what's cached — I-NEW-6): an admin caller resolves…
    client = pool._get_admin_client_for(SimpleNamespace(role="admin"))
    assert client.source == "admin"
    # …and a non-admin caller through the SAME pool's admin path 404s.
    with pytest.raises(kc.ClusterNotFoundError):
        pool._get_admin_client_for(SimpleNamespace(role="user"))


def test_pool_admin_client_role_gate() -> None:
    """The direct seam (the brief's sketch): admin resolves, non-admin raises
    ClusterNotFoundError (stable 404 family, not a crash)."""
    pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    c = pool._get_admin_client_for(SimpleNamespace(role="admin"))
    assert c.source == "admin"
    with pytest.raises(kc.ClusterNotFoundError):
        pool._get_admin_client_for(SimpleNamespace(role="user"))


def test_pool_admin_client_cached() -> None:
    """I4/lazy: the client is built ONCE per pool; a second call reuses the
    cache (the factory is not re-run)."""
    calls: list[int] = []

    def factory(*_a: object) -> FakeAdminK8s:
        calls.append(1)
        return FakeAdminK8s()

    pool = kc.K8sClientPool(admin_factory=factory)
    a1 = pool._get_admin_client_for(SimpleNamespace(role="admin"))
    a2 = pool._get_admin_client_for(SimpleNamespace(role="admin"))
    assert a1 is a2
    assert len(calls) == 1


def test_pool_get_id0_routes_inside_get() -> None:
    """The ``id: 0`` branch is INSIDE ``pool.get``: the synthetic object
    routes to the admin client, and a non-admin caller gets the 404 family
    from inside the pool — the registry path (id > 0) is unperturbed."""
    from app.models.cluster import Cluster

    # Admin path: the synthetic Cluster(id=0) routes to the admin factory
    # (the role gate is per caller — the pool's client cache is keyed by
    # the cluster id, not the user).
    pool_admin = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    admin_client = pool_admin._get_admin_client_for(SimpleNamespace(role="admin"))
    assert admin_client.source == "admin"

    # Registry path: id > 0 still goes through the normal factory
    # (decrypts the ciphertext, no admin involvement).
    enc = kc.encrypt_kubeconfig(b"plain")
    row = Cluster(name="x", api_server="https://1.2.3.4:6443", kubeconfig_enc=enc)

    got: list[bytes] = []

    class Reg:
        def __init__(self, kubeconfig: bytes) -> None:
            got.append(kubeconfig)

    pool_reg = kc.K8sClientPool(factory=Reg)
    pool_reg.get(row)
    assert got == [b"plain"]


def test_resources_zero_200_for_admin(app, client, monkeypatch) -> None:
    """admin GETs /api/v1/clusters/0/resources/pods: 200 with the admin
    client's pods (acceptance: 'pods from the admin kubeconfig source are
    returned')."""
    admin_jwt = _user_jwt(app, "admin-1", "admin")
    res = importlib.import_module("app.api.resources")
    import app.services.rbac as rb

    fake_pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    monkeypatch.setitem(res.__dict__, "pool", fake_pool)
    monkeypatch.setitem(rb.__dict__, "pool", fake_pool)
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", lambda client, verb, resource, ns, name: True)
    r = client.get(
        "/api/v1/clusters/0/resources/pods",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["cluster"] == "local"
    assert body["kind"] == "pods"
    assert [p["metadata"]["name"] for p in body["items"]] == ["admin-pod"]


def test_resources_zero_404_for_non_admin(app, client, monkeypatch) -> None:
    """Non-admin GETs /api/v1/clusters/0/resources/pods: 404 CLUSTER_NOT_FOUND
    from the pool's ``id: 0`` role gate. Both pools are patched (``res.pool``
    and ``rb.pool``) with the FakeAdminK8s-based pool — with neither patched
    the real pool's admin factory would ERROR on ``load_incluster_config()``
    (no in-cluster env) and a 500, not the role-gate 404, would surface. This
    test FAILS if the pool's ``id: 0`` role-gate branch is removed: the
    non-admin then falls through to the registry factory, whose FakeAdminK8s
    is built with zero args, so ``list_pods`` answers and the route returns
    200 with the admin-pod item."""
    user_jwt = _user_jwt(app, "user-1", "user")
    res = importlib.import_module("app.api.resources")
    import app.services.rbac as rb

    fake_pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    monkeypatch.setitem(res.__dict__, "pool", fake_pool)
    monkeypatch.setitem(rb.__dict__, "pool", fake_pool)
    r = client.get(
        "/api/v1/clusters/0/resources/pods",
        headers={"Authorization": f"Bearer {user_jwt}"},
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_cluster_get_and_health_zero_short_circuit(app, client, monkeypatch) -> None:
    """The same short-circuit covers GET /clusters/0 (the synthetic row, no
    binding lookup) and /clusters/0/health (the admin client's readyz)."""
    admin_jwt = _user_jwt(app, "admin-2", "admin")
    h = {"Authorization": f"Bearer {admin_jwt}"}
    # GET /clusters/0 is GATED through the pool (the id:0 role branch): patch
    # kc.pool BEFORE the request so the handler's gate call hits the fake
    # (the clusters module resolves the module-level `kc.pool` at call time).
    import app.services.rbac as rb

    fake_pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    monkeypatch.setitem(kc.__dict__, "pool", fake_pool)
    monkeypatch.setitem(rb.__dict__, "pool", fake_pool)
    r = client.get("/api/v1/clusters/0", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["id"] == 0
    assert body["name"] == "local"
    # health: the module pool must route id 0 to the admin client.
    r2 = client.get("/api/v1/clusters/0/health", headers=h)
    assert r2.status_code == 200, r2.get_data(as_text=True)
    assert r2.get_json() == {"status": "up"}


def test_cluster_get_zero_404_for_non_admin(app, client, monkeypatch) -> None:
    """Non-admin GETs /api/v1/clusters/0: 404 CLUSTER_NOT_FOUND from the pool's
    ``id: 0`` role gate — the handler must go THROUGH ``pool.get`` (the gate)
    before answering, not return the synthetic row unconditionally (the brief's
    short-circuit constraint: 'Non-admin + id 0 → 404 CLUSTER_NOT_FOUND')."""
    user_jwt = _user_jwt(app, "user-2", "user")
    fake_pool = kc.K8sClientPool(admin_factory=FakeAdminK8s)
    monkeypatch.setitem(kc.__dict__, "pool", fake_pool)
    r = client.get(
        "/api/v1/clusters/0",
        headers={"Authorization": f"Bearer {user_jwt}"},
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_readyz_503_when_admin_kubeconfig_file_missing(app, monkeypatch, tmp_path) -> None:
    """KUBEDASH_ADMIN_KUBECONFIG → a missing file: /readyz is 503 naming
    admin-kubeconfig (the probe, I-NEW-6: an isfile check, not a re-resolver).

    The ``app`` fixture resets ``_config._settings`` BEFORE ``create_app``;
    setenv + reset AFTER the build still works because the readyz probe
    resolves ``get_settings()`` lazily at request time (I4)."""
    missing = tmp_path / "missing-kubeconfig.yaml"
    monkeypatch.setenv("KUBEDASH_ADMIN_KUBECONFIG", str(missing))
    _config._settings = None
    res = app.test_client().get("/readyz")
    assert res.status_code == 503
    assert "admin-kubeconfig" in res.get_data(as_text=True)


def test_readyz_ok_when_admin_kubeconfig_empty(client) -> None:
    """In-cluster mode (env empty): the admin-kubeconfig key is ABSENT from
    the readyz JSON — there is no file dependency to probe (absent, not ok)."""
    res = client.get("/readyz")
    body = res.get_json()
    assert "admin-kubeconfig" not in body
