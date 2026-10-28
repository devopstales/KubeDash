"""TICKET-16 (ADR-0021): the synthetic ``local`` cluster in the list + the
``me`` response growth.

Docker-free api tier: two local users are seeded directly (role ``admin`` /
``user``, ``auth_source='local'``) and JWTs are minted via
``security.issue_token_pair`` — the standard pattern in ``test_auth.py`` /
``test_local_auth.py`` (direct seed + mint + ``Authorization: Bearer``).

SATISFIES: admin-sees-local-cluster-from-config (T6, T8 — the list half),
profile-page-shows-identity (backend half: the ``me`` fields the Profile page
renders).
"""
from __future__ import annotations

import os
import pathlib
import tempfile
from datetime import UTC, datetime

import pytest

# A minimal kubeconfig the kubernetes client can load (same constant shape as
# tests/api/test_clusters.py; the fake client never dials).
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


def _seed(api_client, api_app, sub: str, email: str, role: str, last_login: datetime | None = None):
    """Seed a local user directly and return a bearer header for it."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=email, role=role, auth_source="local")
        if last_login is not None:
            u.last_login_at = last_login
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def client_admin(api_client, api_app):
    """An admin local user, minted (last_login_at seeded explicitly)."""
    api_client.h_admin = _seed(
        api_client, api_app, "local:admin@local", "admin@local", "admin",
        last_login=datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC),
    )
    return api_client


@pytest.fixture()
def client_user(api_client, api_app):
    """A non-admin local user, minted."""
    api_client.h_user = _seed(api_client, api_app, "local:user@local", "user@local", "user")
    return api_client


def _register(api_client, headers, name="prod") -> object:
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


# ---------------------------------------------------------------------------
# The synthetic local cluster in the LIST (admin-sees-local-cluster-from-config)
# ---------------------------------------------------------------------------


def test_admin_sees_synthetic_local_cluster_exactly_once(client_admin, monkeypatch) -> None:
    # Setup: the admin registers one registry cluster (auto-bind makes it
    # visible). The list must then carry exactly ONE synthetic admin entry.
    client = client_admin
    # Isolate: no default kubeconfig → in-cluster source (deterministic).
    monkeypatch.setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-test")
    r = _register(client, client.h_admin)
    assert r.status_code == 201, r.get_json()
    items = client.get("/api/v1/clusters", headers=client.h_admin).get_json()
    locals_ = [i for i in items if i.get("source") == "admin"]
    assert len(locals_) == 1
    assert locals_[0]["id"] == 0
    assert locals_[0]["name"] == "local"
    # I13: the synthetic api_server reflects the RESOLVED source — "in-cluster"
    # when admin_kubeconfig is empty AND no default kubeconfig, else the file
    # path. Status is probed (up/down), not None.
    from app.core.config import get_settings
    from app.services.k8s_client import resolve_admin_source

    s = get_settings()
    src = resolve_admin_source(s)
    if src == "kubeconfig-file":
        expected = s.admin_kubeconfig
    elif src == "local-kubeconfig":
        import os

        expected = os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))
    else:
        expected = "in-cluster"
    assert locals_[0]["api_server"] == expected
    assert locals_[0]["status"] in {"up", "down"}
    # The registered registry row is present and marked "registry".
    registries = [i for i in items if i.get("source") == "registry"]
    assert len(registries) == 1
    assert registries[0]["name"] == "prod"
    assert registries[0]["id"] != 0


def test_admin_list_with_admin_kubeconfig_shows_path(client_admin, monkeypatch) -> None:
    """I13: in kubeconfig-file mode the synthetic api_server is the FILE PATH
    (the resolved value), not the resolve_admin_source literal. Status is
    probed (up/down), not None."""
    client = client_admin
    monkeypatch.setenv("KUBEDASH_ADMIN_KUBECONFIG", "/etc/kubedash/admin.kubeconfig")
    import app.core.config as _config

    _config._settings = None  # the Settings singleton caches from ENV
    items = client.get("/api/v1/clusters", headers=client.h_admin).get_json()
    locals_ = [i for i in items if i.get("source") == "admin"]
    assert len(locals_) == 1
    assert locals_[0]["api_server"] == "/etc/kubedash/admin.kubeconfig"
    assert locals_[0]["status"] in {"up", "down"}


def test_non_admin_list_unchanged_shape(client_user) -> None:
    # No synthetic entry for non-admins; every item is a registry row.
    client = client_user
    r = _register(client, client.h_user, name="mine")
    assert r.status_code == 201, r.get_json()
    items = client.get("/api/v1/clusters", headers=client.h_user).get_json()
    assert items  # the registered one is visible
    assert all(i.get("source") == "registry" for i in items)
    assert not any(i["id"] == 0 for i in items)


def test_admin_single_row_routes_unchanged_shape(client_admin, monkeypatch) -> None:
    """Regression: the single-row id:0 routes (GET /clusters/0) keep the
    literal api_server="local" display (only the LIST entry uses the resolved
    source — I13 is scoped to the list). The gate call goes through the
    pool's id:0 branch, so the fake admin factory stands in for the k8s
    world (same seam as the Task 3 tests)."""
    import app.services.k8s_client as kc

    class _FakeAdmin:
        def list_pods(self, namespace=None):
            return []

        def readyz(self):
            return True

    monkeypatch.setitem(
        kc.__dict__,
        "pool",
        kc.K8sClientPool(admin_factory=lambda s: _FakeAdmin()),
    )
    client = client_admin
    r = client.get("/api/v1/clusters/0", headers=client.h_admin)
    assert r.status_code == 200
    body = r.get_json()
    assert body["id"] == 0
    assert body["name"] == "local"
    assert body["api_server"] == "local"


# ---------------------------------------------------------------------------
# The me response growth (profile-page-shows-identity, backend half)
# ---------------------------------------------------------------------------


def test_admin_me_includes_kubeconfig_source(client_admin, monkeypatch) -> None:
    client = client_admin
    monkeypatch.setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-test")
    me = client.get("/api/v1/auth/me", headers=client.h_admin).get_json()
    assert me["role"] == "admin"
    assert me["auth_source"] == "local"
    assert me["kubeconfig_source"] in {"in-cluster", "kubeconfig-file", "local-kubeconfig"}
    assert "last_login_at" in me
    # The seeded value is echoed (the column exists and is read, not
    # invented) — the UTC instant 2026-10-18T12:00:00, the wire form.
    assert me["last_login_at"] == "2026-10-18T12:00:00"


def test_admin_me_kubeconfig_source_follows_config(client_admin, monkeypatch) -> None:
    """kubeconfig_source is the resolve_admin_source() value for admins — it
    tracks the resolved source, not a fixed literal."""
    client = client_admin
    monkeypatch.setenv("KUBEDASH_ADMIN_KUBECONFIG", "/etc/kubedash/admin.kubeconfig")
    import app.core.config as _config

    _config._settings = None
    me = client.get("/api/v1/auth/me", headers=client.h_admin).get_json()
    assert me["kubeconfig_source"] == "kubeconfig-file"


def test_user_me_kubeconfig_source_null(client_user) -> None:
    client = client_user
    me = client.get("/api/v1/auth/me", headers=client.h_user).get_json()
    assert me["role"] == "user"
    assert me["auth_source"] == "local"
    assert me["kubeconfig_source"] is None
    assert me["last_login_at"] is None


# ---------------------------------------------------------------------------
# kind integration tier (env-blocked locally; CI backstop) — the Task 3
# short-circuit routes 0 → admin source; the list + pod paths compose it.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_admin_pod_list_via_local_cluster(api_client, api_app, kind_cluster) -> None:
    """The admin's GET /clusters/0/resources/pods returns the kind pods
    (pool id:0 branch → admin client → SAR as usual); the non-admin gets the
    stable 404 CLUSTER_NOT_FOUND (the role gate).

    The admin source is the kind kubeconfig itself: point
    KUBEDASH_ADMIN_KUBECONFIG at a temp copy of it (kubeconfig-file mode).
    """
    import app.core.config as _config
    import app.services.rbac as rb

    tmp_path = (
        pathlib.Path(tempfile.gettempdir()) / f"kubedash-admin-{os.getpid()}.kubeconfig"
    )
    tmp_path.write_bytes(kind_cluster)
    _config._settings = None
    # Re-seed: settings changed after the pool/app were built.
    h_admin = _seed(api_client, api_app, "local:admin@local", "admin@local", "admin")
    h_user = _seed(api_client, api_app, "local:user@local", "user@local", "user")
    try:
        os.environ["KUBEDASH_ADMIN_KUBECONFIG"] = str(tmp_path)
        _config._settings = None

        orig_get, orig_set = rb._cache_get, rb._cache_set
        rb._cache_get, rb._cache_set = (lambda e, k: None, lambda e, k, v: None)
        try:
            r = api_client.get("/api/v1/clusters/0/resources/pods", headers=h_admin)
        finally:
            rb._cache_get, rb._cache_set = orig_get, orig_set
        assert r.status_code == 200, r.get_json()
        names = [p["metadata"]["name"] for p in r.get_json()["items"]]
        assert "kubedash-pod" in names
        r = api_client.get("/api/v1/clusters/0/resources/pods", headers=h_user)
        assert r.status_code == 404
        assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"
    finally:
        tmp_path.unlink(missing_ok=True)
        os.environ.pop("KUBEDASH_ADMIN_KUBECONFIG", None)
        _config._settings = None
