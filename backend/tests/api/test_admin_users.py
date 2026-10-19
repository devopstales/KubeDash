"""TICKET-04 — admin user management API: ``GET /admin/users`` +
``PATCH /admin/users/<id>`` (role/status, audit, bootstrap-admin 409).

Docker-free: the sqlite api tier (tests/api/conftest.py) seeds local users
directly and mints JWTs via ``security.issue_token_pair`` (the standard
pattern in test_clusters_admin.py). The bootstrap-admin row is created with
the same PG hook the PG tier uses where the dialect allows, or seeded
directly with the hook's exact sub convention (``local:<email>``).

SATISFIES:
admin-lists-and-patches-a-user;
bootstrap-admin-cannot-be-demotion-or-disabled;
non-admin-cannot-reach-admin-users.
"""
from __future__ import annotations

import pytest


def _seed(api_client, api_app, sub: str, email: str, role: str,
          password_hash: str | None = None) -> dict[str, str]:
    """Seed an ``auth_source='oidc'`` user directly and return a bearer
    header for it. The oidc marker keeps the row out of the bootstrap
    immutability gate (``auth_source == 'local'``)."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=email, role=role, auth_source="oidc",
                 password_hash=password_hash)
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


def _seed_bootstrap_admin(api_client, api_app) -> dict[str, str]:
    """Seed the bootstrap ``local:`` admin row the way the PG tier's
    ``_bootstrap_local_admin`` hook does (the sqlite tier skips the hook —
    C-NEW-1) and mint a JWT for it. ``auth_source='local'`` is the
    immutability marker."""
    from app.core.security import hash_password

    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(
            sub="local:admin@local",
            email="admin@local",
            display_name="admin",
            role="admin",
            auth_source="local",
            password_hash=hash_password("correct-horse"),
        )
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def admin_headers(api_client, api_app) -> dict[str, str]:
    """An admin (oidc marker — NOT the immutable bootstrap row), so the
    patch tests can mutate other users without tripping the immutability
    gate on the actor's own row."""
    return _seed(api_client, api_app, "sub-admin-1", "boss@local", "admin")


@pytest.fixture()
def user_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "sub-user-1", "user@local", "user")


def test_admin_lists_users_with_cluster_count(api_client, api_app, admin_headers, user_headers) -> None:
    """SATISFIES admin-lists-and-patches-a-user (list half).

    The admin sees EVERY user (sub, role, status, cluster_count). The
    cluster_count is the number of user-management (template-scoped)
    bindings — the legacy auto-bind row (template=None) from cluster
    registration does NOT count.
    """
    # Legacy auto-bind (template=None): does not count toward cluster_count.
    _register_cluster(api_client, api_app, user_headers, "prod")
    # A template-scoped permission binding: counts.
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.binding import ClusterBinding
        from app.models.cluster import Cluster
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub="sub-user-1")).scalar_one()
        c = db.session.execute(db.select(Cluster).filter_by(name="prod")).scalar_one()
        db.session.add(ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer",
                                      namespace="team-a", template="viewer"))
        db.session.commit()
    r = api_client.get("/api/v1/admin/users", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    subs = {u["sub"] for u in body}
    assert "sub-admin-1" in subs
    assert "sub-user-1" in subs
    by_sub = {u["sub"]: u for u in body}
    # Exactly 1 (the template-scoped row); the legacy auto-bind row is not
    # a permission binding.
    assert by_sub["sub-user-1"]["cluster_count"] == 1
    assert by_sub["sub-admin-1"]["cluster_count"] == 0
    assert by_sub["sub-user-1"]["role"] == "user"
    assert by_sub["sub-user-1"]["status"] == "active"


def test_non_admin_get_admin_users_is_403(api_client, user_headers) -> None:
    """SATISFIES non-admin-cannot-reach-admin-users.

    Red against the stub: the route 501s (the gate is not there yet); the
    assertion pins the real gate's contract (403 RBAC_DENIED, not the 501).
    """
    r = api_client.get("/api/v1/admin/users", headers=user_headers)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_admin_patches_user_role_and_audits(api_client, api_app, admin_headers, user_headers) -> None:
    """SATISFIES admin-lists-and-patches-a-user (patch + audit half)."""
    user_id = _user_id(api_app, "sub-user-1")
    r = api_client.patch(f"/api/v1/admin/users/{user_id}", json={"role": "admin"}, headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.audit import AuditLog
        from app.models.user import User

        u = db.session.execute(
            db.select(User).filter_by(sub="sub-user-1")
        ).scalar_one()
        assert u.role == "admin"
        audit = db.session.execute(
            db.select(AuditLog).filter_by(action="role_change", actor_sub="sub-admin-1")
        ).scalar_one()
        assert audit.target == "sub-user-1"


def test_admin_patches_user_status_disabled_next_call_401(
    api_client, api_app, admin_headers, user_headers
) -> None:
    """A disabled user's next authenticated call is 401 UNAUTHORIZED (Task 3
    gate at _load_user_for_claims)."""
    user_id = _user_id(api_app, "sub-user-1")
    r = api_client.patch(f"/api/v1/admin/users/{user_id}", json={"status": "disabled"}, headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    r2 = api_client.get("/api/v1/auth/me", headers=user_headers)
    assert r2.status_code == 401
    assert r2.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_bootstrap_admin_role_change_is_409(api_client, api_app, admin_headers) -> None:
    """SATISFIES bootstrap-admin-cannot-be-demotion-or-disabled (role half).

    The bootstrap ``local:`` admin is immutable: role PATCH → 409
    ClusterAlreadyExistsError (the stable 409; the message names the
    restriction). The row keeps its admin role.
    """
    _seed_bootstrap_admin(api_client, api_app)  # the immutable bootstrap row
    bootstrap_sub = "local:admin@local"
    user_id = _user_id(api_app, bootstrap_sub)
    r = api_client.patch(f"/api/v1/admin/users/{user_id}", json={"role": "user"}, headers=admin_headers)
    assert r.status_code == 409, r.get_json()
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub=bootstrap_sub)).scalar_one()
        assert u.role == "admin"  # unchanged


def test_bootstrap_admin_status_change_is_409(api_client, api_app, admin_headers) -> None:
    """SATISFIES bootstrap-admin-cannot-be-demotion-or-disabled (status half)."""
    _seed_bootstrap_admin(api_client, api_app)
    bootstrap_sub = "local:admin@local"
    user_id = _user_id(api_app, bootstrap_sub)
    r = api_client.patch(f"/api/v1/admin/users/{user_id}", json={"status": "disabled"}, headers=admin_headers)
    assert r.status_code == 409, r.get_json()
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub=bootstrap_sub)).scalar_one()
        assert u.status == "active"  # unchanged


def test_patch_unknown_user_is_404(api_client, api_app, admin_headers) -> None:
    r = api_client.patch("/api/v1/admin/users/9999", json={"role": "user"}, headers=admin_headers)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_patch_invalid_role_is_422(api_client, api_app, admin_headers, user_headers) -> None:
    user_id = _user_id(api_app, "sub-user-1")
    r = api_client.patch(f"/api/v1/admin/users/{user_id}", json={"role": "boss"}, headers=admin_headers)
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"


def _user_id(api_app, sub: str) -> int:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        return db.session.execute(db.select(User).filter_by(sub=sub)).scalar_one().id


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


def _register_cluster(api_client, api_app, headers: dict[str, str], name: str) -> object:
    """Register a cluster as the header's user (auto-binds them as admin)."""
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
