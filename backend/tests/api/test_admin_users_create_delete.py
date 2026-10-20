"""Users page (TASK-027) — create / delete a user + ``user_type`` on the list.

The /users surface matches the main-branch Users page: an admin can CREATE a
local-password user (``POST /admin/users``), DELETE one
(``DELETE /admin/users/<id>``), and the list carries ``user_type``
(Local / OIDC). The bootstrap ``local:`` admin and the caller themselves are
immutable (409, frozen ``CLUSTER_ALREADY_EXISTS``) — the same rule as
``patch_user``.

Docker-free: the sqlite api tier (tests/api/conftest.py); JWTs mint via
``security.issue_token_pair``.
"""
from __future__ import annotations

import pytest


def _seed(api_client, api_app, sub: str, email: str, role: str,
          groups: list[str] | None = None, auth_source: str = "oidc") -> dict[str, str]:
    """Seed a user and return a bearer header for it."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=email, role=role, groups=list(groups or []),
                 auth_source=auth_source)
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def admin_headers(api_client, api_app) -> dict[str, str]:
    """A NON-bootstrap local admin (sub does not start with 'local:'), so
    the immutability gate (keyed on the 'local:' prefix) does not fire."""
    return _seed(api_client, api_app, "adm-t27", "adm-t27@local", "admin",
                 auth_source="oidc")


@pytest.fixture()
def user_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "sub-u27", "u27@local", "user")


def _create(api_client, headers, body: dict):
    return api_client.post("/api/v1/admin/users", json=body, headers=headers)


def _user_id(api_app, sub: str) -> int:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        return db.session.execute(
            db.select(User.id).filter_by(sub=sub)
        ).scalar_one()


# --- user_type on the list -------------------------------------------------

def test_list_users_user_type_values(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-local", "sl@e", "user", auth_source="local")
    _seed(api_client, api_app, "sub-oidc", "so@e", "user", auth_source="oidc")
    out = api_client.get("/api/v1/admin/users", headers=admin_headers)
    assert out.status_code == 200
    rows = {u["sub"]: u["user_type"] for u in out.get_json()}
    assert rows["sub-local"] == "Local"
    assert rows["sub-oidc"] == "OIDC"


# --- POST /admin/users (create local-password user) ------------------------

def test_create_local_user_201(api_client, api_app, admin_headers) -> None:
    r = _create(api_client, admin_headers, {
        "username": "jdoe", "email": "jdoe@e", "password": "s3cret!", "role": "user",
    })
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["user_type"] == "Local"
    # The created user logs in with the password (ADR-0021 path).
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import verify_password
        from app.extensions import db
        from app.models.user import User

        u = db.session.execute(
            db.select(User).filter_by(email="jdoe@e")
        ).scalar_one()
        assert u.auth_source == "local"
        assert verify_password(u.password_hash, "s3cret!")


def test_create_user_duplicate_email_is_409(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-dup", "dup@e", "user", auth_source="oidc")
    r = _create(api_client, admin_headers, {
        "username": "dup2", "email": "dup@e", "password": "pw", "role": "user",
    })
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_create_user_blank_field_is_422(api_client, admin_headers) -> None:
    r = _create(api_client, admin_headers, {
        "username": "  ", "email": "b@e", "password": "pw", "role": "user",
    })
    assert r.status_code == 422
    r2 = _create(api_client, admin_headers, {
        "username": "b2", "email": "b2@e", "password": "", "role": "user",
    })
    assert r2.status_code == 422


def test_create_user_bad_role_is_422(api_client, api_app, admin_headers) -> None:
    r = _create(api_client, admin_headers, {
        "username": "c", "email": "c@e", "password": "pw", "role": "superuser",
    })
    assert r.status_code == 422


def test_create_user_non_admin_is_403(api_client, user_headers) -> None:
    r = _create(api_client, user_headers, {
        "username": "n", "email": "n@e", "password": "pw", "role": "user",
    })
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


# --- DELETE /admin/users/<id> ----------------------------------------------

def test_delete_user_200_cascades(api_client, api_app, admin_headers) -> None:
    uid = _user_id(api_app, "sub-del") if _exists(api_app, "sub-del") else _seed_del(api_client, api_app)
    r = api_client.delete(f"/api/v1/admin/users/{uid}", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    # Gone: a re-list does not contain the sub.
    out = api_client.get("/api/v1/admin/users", headers=admin_headers)
    assert all(u["sub"] != "sub-del" for u in out.get_json())


def _exists(api_app, sub: str) -> bool:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        return db.session.execute(
            db.select(User.id).filter_by(sub=sub)
        ).scalar_one_or_none() is not None


def _seed_del(api_client, api_app) -> int:
    h = _seed(api_client, api_app, "sub-del", "del@e", "user", auth_source="oidc")  # noqa: F841
    return _user_id(api_app, "sub-del")


def test_delete_bootstrap_admin_is_409(api_client, api_app) -> None:
    """A 'local:' admin (the bootstrap convention) is immutable — a DELETE
    is a 409. The api-tier app skips the PG-dialect bootstrap hook, so the
    local: row is seeded directly (its sub carries the reserved 'local:'
    prefix the gate keys on)."""
    _seed(api_client, api_app, "local:boot@local", "boot@local", "admin",
          auth_source="local")
    uid = _user_id(api_app, "local:boot@local")
    headers = _seed(api_client, api_app, "adm-del", "adm-del@local", "admin",
                    auth_source="oidc")
    r = api_client.delete(f"/api/v1/admin/users/{uid}", headers=headers)
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_delete_self_is_409(api_client, api_app, admin_headers) -> None:
    """An admin cannot delete their own account."""
    uid = _user_id(api_app, "adm-t27")
    r = api_client.delete(f"/api/v1/admin/users/{uid}", headers=admin_headers)
    assert r.status_code == 409


def test_delete_unknown_user_is_404(api_client, admin_headers) -> None:
    r = api_client.delete("/api/v1/admin/users/999999", headers=admin_headers)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_delete_user_non_admin_is_403(api_client, api_app, user_headers) -> None:
    uid = _user_id(api_app, "sub-u27")
    r = api_client.delete(f"/api/v1/admin/users/{uid}", headers=user_headers)
    assert r.status_code == 403
