"""User-management menus — ``GET /admin/groups`` (group → member_count,
dialect-portable across the sqlite api tier and PG).

Docker-free: the sqlite api tier (tests/api/conftest.py) seeds users with
OIDC groups claims directly; JWTs mint via ``security.issue_token_pair``
(the standard pattern in test_admin_users.py).

SATISFIES: the /groups admin view's data source (left-menu user-management
surface; non-admins get 403 RBAC_DENIED).
"""
from __future__ import annotations

import pytest


def _seed(api_client, api_app, sub: str, email: str, role: str,
          groups: list[str] | None = None) -> dict[str, str]:
    """Seed an ``auth_source='oidc'`` user (with an optional groups claim)
    and return a bearer header for it."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=email, role=role, groups=list(groups or []),
                 auth_source="oidc")
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def admin_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "sub-admin-g", "boss-g@local", "admin",
                 groups=["ops"])


@pytest.fixture()
def user_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "sub-user-g", "user-g@local", "user")


def test_admin_lists_groups_with_member_counts(api_client, api_app, admin_headers) -> None:
    """Every distinct group across all users, with the number of members
    in it, sorted by group name."""
    _seed(api_client, api_app, "sub-g-1", "g1@example.com", "user",
          groups=["dev", "platform"])
    _seed(api_client, api_app, "sub-g-2", "g2@example.com", "user", groups=["dev"])
    # sub-user-g (user_headers) has no groups — contributes nothing.

    r = api_client.get("/api/v1/admin/groups", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    assert r.get_json() == [
        {"group": "dev", "member_count": 2},
        {"group": "ops", "member_count": 1},
        {"group": "platform", "member_count": 1},
    ]


def test_groups_empty_when_no_user_has_any(api_client, api_app) -> None:
    """No users with groups → 200 with an empty list (not an error)."""
    headers = _seed(api_client, api_app, "sub-admin-eg", "eg@local", "admin")
    r = api_client.get("/api/v1/admin/groups", headers=headers)
    assert r.status_code == 200, r.get_json()
    assert r.get_json() == []


def test_non_admin_get_admin_groups_is_403(api_client, user_headers) -> None:
    r = api_client.get("/api/v1/admin/groups", headers=user_headers)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
