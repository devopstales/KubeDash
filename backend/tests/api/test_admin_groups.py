"""Admin-managed groups (TASK-026) — CRUD API + membership.

The ``/groups`` admin surface stores groups as first-class rows: an admin
creates a group (POST), lists stored ∪ claim groups (GET), assigns /
unassigns users (POST/DELETE members), deletes a group (DELETE). The
frozen v1 error contract is followed: 409 CLUSTER_ALREADY_EXISTS for a
duplicate name (the frozen 409 code; the message names the restriction),
404 RESOURCE_KIND_NOT_FOUND-style 404 via ResourceKindNotSupportedError
for unknown user/group, 403 RBAC_DENIED for non-admins.

Docker-free: the sqlite api tier (tests/api/conftest.py).
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
    return _seed(api_client, api_app, "sub-admin-g", "boss-g@local", "admin")


@pytest.fixture()
def user_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "sub-user-g", "user-g@local", "user")


def _create(api_client, headers, name: str):
    return api_client.post(
        "/api/v1/admin/groups",
        json={"name": name},
        headers=headers,
    )


def test_create_group_201(api_client, admin_headers) -> None:
    r = _create(api_client, admin_headers, "platform")
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["name"] == "platform"
    assert body["member_count"] == 0


def test_create_group_duplicate_is_409_frozen_code(api_client, admin_headers) -> None:
    assert _create(api_client, admin_headers, "ops").status_code == 201
    r = _create(api_client, admin_headers, "ops")
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_create_group_non_admin_is_403(api_client, user_headers) -> None:
    r = _create(api_client, user_headers, "ops")
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_create_group_blank_name_is_422(api_client, admin_headers) -> None:
    r = _create(api_client, admin_headers, "   ")
    assert r.status_code == 422


def test_list_groups_merges_stored_and_claim_groups(api_client, api_app, admin_headers) -> None:
    """GET lists stored rows ∪ claim groups; member_count = distinct users
    that have the group via EITHER source."""
    # user A: stored member of "platform" (via assign below) + claim "devs"
    _seed(api_client, api_app, "sub-merge-A", "a@e", "user", groups=["devs"])
    # user B: claim "devs" only
    _seed(api_client, api_app, "sub-merge-B", "b@e", "user", groups=["devs"])
    # stored group "platform" with no claim anywhere
    assert _create(api_client, admin_headers, "platform").status_code == 201
    # assign A to "platform"
    r = api_client.post(
        "/api/v1/admin/groups/platform/members",
        json={"user_sub": "sub-merge-A"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()

    out = api_client.get("/api/v1/admin/groups", headers=admin_headers)
    assert out.status_code == 200
    got = {g["group"]: g["member_count"] for g in out.get_json()}
    assert got == {
        "platform": 1,  # A via stored membership
        "devs": 2,      # A + B via claim
    }


def test_get_admin_users_groups_merge_stored_and_claim(api_client, api_app, admin_headers) -> None:
    """GET /admin/users: ``groups`` = stored ∪ claim, deduped + sorted."""
    _seed(api_client, api_app, "sub-u26-A", "a26@e", "user", groups=["devs", "zeta"])
    _create(api_client, admin_headers, "platform")
    api_client.post(
        "/api/v1/admin/groups/platform/members",
        json={"user_sub": "sub-u26-A"},
        headers=admin_headers,
    )
    out = api_client.get("/api/v1/admin/users", headers=admin_headers)
    assert out.status_code == 200
    row = next(u for u in out.get_json() if u["sub"] == "sub-u26-A")
    assert row["groups"] == ["devs", "platform", "zeta"]


def test_assign_member_200_idempotent(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-assign-u", "au@e", "user")
    _create(api_client, admin_headers, "team")
    for _ in range(2):
        r = api_client.post(
            "/api/v1/admin/groups/team/members",
            json={"user_sub": "sub-assign-u"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.get_json()


def test_assign_unknown_user_is_404(api_client, api_app, admin_headers) -> None:
    _create(api_client, admin_headers, "team")
    r = api_client.post(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-ghost"},
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_assign_unknown_group_is_404(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-assign-u2", "au2@e", "user")
    r = api_client.post(
        "/api/v1/admin/groups/ghost/members",
        json={"user_sub": "sub-assign-u2"},
        headers=admin_headers,
    )
    assert r.status_code == 404


def test_assign_non_admin_is_403(api_client, api_app, user_headers) -> None:
    _seed(api_client, api_app, "sub-assign-u3", "au3@e", "user")
    r = api_client.post(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-assign-u3"},
        headers=user_headers,
    )
    assert r.status_code == 403


def test_unassign_member_200_then_404(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-unassign-u", "un@e", "user")
    _create(api_client, admin_headers, "team")
    api_client.post(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-unassign-u"},
        headers=admin_headers,
    )
    r = api_client.delete(
        "/api/v1/admin/groups/team/members/sub-unassign-u", headers=admin_headers
    )
    assert r.status_code == 200, r.get_json()
    # A second unassign is a 404 (the membership row is gone).
    r2 = api_client.delete(
        "/api/v1/admin/groups/team/members/sub-unassign-u", headers=admin_headers
    )
    assert r2.status_code == 404


def test_unassign_non_admin_is_403(api_client, user_headers) -> None:
    r = api_client.delete(
        "/api/v1/admin/groups/team/members/sub-x", headers=user_headers
    )
    assert r.status_code == 403


def test_delete_group_200_cascades_members(api_client, api_app, admin_headers) -> None:
    _seed(api_client, api_app, "sub-del-u", "du@e", "user")
    _create(api_client, admin_headers, "team")
    api_client.post(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-del-u"},
        headers=admin_headers,
    )
    r = api_client.delete("/api/v1/admin/groups/team", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    # The group is gone (a re-create succeeds; the old membership is with it).
    assert _create(api_client, admin_headers, "team").status_code == 201
    # Unassigning a (now non-existent) membership is a 404.
    r2 = api_client.delete(
        "/api/v1/admin/groups/team/members/sub-del-u", headers=admin_headers
    )
    assert r2.status_code == 404


def test_delete_unknown_group_is_404(api_client, admin_headers) -> None:
    r = api_client.delete("/api/v1/admin/groups/ghost", headers=admin_headers)
    assert r.status_code == 404


def test_delete_group_non_admin_is_403(api_client, user_headers) -> None:
    r = api_client.delete("/api/v1/admin/groups/whatever", headers=user_headers)
    assert r.status_code == 403
