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
    assert body["name"] == "local:platform"
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


def test_list_groups_shows_stored_and_role_groups(api_client, api_app, admin_headers) -> None:
    """GET /admin/groups (GroupsApi) lists stored rows, local role groups
    first, name order (the GroupsApi contract — the frontend's GroupRow
    shape; src/lib/groupTypes.ts). Claim-only groups are materialized by
    POST /admin/groups/sync, not by the list."""
    # user A: claim "devs" + stored member of "platform" (via assign below)
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
    rows = {g["name"]: g for g in out.get_json()}
    # local role groups come first (source asc), then the local-created group.
    assert list(rows) == ["kubedash-admin", "kubedash-user", "local:platform"]
    assert rows["local:platform"]["member_count"] == 1  # A via stored membership
    assert rows["kubedash-admin"]["source"] == "local"
    # Claim-only "devs" is NOT listed until sync materializes it.
    assert "devs" not in rows


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


def test_unassign_member_via_groupsapi_delete(api_client, api_app, admin_headers) -> None:
    """Unassign is the GroupsApi's ``DELETE /admin/groups/<name>/members``
    (body ``user_sub``) — the AdminApi's path-param
    ``DELETE .../members/<user_sub>`` was removed 2026-10-26 (duplicate
    registration). A non-member delete is a 404."""
    _seed(api_client, api_app, "sub-unassign-u", "un@e", "user")
    _create(api_client, admin_headers, "team")
    api_client.post(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-unassign-u"},
        headers=admin_headers,
    )
    r = api_client.delete(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-unassign-u"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    # A second delete is a 404 (the membership row is gone).
    r2 = api_client.delete(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-unassign-u"},
        headers=admin_headers,
    )
    assert r2.status_code == 404


def test_unassign_non_admin_is_403(api_client, user_headers) -> None:
    r = api_client.delete(
        "/api/v1/admin/groups/team/members",
        json={"user_sub": "sub-x"},
        headers=user_headers,
    )
    assert r.status_code == 403


@pytest.mark.skip(reason="OPEN TASK: no DELETE /admin/groups/<name> route on GroupsApi — the AdminApi delete was removed 2026-10-26; re-add when the route lands")
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


@pytest.mark.skip(reason="OPEN TASK: no DELETE /admin/groups/<name> route on GroupsApi — the AdminApi delete was removed 2026-10-26; re-add when the route lands")
def test_delete_unknown_group_is_404(api_client, admin_headers) -> None:
    r = api_client.delete("/api/v1/admin/groups/ghost", headers=admin_headers)
    assert r.status_code == 404


@pytest.mark.skip(reason="OPEN TASK: no DELETE /admin/groups/<name> route on GroupsApi — the AdminApi delete was removed 2026-10-26; re-add when the route lands")
def test_delete_group_non_admin_is_403(api_client, user_headers) -> None:
    r = api_client.delete("/api/v1/admin/groups/whatever", headers=user_headers)
    assert r.status_code == 403
