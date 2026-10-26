"""Groups API: list / detail / sync / members / privilege bind+unbind.

Same docker-free sqlite api tier as test_permissions.py — local users are
seeded directly + JWTs minted; the k8s world is a FakeK8s double injected
via the pool's ``factory`` kwarg. Group privilege bind reuses the
permissions FakeK8s (subject_kind="Group" applies a k8s Group subject).
"""
from __future__ import annotations

from typing import Any

import pytest

from tests.api.test_permissions import (
    KUBECONFIG,  # noqa: F401  (re-exported for future group cluster tests)
    FakeK8s,
    _cluster_name,
    _register_cluster,
    _seed,
    _seed_template,
)

# Module-level fixture import: pytest discovers fixtures in the imported
# module's namespace (admin_headers / user_headers live in test_permissions).
from tests.api.test_permissions import (  # noqa: F401
    admin_headers,
    user_headers,
)

RULES_NS = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
RULES_CLUSTER = [{"api_groups": [""], "resources": ["nodes"], "verbs": ["get"]}]
NS = "team-a"


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> dict[str, bool]:
    """Same seam as test_permissions.fake_k8s — a fresh pool per test."""
    import app.services.k8s_client as kc

    state = {"unreachable": False}

    def factory(plain: bytes) -> FakeK8s:
        return FakeK8s(state["unreachable"])

    monkeypatch.setitem(kc.__dict__, "pool", kc.K8sClientPool(factory=factory))
    return state


def _seed_group(api_app, name: str, source: str = "oidc") -> None:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.group import Group

        db.session.add(Group(name=name, source=source))
        db.session.commit()


def _seed_user(api_app, sub: str) -> int:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=f"{sub}@example.com", auth_source="oidc")
        db.session.add(u)
        db.session.commit()
        return u.id


def test_default_local_groups_follow_permission_roles(
    api_client, api_app, admin_headers
) -> None:
    """kubedash-admin / kubedash-user are local groups. Membership follows
    the user permission role: admin → kubedash-admin, user → kubedash-user."""
    _seed_user(api_app, "oidc-member")
    r = api_client.get("/api/v1/admin/groups", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    by_name = {g["name"]: g for g in r.get_json()}
    assert by_name["kubedash-admin"]["source"] == "local"
    assert by_name["kubedash-user"]["source"] == "local"

    admin = api_client.get(
        "/api/v1/admin/groups/kubedash-admin", headers=admin_headers
    ).get_json()
    user = api_client.get(
        "/api/v1/admin/groups/kubedash-user", headers=admin_headers
    ).get_json()
    admin_subs = [m["sub"] for m in admin["members"]]
    user_subs = [m["sub"] for m in user["members"]]
    assert "local:admin@local" in admin_subs
    assert "oidc-member" not in admin_subs
    assert "oidc-member" in user_subs
    assert "local:admin@local" not in user_subs


def test_permission_change_moves_role_group(
    api_client, api_app, admin_headers
) -> None:
    """PATCH role admin moves the user from kubedash-user to kubedash-admin."""
    _seed_user(api_app, "oidc-mover")
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        user_id = db.session.execute(
            db.select(User.id).filter_by(sub="oidc-mover")
        ).scalar_one()
    api_client.get("/api/v1/admin/groups", headers=admin_headers)
    r = api_client.patch(
        f"/api/v1/admin/users/{user_id}",
        json={"role": "admin"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    admin = api_client.get(
        "/api/v1/admin/groups/kubedash-admin", headers=admin_headers
    ).get_json()
    user = api_client.get(
        "/api/v1/admin/groups/kubedash-user", headers=admin_headers
    ).get_json()
    assert "oidc-mover" in [m["sub"] for m in admin["members"]]
    assert "oidc-mover" not in [m["sub"] for m in user["members"]]


def test_admin_lists_groups(api_client, api_app, admin_headers) -> None:
    _seed_group(api_app, "devs2")
    _seed_group(api_app, "local:ops", source="local")
    r = api_client.get("/api/v1/admin/groups", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    names = [g["name"] for g in r.get_json()]
    # local first (role groups, then dashboard groups), then OpenID, each alphabetical.
    assert names == ["kubedash-admin", "kubedash-user", "local:ops", "devs2"]
    by_name = {g["name"]: g for g in r.get_json()}
    assert by_name["devs2"]["member_count"] == 0
    assert by_name["local:ops"]["member_count"] == 0
    assert by_name["kubedash-admin"]["source"] == "local"


def test_user_cannot_list_groups(api_client, api_app, user_headers) -> None:
    r = api_client.get("/api/v1/admin/groups", headers=user_headers)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_group_detail_includes_members(api_client, api_app, admin_headers) -> None:
    _seed_group(api_app, "devs2")
    _seed_user(api_app, "sub-dev-1")
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.group import Group, GroupMember
        from app.models.user import User

        group = db.session.execute(db.select(Group).filter_by(name="devs2")).scalar_one()
        user = db.session.execute(db.select(User).filter_by(sub="sub-dev-1")).scalar_one()
        db.session.add(GroupMember(user_id=user.id, group_id=group.id))
        db.session.commit()
    r = api_client.get("/api/v1/admin/groups/devs2", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["name"] == "devs2"
    assert body["member_count"] == 1
    assert [m["sub"] for m in body["members"]] == ["sub-dev-1"]


def test_group_detail_404_when_missing(api_client, api_app, admin_headers) -> None:
    r = api_client.get("/api/v1/admin/groups/nope", headers=admin_headers)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_sync_materializes_memberships_from_claims(
    api_client, api_app, admin_headers
) -> None:
    _seed_user(api_app, "sub-sync-1")
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub="sub-sync-1")).scalar_one()
        u.groups = ["devs2", "sre"]
        db.session.commit()
    r = api_client.post("/api/v1/admin/groups/sync", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["created_members"] == 2
    # Second sync is a no-op (idempotent upsert).
    r2 = api_client.post("/api/v1/admin/groups/sync", headers=admin_headers)
    assert r2.status_code == 200
    assert r2.get_json()["created_members"] == 0
    names = [g["name"] for g in api_client.get("/api/v1/admin/groups", headers=admin_headers).get_json()]
    assert names == ["kubedash-admin", "kubedash-user", "devs2", "sre"]


def test_create_manual_group_and_name_collision(
    api_client, api_app, admin_headers
) -> None:
    r = api_client.post(
        "/api/v1/admin/groups", json={"name": "ops"}, headers=admin_headers
    )
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["name"] == "local:ops"
    assert r.get_json()["source"] == "local"
    r2 = api_client.post(
        "/api/v1/admin/groups", json={"name": "ops"}, headers=admin_headers
    )
    assert r2.status_code == 409
    assert r2.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_create_manual_group_whitespace_name_is_rejected(
    api_client, api_app, admin_headers
) -> None:
    """A whitespace-only display name is blank after strip — it must 422,
    not create a nameless ``local:  `` group (regression: the blank-name
    rows that appeared on /user/group)."""
    r = api_client.post(
        "/api/v1/admin/groups", json={"name": "   "}, headers=admin_headers
    )
    assert r.status_code == 422, r.get_json()
    # No group was created.
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.group import Group

        row = db.session.execute(
            db.select(Group).filter(Group.name.in_(["local:", "local:   "]))
        ).scalars().first()
        assert row is None


def test_add_and_remove_group_member(api_client, api_app, admin_headers) -> None:
    _seed_group(api_app, "devs2")
    _seed_user(api_app, "sub-mem-2")
    r = api_client.post(
        "/api/v1/admin/groups/devs2/members",
        json={"user_sub": "sub-mem-2"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    # Idempotent re-add.
    r = api_client.post(
        "/api/v1/admin/groups/devs2/members",
        json={"user_sub": "sub-mem-2"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = api_client.get("/api/v1/admin/groups/devs2", headers=admin_headers).get_json()
    assert body["member_count"] == 1
    r = api_client.delete(
        "/api/v1/admin/groups/devs2/members",
        json={"user_sub": "sub-mem-2"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    body = api_client.get("/api/v1/admin/groups/devs2", headers=admin_headers).get_json()
    assert body["member_count"] == 0
    # Removing a non-member is a 404.
    r = api_client.delete(
        "/api/v1/admin/groups/devs2/members",
        json={"user_sub": "sub-mem-2"},
        headers=admin_headers,
    )
    assert r.status_code == 404


def test_group_privilege_bind_and_unbind(
    api_client, api_app, admin_headers, fake_k8s
) -> None:
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed_group(api_app, "devs2")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/groups/devs2/privileges",
        json={
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    assert ("apply_role", NS, "kubedash-viewer") in FakeK8s.last.calls
    assert (
        "apply_role_binding", NS, "kubedash-devs2-team-a", "kubedash-viewer", "devs2"
    ) in FakeK8s.last.calls
    # The binding row is stored under the group id (subject-agnostic table).
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.binding import ClusterBinding
        from app.models.group import Group

        group = db.session.execute(db.select(Group).filter_by(name="devs2")).scalar_one()
        row = db.session.execute(
            db.select(ClusterBinding).filter_by(user_id=group.id, namespace=NS)
        ).scalar_one()
        assert row.namespace == NS and row.template == "viewer"
    # GET privileges lists the binding (legacy rows — template None — are
    # filtered out here; the groups list shows only template bindings).
    r = api_client.get("/api/v1/admin/groups/devs2/privileges", headers=admin_headers)
    assert r.status_code == 200
    items = [i for i in r.get_json() if i["template"]]
    assert len(items) == 1
    assert items[0]["template"] == "viewer" and items[0]["namespace"] == NS
    # Unbind removes the k8s RoleBinding + GCs the Role (last referrer).
    r = api_client.delete(
        "/api/v1/admin/groups/devs2/privileges",
        json={
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    assert ("delete_role_binding", NS, "kubedash-devs2-team-a") in FakeK8s.last.calls
    assert ("delete_role", NS, "kubedash-viewer") in FakeK8s.last.calls
    r = api_client.get("/api/v1/admin/groups/devs2/privileges", headers=admin_headers)
    assert [i for i in r.get_json() if i["template"]] == []


def test_group_bind_missing_group_is_404(
    api_client, api_app, admin_headers, fake_k8s
) -> None:
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/groups/nope/privileges",
        json={
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"
