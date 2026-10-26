"""TICKET-04 — permissions API: templates CRUD + bind/unbind + my-access.

Docker-free: the sqlite api tier (tests/api/conftest.py). Local users are
seeded directly + JWTs minted via ``security.issue_token_pair``; the k8s
world is a ``FakeK8s`` double injected via the pool's ``factory`` kwarg
(same seam as test_clusters.py / test_permission.py).

SATISFIES:
admin-creates-and-reads-a-custom-template;
malformed-template-rule-is-rejected;
template-in-use-cannot-be-deleted;
user-lists-their-own-bindings;
user-with-no-bindings-sees-an-empty-list;
a-user-never-sees-another-users-bindings.
"""
from __future__ import annotations

from typing import Any

import pytest

RULES_NS = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
RULES_CLUSTER = [{"api_groups": [""], "resources": ["nodes"], "verbs": ["get"]}]
NS = "team-a"

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
    """Double standing in for a live K8sClient; records every apply/delete
    call. ``raise_unreachable`` simulates a dead cluster (any call raises)."""

    def __init__(self, raise_unreachable: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.raise_unreachable = raise_unreachable
        FakeK8s.last = self

    def _maybe_raise(self) -> None:
        if self.raise_unreachable:
            raise RuntimeError("connection refused")

    def list_pods(self, namespace: str | None) -> list[dict]:
        return []

    def readyz(self) -> bool:
        return not self.raise_unreachable

    def apply_role(
        self, namespace: str, name: str, rules: list[dict[str, Any]], labels: dict[str, str]
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_role", namespace, name))

    def apply_role_binding(
        self,
        namespace: str,
        name: str,
        role_name: str,
        subject_user: str,
        labels: dict[str, str],
        subject_kind: str = "User",
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_role_binding", namespace, name, role_name, subject_user))

    def apply_cluster_role(self, name: str, rules: list[dict[str, Any]], labels: dict[str, str]) -> None:
        self._maybe_raise()
        self.calls.append(("apply_cluster_role", name))

    def apply_cluster_role_binding(
        self,
        name: str,
        role_name: str,
        subject_user: str,
        labels: dict[str, str],
        subject_kind: str = "User",
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_cluster_role_binding", name, role_name, subject_user))

    def delete_role_binding(self, namespace: str, name: str) -> None:
        self._maybe_raise()
        self.calls.append(("delete_role_binding", namespace, name))

    def delete_cluster_role_binding(self, name: str) -> None:
        self._maybe_raise()
        self.calls.append(("delete_cluster_role_binding", name))

    def delete_role(self, namespace: str, name: str) -> None:
        self._maybe_raise()
        self.calls.append(("delete_role", namespace, name))

    def delete_cluster_role(self, name: str) -> None:
        self._maybe_raise()
        self.calls.append(("delete_cluster_role", name))


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> dict[str, bool]:
    """Inject the FakeK8s factory into the module pool (per-test)."""
    import app.services.k8s_client as kc

    state = {"unreachable": False}

    def factory(plain: bytes) -> FakeK8s:
        return FakeK8s(state["unreachable"])

    monkeypatch.setitem(kc.__dict__, "pool", kc.K8sClientPool(factory=factory))
    return state


def _seed(api_client, api_app, sub: str, email: str, role: str) -> dict[str, str]:
    """Seed an ``auth_source='oidc'`` user (keeps it out of the bootstrap
    immutability gate) and mint a JWT. The email derives from the sub — two
    seeds of the same sub reuse the same row (email is UNIQUE; re-seeding in
    one test is a no-op, not an IntegrityError)."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        existing = db.session.execute(
            db.select(User).filter_by(sub=sub)
        ).scalar_one_or_none()
        if existing is None:
            existing = User(sub=sub, email=f"{sub}@local", role=role, auth_source="oidc")
            db.session.add(existing)
            db.session.commit()
        else:
            existing.role = role
            db.session.commit()
        access, _ = issue_token_pair(existing)
    return {"Authorization": f"Bearer {access}"}


def _seed_bootstrap_admin(api_client, api_app) -> dict[str, str]:
    """Seed the bootstrap ``local:`` admin row the way the PG tier's
    ``_bootstrap_local_admin`` hook does (the sqlite tier skips the hook —
    C-NEW-1) and mint a JWT for it."""
    from app.core.security import hash_password

    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(
            sub="local:admin@local", email="admin@local", display_name="admin",
            role="admin", auth_source="local",
            password_hash=hash_password("correct-horse"),
        )
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture()
def admin_headers(api_client, api_app) -> dict[str, str]:
    """The bootstrap ``local:`` admin is the actor — the immutability gate
    (``auth_source == 'local'``) only fires on a PATCH, never on the
    permissions routes, so the actor's own row never blocks these tests."""
    return _seed_bootstrap_admin(api_client, api_app)


@pytest.fixture()
def user_headers(api_client, api_app) -> dict[str, str]:
    return _seed(api_client, api_app, "local:user@local", "user@local", "user")


def _seed_template(api_app, name: str, scope: str, rules: list[dict[str, Any]],
                   builtin: bool = False) -> None:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.rbac_template import RBACTemplate

        db.session.add(RBACTemplate(name=name, scope=scope, rules=rules, builtin=builtin))
        db.session.commit()


def _register_cluster(api_client, api_app, headers: dict[str, str], name: str) -> int:
    r = api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )
    assert r.status_code in (200, 201), r.get_json()
    return int(r.get_json()["id"])


def _cluster_name(api_app, cluster_id: int) -> str:
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.cluster import Cluster

        return db.session.get(Cluster, cluster_id).name  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Templates CRUD
# ---------------------------------------------------------------------------


def test_admin_creates_and_reads_a_custom_template(api_client, api_app, admin_headers) -> None:
    """SATISFIES admin-creates-and-reads-a-custom-template."""
    r = api_client.post(
        "/api/v1/admin/permissions/templates",
        json={
            "name": "sre-oncall",
            "description": "on-call duties",
            "scope": "namespace",
            "rules": RULES_NS,
        },
        headers=admin_headers,
    )
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    assert body["name"] == "sre-oncall"
    assert body["builtin"] is False

    # Appears in the list.
    r2 = api_client.get("/api/v1/admin/permissions/templates", headers=admin_headers)
    assert r2.status_code == 200
    assert any(t["name"] == "sre-oncall" for t in r2.get_json())

    # GET back: rules match what was created.
    r3 = api_client.get("/api/v1/admin/permissions/templates/sre-oncall", headers=admin_headers)
    assert r3.status_code == 200
    assert r3.get_json()["rules"] == RULES_NS
    assert r3.get_json()["scope"] == "namespace"


def test_template_list_builtins_first(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "zzz-custom", "namespace", RULES_NS, builtin=False)
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    r = api_client.get("/api/v1/admin/permissions/templates", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body[0]["builtin"] is True
    assert [t["name"] for t in body] == ["viewer", "zzz-custom"]


def test_get_missing_template_is_404(api_client, admin_headers) -> None:
    r = api_client.get("/api/v1/admin/permissions/templates/nope", headers=admin_headers)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_template_name_collision_is_409(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "dup", "namespace", RULES_NS, builtin=True)
    r = api_client.post(
        "/api/v1/admin/permissions/templates",
        json={"name": "dup", "scope": "namespace", "rules": RULES_NS},
        headers=admin_headers,
    )
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"


def test_malformed_template_rule_is_rejected(api_client, api_app, admin_headers) -> None:
    """SATISFIES malformed-template-rule-is-rejected: a rule missing verbs →
    422 INVALID_KUBECONFIG and the template is NOT stored."""
    r = api_client.post(
        "/api/v1/admin/permissions/templates",
        json={
            "name": "bad",
            "scope": "namespace",
            "rules": [{"api_groups": [""], "resources": ["pods"]}],  # no verbs
        },
        headers=admin_headers,
    )
    assert r.status_code == 422, r.get_json()
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"
    r2 = api_client.get("/api/v1/admin/permissions/templates/bad", headers=admin_headers)
    assert r2.status_code == 404  # not stored


def test_put_builtin_template_is_409(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "developer", "namespace", RULES_NS, builtin=True)
    r = api_client.put(
        "/api/v1/admin/permissions/templates/developer",
        json={"name": "developer", "description": "mutated", "scope": "namespace", "rules": RULES_NS},
        headers=admin_headers,
    )
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "BUILTIN_TEMPLATE_PROTECTED"


def test_put_custom_template_updates(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "custom", "namespace", RULES_NS, builtin=False)
    r = api_client.put(
        "/api/v1/admin/permissions/templates/custom",
        json={"name": "custom", "description": "updated", "scope": "cluster", "rules": RULES_CLUSTER},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["scope"] == "cluster"
    assert body["rules"] == RULES_CLUSTER


def test_delete_builtin_template_is_409(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "developer", "namespace", RULES_NS, builtin=True)
    r = api_client.delete("/api/v1/admin/permissions/templates/developer", headers=admin_headers)
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "BUILTIN_TEMPLATE_PROTECTED"


def test_referenced_custom_template_cannot_be_deleted(api_client, api_app, admin_headers,
                                                       fake_k8s, user_headers) -> None:
    """SATISFIES template-in-use-cannot-be-deleted: DELETE on a custom
    template still referenced by a binding → 409 naming the binding."""
    _seed_template(api_app, "custom", "namespace", RULES_NS, builtin=False)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "custom",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    r2 = api_client.delete("/api/v1/admin/permissions/templates/custom", headers=admin_headers)
    assert r2.status_code == 409, r2.get_json()
    assert r2.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    msg = str(r2.get_json()["error"].get("message", "")) + str(
        r2.get_json()["error"].get("details", "")
    )
    assert "sub-user-1" in msg  # names the referencing binding


def test_delete_custom_template_succeeds_when_unreferenced(api_client, api_app, admin_headers) -> None:
    _seed_template(api_app, "free", "namespace", RULES_NS, builtin=False)
    r = api_client.delete("/api/v1/admin/permissions/templates/free", headers=admin_headers)
    assert r.status_code == 200, r.get_json()
    r2 = api_client.get("/api/v1/admin/permissions/templates/free", headers=admin_headers)
    assert r2.status_code == 404


def test_templates_require_admin(api_client, user_headers) -> None:
    # smorest validates the body BEFORE the handler runs, so the bodies below
    # must be schema-valid — the 403 is the gate, not the schema.
    for method, path, body in (
        ("GET", "/api/v1/admin/permissions/templates", None),
        ("POST", "/api/v1/admin/permissions/templates", {"name": "n", "scope": "namespace", "rules": RULES_NS}),
        ("GET", "/api/v1/admin/permissions/templates/any", None),
        ("PUT", "/api/v1/admin/permissions/templates/any", {"name": "any", "scope": "namespace", "rules": RULES_NS}),
        ("DELETE", "/api/v1/admin/permissions/templates/any", None),
        ("POST", "/api/v1/admin/permissions/bind", {"user": "u", "cluster": "c", "template": "t"}),
        ("DELETE", "/api/v1/admin/permissions/bind", {"user": "u", "cluster": "c", "template": "t"}),
    ):
        if method == "GET":
            r = api_client.get(path, headers=user_headers)
        else:
            r = api_client.open(path, method=method, json=body, headers=user_headers)
        assert r.status_code == 403, path
        assert r.get_json()["error"]["code"] == "RBAC_DENIED", path


# ---------------------------------------------------------------------------
# Bind / unbind
# ---------------------------------------------------------------------------


def test_admin_bind_records_binding_and_audits(api_client, api_app, admin_headers, fake_k8s) -> None:
    """Unit half of admin-binds-a-template-and-it-applies-in-the-cluster
    (the API layer: resolution + propagation; the k8s apply is Task 3's)."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    assert FakeK8s.last is not None
    assert ("apply_role", NS, "kubedash-viewer") in FakeK8s.last.calls
    assert (
        "apply_role_binding", NS, f"kubedash-sub-user-1-{NS}", "kubedash-viewer",
        "sub-user-1",
    ) in FakeK8s.last.calls
    # Binding row + audit row committed (the audit is the service's, not the
    # handler's — no double-audit).
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.audit import AuditLog
        from app.models.binding import ClusterBinding
        from app.models.user import User

        u = db.session.execute(
            db.select(User).filter_by(sub="sub-user-1")
        ).scalar_one()
        rows = db.session.execute(
            db.select(ClusterBinding).filter_by(user_id=u.id, cluster_id=cluster_id)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].template == "viewer"
        assert rows[0].namespace == NS
        audits = db.session.execute(
            db.select(AuditLog).filter_by(action="bind", target="user:sub-user-1")
        ).scalars().all()
        assert len(audits) == 1  # single audit row (service-side, no double)


def test_rebind_is_a_noop_no_new_audit(api_client, api_app, admin_headers, fake_k8s) -> None:
    """API half of rebinding-the-same-binding-is-a-no-op: 200, no new audit
    row (the idempotency check is inside the service)."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    body = {
        "user": "sub-user-1",
        "cluster": _cluster_name(api_app, cluster_id),
        "namespace": NS,
        "template": "viewer",
    }
    for _ in range(2):
        r = api_client.post("/api/v1/admin/permissions/bind", json=body, headers=admin_headers)
        assert r.status_code == 200, r.get_json()
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.audit import AuditLog

        n = db.session.execute(
            db.select(db.func.count())
            .select_from(AuditLog)
            .filter_by(action="bind", target="user:sub-user-1")
        ).scalar_one()
        assert n == 1


def test_bind_unknown_cluster_is_404(api_client, api_app, admin_headers, fake_k8s) -> None:
    """Unknown CLUSTER resolves first (404 CLUSTER_NOT_FOUND before the
    template lookup) — no user row needed."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={"user": "sub-user-1", "cluster": "ghost", "namespace": NS, "template": "viewer"},
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_bind_unknown_template_is_404(api_client, api_app, admin_headers, fake_k8s) -> None:
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "ghost",
        },
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_bind_unknown_user_is_404(api_client, api_app, admin_headers, fake_k8s) -> None:
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-ghost",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_bind_scope_mismatch_is_422(api_client, api_app, admin_headers, fake_k8s) -> None:
    """API half of binding-with-a-mismatched-scope-is-rejected."""
    _seed_template(api_app, "cluster-tpl", "cluster", RULES_CLUSTER, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,  # cluster-scoped template + namespace → 422
            "template": "cluster-tpl",
        },
        headers=admin_headers,
    )
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"


def test_bind_unreachable_cluster_is_502_no_binding(api_client, api_app, admin_headers,
                                                     fake_k8s, user_headers) -> None:
    """API half of binding-against-an-unreachable-cluster-records-nothing."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    fake_k8s["unreachable"] = True
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 502
    assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.binding import ClusterBinding
        from app.models.user import User

        u = db.session.execute(
            db.select(User).filter_by(sub="sub-user-1")
        ).scalar_one()
        rows = db.session.execute(
            db.select(ClusterBinding).filter_by(user_id=u.id)
        ).scalars().all()
        assert rows == []  # nothing recorded


def test_unbind_removes_binding_and_audits(api_client, api_app, admin_headers, fake_k8s) -> None:
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    cname = _cluster_name(api_app, cluster_id)
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={"user": "sub-user-1", "cluster": cname, "namespace": NS, "template": "viewer"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    r2 = api_client.delete(
        "/api/v1/admin/permissions/bind",
        json={"user": "sub-user-1", "cluster": cname, "namespace": NS, "template": "viewer"},
        headers=admin_headers,
    )
    assert r2.status_code == 200, r2.get_json()
    assert ("delete_role_binding", NS, "kubedash-sub-user-1-team-a") in FakeK8s.last.calls
    assert ("delete_role", NS, "kubedash-viewer") in FakeK8s.last.calls  # last referrer → GC


def test_unbind_missing_is_404_no_bindings(api_client, api_app, admin_headers, fake_k8s) -> None:
    """API half of unbinding-a-missing-binding-is-a-404. The user row must
    exist (the unbind's 404 is about the BINDING, not the user)."""
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.delete(
        "/api/v1/admin/permissions/bind",
        json={"user": "sub-user-1", "cluster": _cluster_name(api_app, cluster_id),
              "namespace": NS, "template": "viewer"},
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "NO_BINDINGS"


def test_unbind_unknown_cluster_is_404(api_client, api_app, admin_headers, fake_k8s) -> None:
    """Unknown CLUSTER resolves first (404 CLUSTER_NOT_FOUND before the
    binding lookup) — no user row needed."""
    r = api_client.delete(
        "/api/v1/admin/permissions/bind",
        json={"user": "sub-user-1", "cluster": "ghost", "namespace": NS, "template": "viewer"},
        headers=admin_headers,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


# ---------------------------------------------------------------------------
# My access (any authenticated user, NOT admin-gated)
# ---------------------------------------------------------------------------


def test_user_lists_their_own_bindings(api_client, api_app, admin_headers, fake_k8s) -> None:
    """SATISFIES user-lists-their-own-bindings: the caller sees exactly
    their bindings (cluster NAME, namespace, template, created_at)."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed_template(api_app, "developer", "namespace", RULES_NS, builtin=True)
    target = _seed(api_client, api_app, "sub-lister-1", "lister@local", "user")
    c1 = _register_cluster(api_client, api_app, admin_headers, "prod")
    c2 = _register_cluster(api_client, api_app, admin_headers, "staging")
    for cname, tpl, ns in (
        (_cluster_name(api_app, c1), "viewer", NS),
        (_cluster_name(api_app, c2), "developer", "team-b"),
    ):
        r = api_client.post(
            "/api/v1/admin/permissions/bind",
            json={"user": "sub-lister-1", "cluster": cname, "namespace": ns, "template": tpl},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.get_json()
    r2 = api_client.get("/api/v1/permissions/my-access", headers=target)
    assert r2.status_code == 200
    body = r2.get_json()
    assert len(body) == 2
    triples = sorted((b["cluster"], b["namespace"], b["template"]) for b in body)
    assert triples == sorted([
        (_cluster_name(api_app, c1), NS, "viewer"),
        (_cluster_name(api_app, c2), "team-b", "developer"),
    ])
    for b in body:
        assert b["created_at"] is not None


def test_unbound_user_sees_empty_list(api_client, user_headers) -> None:
    """SATISFIES user-with-no-bindings-sees-an-empty-list: 200 + ``[]``,
    not a 404."""
    r = api_client.get("/api/v1/permissions/my-access", headers=user_headers)
    assert r.status_code == 200
    assert r.get_json() == []


def test_a_user_never_sees_another_users_bindings(api_client, api_app, admin_headers,
                                                   fake_k8s) -> None:
    """SATISFIES a-user-never-sees-another-users-bindings: the unbound user's
    list is empty and carries none of the other user's bindings."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-user-1", "user@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-user-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()
    # A fresh unbound user (different sub) sees nothing of the bound user's.
    stranger = _seed(api_client, api_app, "sub-stranger-1", "stranger@local", "user")
    r2 = api_client.get("/api/v1/permissions/my-access", headers=stranger)
    assert r2.status_code == 200
    body = r2.get_json()
    assert body == []


def test_my_access_requires_auth(api_client) -> None:
    r = api_client.get("/api/v1/permissions/my-access")
    assert r.status_code == 401
    assert r.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_my_access_non_admin_can_call(api_client, user_headers) -> None:
    """my-access is NOT admin-gated — a plain user may call it (200 with an
    empty list, not a 403 RBAC_DENIED)."""
    r = api_client.get("/api/v1/permissions/my-access", headers=user_headers)
    assert r.status_code == 200
    assert r.get_json() == []


def test_admin_lists_another_users_bindings(
    api_client, api_app, admin_headers, user_headers, fake_k8s
) -> None:
    """Admin enumeration of ANOTHER user's bindings — the surface
    my-access withholds. Admin sees the target's rows; a non-admin gets
    403; an unknown sub is 404."""
    _seed_template(api_app, "viewer", "namespace", RULES_NS, builtin=True)
    _seed(api_client, api_app, "sub-enum-1", "enum@local", "user")
    cluster_id = _register_cluster(api_client, api_app, admin_headers, "prod")
    r = api_client.post(
        "/api/v1/admin/permissions/bind",
        json={
            "user": "sub-enum-1",
            "cluster": _cluster_name(api_app, cluster_id),
            "namespace": NS,
            "template": "viewer",
        },
        headers=admin_headers,
    )
    assert r.status_code == 200, r.get_json()

    # Admin sees the target user's binding.
    r2 = api_client.get(
        "/api/v1/admin/permissions/users/sub-enum-1/bindings", headers=admin_headers
    )
    assert r2.status_code == 200, r2.get_json()
    body = r2.get_json()
    assert len(body) == 1
    assert (body[0]["cluster"], body[0]["namespace"], body[0]["template"]) == (
        _cluster_name(api_app, cluster_id), NS, "viewer",
    )

    # A non-admin cannot enumerate.
    r3 = api_client.get(
        "/api/v1/admin/permissions/users/sub-enum-1/bindings", headers=user_headers
    )
    assert r3.status_code == 403
    assert r3.get_json()["error"]["code"] == "RBAC_DENIED"

    # An unknown sub is 404.
    r4 = api_client.get(
        "/api/v1/admin/permissions/users/sub-ghost/bindings", headers=admin_headers
    )
    assert r4.status_code == 404
