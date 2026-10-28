"""R4 — generic resource list endpoint: GET /api/v1/clusters/<id>/resources/<kind>.

Docker-free unit tier: the k8s path is a ``FakeK8s`` double injected through
the pool's ``factory`` seam (same as test_clusters.py) and the SAR is the real
``rbac.can`` reading the fake redis (``_cache_get``/``_cache_set`` are the
module seams the unit tests patch). The kind integration tier (``@pytest.mark
.integration``) runs the same endpoint against a real kind cluster —
env-block where no Docker is available, deselected with ``-m "not
integration"``.
"""
import pytest

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
    """Double standing in for a live K8sClient; ``list_pods`` echoes the
    configured pod list (namespaced, per call)."""

    def __init__(self, kubeconfig: bytes) -> None:
        self.kubeconfig = kubeconfig
        self.created_namespaces: list[str] = []
        self.deleted_namespaces: list[str] = []

    def create_namespace(self, name: str) -> dict:
        self.created_namespaces.append(name)
        return {"metadata": {"name": name}}

    def delete_namespace(self, name: str) -> None:
        self.deleted_namespaces.append(name)

    def list_namespaces(self, namespace: str | None) -> list[dict]:
        return [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "team-a"}},
        ]

    def list_pods(self, namespace: str | None) -> list[dict]:
        if namespace is None:
            return [
                {"metadata": {"name": "kubedash-pod", "namespace": "default"}},
                {"metadata": {"name": "other-pod", "namespace": "kube-system"}},
            ]
        return [
            {"metadata": {"name": "kubedash-pod", "namespace": namespace}},
        ]

    def list_nodes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is ignored (mirrors the real
        # K8sClient.list_nodes). NodeStatus + a Ready condition are present so
        # the dashboard's node view can assert on the real shape.
        return [
            {
                "metadata": {"name": "worker-1"},
                "status": {
                    "conditions": [
                        {"type": "Ready", "status": "True"},
                        {"type": "MemoryPressure", "status": "False"},
                    ],
                    "node_info": {"kubelet_version": "v1.31.0", "os_image": "kind"},
                    "addresses": [{"type": "InternalIP", "address": "192.168.0.2"}],
                },
            },
            {
                "metadata": {"name": "control-plane"},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "node_info": {"kubelet_version": "v1.31.0", "os_image": "kind"},
                },
            },
        ]

    def list_roles(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit", "namespace": namespace},
                "rules": [{"resources": ["pods"], "verbs": ["get"]}],
            },
        ]

    def list_rolebindings(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit-binding", "namespace": namespace},
                "role_ref": {
                    "api_group": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "edit",
                },
                "subjects": [
                    {"kind": "User", "name": "jane"},
                    {"kind": "Group", "name": "devs"},
                    {"kind": "ServiceAccount", "name": "builder", "namespace": "team-a"},
                ],
            },
        ]

    def list_cluster_role_bindings(self, _namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "cluster-admin"},
                "role_ref": {
                    "api_group": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "cluster-admin",
                },
                "subjects": [
                    {"kind": "User", "name": "jane"},
                    {"kind": "Group", "name": "system:masters"},
                    {"kind": "ServiceAccount", "name": "builder", "namespace": "ci"},
                ],
            },
        ]

    def list_cluster_roles(self, _namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit"},
                "rules": [{"resources": ["pods"], "verbs": ["get"]}],
            },
        ]

    def list_serviceaccounts(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "builder", "namespace": namespace},
                "secrets": [{"name": "builder-token"}],
                "image_pull_secrets": [{"name": "registry-cred"}],
            },
        ]

    def list_secrets(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "builder-token", "namespace": namespace},
                "type": "kubernetes.io/service-account-token",
            },
        ]

    def get_secret(self, namespace: str, name: str) -> list[dict]:
        if name != "builder-token":
            return []
        return [
            {
                "metadata": {"name": name, "namespace": namespace},
                "type": "kubernetes.io/service-account-token",
                "data": {"token": "dG9rZW4="},
            },
        ]

    def list_crds(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is ignored (mirrors the real
        # K8sClient.list_crds). The shape mirrors a real CRD to_dict — the
        # instances route reads spec.group/names/scope/versions off it.
        return [
            {
                "metadata": {"name": "applications.argoproj.io"},
                "spec": {
                    "group": "argoproj.io",
                    "names": {"kind": "Application", "plural": "applications"},
                    "scope": "Namespaced",
                    "versions": [
                        {"name": "v1alpha1", "served": True, "storage": True},
                        {"name": "v1", "served": True, "storage": False},
                    ],
                },
            }
        ]

    def get_crd(self, _namespace: str, name: str) -> list[dict]:
        [crd] = self.list_crds(None)
        if crd["metadata"]["name"] != name:
            return []
        return [crd]

    def list_crd_instances(
        self, group: str, version: str, plural: str, namespace: str | None
    ) -> list[dict]:
        # Projected 4.1 shape; the fake echoes the namespace when namespaced.
        self.crd_instance_calls: list[tuple] = []
        self.crd_instance_calls.append((group, version, plural, namespace))
        return [
            {
                "name": "app-1",
                "namespace": namespace,
                "status": "True",
                "type": "Ready",
                "reason": "Ok",
                "message": "all good",
                "created": "2026-01-02T03:04:05Z",
            }
        ]

    def readyz(self) -> bool:
        return True


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    """Inject the FakeK8s factory into the module pool (the Task 4 seam).

    The handler does ``from app.services.k8s_client import pool`` — a copy
    into ``api_app.api.resources.__dict__`` — so the patch must target the
    ``resources`` module's binding, not ``k8s_client.pool`` (the test_clusters
    fixture patches ``kc.pool`` and works there because no module holds a
    copied reference to the pool).
    """
    import importlib

    import app.services.k8s_client as kc

    fake = FakeK8s(b"unused")
    res = importlib.import_module("app.api.resources")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(res.__dict__, "pool", fake_pool)
    return fake


def _allow_sar(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let every SAR through (the unit tier does not model cluster RBAC)."""
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda e, k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", lambda client, verb, resource, ns, name, group="": True)


def _make_admin(api_client) -> None:
    """OIDC login creates a role=user row; namespace mutations require admin."""
    from app.extensions import db
    from app.models.user import User

    with api_client.application.app_context():
        user = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        user.role = "admin"
        db.session.commit()


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


def test_unknown_kind_404_stable_code(api_client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/widgets", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_unbound_cluster_404(api_client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    # No cluster 999 was ever registered — the binding gate fails first.
    r = api_client.get("/api/v1/clusters/999/resources/pods", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_unbound_user_404(api_client, auth_client, api_app, fake_k8s, monkeypatch) -> None:
    """A cluster that exists but is bound to another user is invisible —
    same CLUSTER_NOT_FOUND, the binding gate does not distinguish (R3)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r1 = _register(api_client, h, name="other-users-cluster")
    assert r1.status_code == 201
    # A second, unbound user.
    with api_app.app_context():
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub="unbound-user", email="ub@example.com")
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    r = api_client.get(
        f"/api/v1/clusters/{r1.get_json()['id']}/resources/pods",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_list_pods_200_with_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """list-pods-for-bound-cluster (SATISFIES; acceptance.feature pending,
    Task 12): a bound user listing pods gets the pod list back."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "pods"
    assert body["cluster"] == "prod"
    names = [p["metadata"]["name"] for p in body["items"]]
    assert "kubedash-pod" in names


def test_list_namespaces_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The header selector lists namespaces on the selected cluster."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/namespaces", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "namespaces"
    assert [item["metadata"]["name"] for item in body["items"]] == ["default", "team-a"]


def test_list_nodes_200_cluster_scoped(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The node view lists cluster-scoped nodes (SATISFIES the node route).

    Nodes are cluster-scoped: the namespace query does not apply, and the
    SAR verb is ``list`` on ``nodes`` (ADR-0004 enforcement point)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/nodes", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "nodes"
    assert [item["metadata"]["name"] for item in body["items"]] == ["worker-1", "control-plane"]


def test_list_pods_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods?namespace=prod-ns", headers=h)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert [p["metadata"]["namespace"] for p in items] == ["prod-ns"]


def test_list_rolebindings_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > RoleBindings page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/rolebindings?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "rolebindings"
    [binding] = body["items"]
    assert binding["metadata"] == {"name": "edit-binding", "namespace": "team-a"}
    assert binding["role_ref"]["kind"] == "Role"
    assert binding["role_ref"]["name"] == "edit"
    assert binding["subjects"][0]["name"] == "jane"


def test_list_roles_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > Roles page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/roles?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "roles"
    [role] = body["items"]
    assert role["metadata"] == {"name": "edit", "namespace": "team-a"}
    assert role["rules"] == [{"resources": ["pods"], "verbs": ["get"]}]


def test_list_clusterrolebindings(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """Cluster Permissions > Cluster Role Bindings lists the cluster-scoped kind."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/clusterrolebindings?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "clusterrolebindings"
    [binding] = body["items"]
    assert binding["metadata"] == {"name": "cluster-admin"}
    assert binding["role_ref"]["kind"] == "ClusterRole"
    assert binding["role_ref"]["name"] == "cluster-admin"
    assert binding["subjects"][0]["name"] == "jane"


def test_list_clusterroles(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """Cluster Permissions > Cluster Role lists the cluster-scoped kind."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/clusterroles?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "clusterroles"
    [role] = body["items"]
    assert role["metadata"] == {"name": "edit"}
    assert role["rules"] == [{"resources": ["pods"], "verbs": ["get"]}]


def test_list_serviceaccounts_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > ServiceAccounts page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/serviceaccounts?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "serviceaccounts"
    [sa] = body["items"]
    assert sa["metadata"] == {"name": "builder", "namespace": "team-a"}
    assert sa["secrets"] == [{"name": "builder-token"}]
    assert sa["image_pull_secrets"] == [{"name": "registry-cred"}]


def test_list_secrets_namespaced_without_data(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Security > Secrets page lists one namespace: names and types only."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "secrets"
    [secret] = body["items"]
    assert secret == {
        "metadata": {"name": "builder-token", "namespace": "team-a"},
        "type": "kubernetes.io/service-account-token",
    }


def test_get_secret_by_name_returns_data(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The secret data page reads one secret, data still base64."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/secrets?namespace=team-a&name=builder-token", headers=h
    )
    assert r.status_code == 200
    [secret] = r.get_json()["items"]
    assert secret["metadata"] == {"name": "builder-token", "namespace": "team-a"}
    assert secret["data"] == {"token": "dG9rZW4="}


def test_get_missing_secret_returns_no_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a&name=gone", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def _record_sar(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Deny every SAR and record what was asked."""
    import app.services.rbac as rb

    asked: list[tuple] = []
    monkeypatch.setattr(rb, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda e, k, v: None)

    def deny(client, verb, resource, ns, name, group=""):
        asked.append((verb, resource, ns, name, group))
        return False

    monkeypatch.setattr(rb, "_sar_allowed", deny)
    return asked


def test_list_secrets_asks_sar_for_list(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a", headers=h)
    assert r.status_code == 403
    assert asked == [("list", "secrets", "team-a", None, "")]


def test_get_secret_asks_sar_for_get_on_that_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a&name=db", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [("get", "secrets", "team-a", "db", "")]


def test_name_lookup_on_kind_without_getter_404(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods?namespace=team-a&name=web", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_rbac_denied_403(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """SAR deny -> 403 RBAC_DENIED: the service seam (``_sar_allowed``) is
    the unit-tier stand-in for a cluster that lacks the grant."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda e, k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", lambda api_client, verb, resource, ns, name, group="": False)
    r = api_client.get("/api/v1/clusters/1/resources/pods", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_admin_creates_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 201
    assert r.get_json()["name"] == "team-b"
    assert fake_k8s.created_namespaces == ["team-b"]


@pytest.mark.parametrize(
    "name", ["default", "kube-system", "kube-public", "kube-node-lease"]
)
def test_protected_namespace_delete_is_rejected_without_client_call(
    api_client, auth_client, fake_k8s, monkeypatch, name
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        f"/api/v1/clusters/1/resources/namespaces/{name}", headers=h
    )
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    assert fake_k8s.deleted_namespaces == []


def test_admin_deletes_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        "/api/v1/clusters/1/resources/namespaces/team-b", headers=h
    )
    assert r.status_code == 200
    assert r.get_json() == {"name": "team-b"}
    assert fake_k8s.deleted_namespaces == ["team-b"]


def test_namespace_create_requires_admin(
    api_client, auth_client, api_app, fake_k8s, monkeypatch
) -> None:
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User

    auth_client.login()
    admin_headers = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, admin_headers)
    with api_app.app_context():
        cluster = db.session.get(Cluster, 1)
        user = User(sub="plain-user", email="plain@example.com", role="user")
        db.session.add(user)
        db.session.flush()
        db.session.add(ClusterBinding(user_id=user.id, cluster_id=cluster.id, role="viewer"))
        db.session.commit()
        access, _ = issue_token_pair(user)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert fake_k8s.created_namespaces == []


def test_namespace_create_asks_sar_for_create(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 403
    assert asked == [("create", "namespaces", None, None, "")]


def test_invalid_namespace_name_is_422(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "Not Valid"},
        headers=h,
    )
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"
    assert fake_k8s.created_namespaces == []


def test_list_crds_200_cluster_scoped(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The CRDs view lists cluster-scoped CRDs (SAR on
    ``list customresourcedefinitions`` in ``apiextensions.k8s.io``)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "crds"
    assert body["cluster"] == "prod"
    [crd] = body["items"]
    assert crd["metadata"]["name"] == "applications.argoproj.io"


def test_get_crd_by_name_returns_single_item(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The CRD detail page reads one CRD via the ``_GETTERS`` path."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 200
    [crd] = r.get_json()["items"]
    assert crd["spec"]["group"] == "argoproj.io"


def test_get_missing_crd_returns_no_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds?name=gone.example.io", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_crds_asks_sar_for_list(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds", headers=h)
    assert r.status_code == 403
    assert asked == [("list", "customresourcedefinitions", None, None, "apiextensions.k8s.io")]


def test_get_crd_asks_sar_for_get_on_that_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The ``?name=`` lookup is SAR-gated with ``get`` (matching the secrets
    ``_GETTERS`` precedent), not ``list``."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # namespace defaults to "default" on the ``?name=`` path (the shared
    # _GETTERS convention — see the secrets ``?name=`` tests); the CRD is
    # cluster-scoped so the value is cosmetic, but the SAR cache key carries it.
    assert asked == [
        ("get", "customresourcedefinitions", "default", "applications.argoproj.io", "apiextensions.k8s.io")
    ]


def test_get_crd_by_name_sar_allow_returns_item(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 200
    assert len(r.get_json()["items"]) == 1


def test_list_crd_instances_200_namespaced(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """The CRD detail page lists the CRD's instances: two SARs (list on the
    CRD + list on the instances) both pass, the namespace is applied because
    the fake CRD is Namespaced-scoped."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances"
        "?name=applications.argoproj.io&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "crds"
    [inst] = body["items"]
    assert inst["name"] == "app-1"
    assert inst["namespace"] == "team-a"
    # The instances route prefers the STORAGE served version (v1alpha1 in the
    # fake CRD), not the first declared version.
    assert fake_k8s.crd_instance_calls == [("argoproj.io", "v1alpha1", "applications", "team-a")]


def test_list_crd_instances_first_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """A deny on the FIRST gate (list on the CRD) short-circuits: only one
    SAR is recorded, and the 403 names customresourcedefinitions. The second
    SAR (list on the instances) is never asked."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=applications.argoproj.io",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [
        ("list", "customresourcedefinitions", None, "applications.argoproj.io", "apiextensions.k8s.io")
    ]


def test_list_crd_instances_second_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """The first SAR (list on the CRD) passes; the second (list on the
    instances) is denied — the 403 names the instance plural, and the client
    method is never called."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    import app.services.rbac as rb

    asked: list[tuple] = []

    def selective(client, verb, resource, ns, name, group=""):
        asked.append((verb, resource, ns, name, group))
        # Allow the CRD read, deny the instance list.
        return resource == "customresourcedefinitions"

    monkeypatch.setattr(rb, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda e, k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", selective)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=applications.argoproj.io&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [
        ("list", "customresourcedefinitions", None, "applications.argoproj.io", "apiextensions.k8s.io"),
        ("list", "applications", "team-a", None, "argoproj.io"),
    ]


def test_list_crd_instances_missing_crd_404(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """A ``?name=`` that no CRD matches is a CLUSTER_NOT_FOUND, not a 500 —
    the second SAR is never asked (the CRD read is what resolves it)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=gone.example.io", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_list_crd_instances_requires_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds/instances", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


@pytest.mark.integration
def test_list_pods_on_kind(api_client, auth_client, kind_client) -> None:
    cid, kubeconfig = kind_client
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    api_client.post(
        "/api/v1/clusters",
        json={
            "name": "kind-test",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kubeconfig.decode(),
            "context": "kind-kind-test",
        },
        headers=h,
    )
    r = api_client.get(f"/api/v1/clusters/{cid}/resources/pods?namespace=default", headers=h)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert any(p["metadata"]["name"] == "kubedash-pod" for p in items)


@pytest.mark.integration
def test_demo_serviceaccount_with_secret_and_pullsecret(
    api_client, auth_client, kind_client
) -> None:
    """The kind fixture's demo account lists its token secret and pull secret,
    and the pull secret's value is only on the single-object read."""
    cid, kubeconfig = kind_client
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    api_client.post(
        "/api/v1/clusters",
        json={
            "name": "kind-test",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kubeconfig.decode(),
            "context": "kind-kind-test",
        },
        headers=h,
    )
    accounts = api_client.get(
        f"/api/v1/clusters/{cid}/resources/serviceaccounts?namespace=default", headers=h
    )
    assert accounts.status_code == 200, accounts.get_json()
    account = next(
        item
        for item in accounts.get_json()["items"]
        if item["metadata"]["name"] == "kubedash-builder"
    )
    assert account["secrets"] == [{"name": "kubedash-builder-token"}]
    assert account["image_pull_secrets"] == [{"name": "kubedash-registry"}]

    listed = api_client.get(
        f"/api/v1/clusters/{cid}/resources/secrets?namespace=default", headers=h
    )
    assert listed.status_code == 200, listed.get_json()
    by_name = {item["metadata"]["name"]: item for item in listed.get_json()["items"]}
    assert by_name["kubedash-builder-token"]["type"] == "kubernetes.io/service-account-token"
    assert by_name["kubedash-registry"]["type"] == "kubernetes.io/dockerconfigjson"
    assert "data" not in by_name["kubedash-registry"]

    one = api_client.get(
        f"/api/v1/clusters/{cid}/resources/secrets?namespace=default&name=kubedash-registry",
        headers=h,
    )
    assert one.status_code == 200, one.get_json()
    [secret] = one.get_json()["items"]
    assert ".dockerconfigjson" in secret["data"]


@pytest.mark.integration
def test_rbac_denied_403_on_kind(api_client, kind_client, api_app) -> None:
    """Denial path without kind RBAC gymnastics: a KubeDash user whose K8s
    identity has no grants. The kind kubeconfig's user is 'kind' (admin) —
    create a second binding for a KubeDash user and patch the SAR for that
    (cluster, user) pair to deny (the service seam), then expect 403."""
    cid, kubeconfig = kind_client
    import app.services.rbac as rb
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User
    from app.services.k8s_client import encrypt_kubeconfig

    with api_app.app_context():
        c = Cluster.query.filter_by(name="kind-test").first()
        if c is None:  # test ordering: the register happens in the pod test
            enc = encrypt_kubeconfig(kubeconfig)
            u0 = db.session.execute(
                db.select(User).filter_by(sub="sub-oidc-1")
            ).scalar_one()
            c = Cluster(
                name="kind-test",
                api_server="https://127.0.0.1:6443",
                kubeconfig_enc=enc,
                context="kind-kind-test",
            )
            db.session.add(c)
            db.session.flush()
            db.session.add(ClusterBinding(user_id=u0.id, cluster_id=c.id, role="admin"))
        u = User(sub="denied-sa", email="d@example.com")
        db.session.add_all([u, ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")])
        db.session.commit()
        access, _ = issue_token_pair(u)
    orig = rb._sar_allowed
    rb._sar_allowed = lambda *a, **k: False
    try:
        r = api_client.get(
            f"/api/v1/clusters/{c.id}/resources/pods",
            headers={"Authorization": f"Bearer {access}"},
        )
    finally:
        rb._sar_allowed = orig
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
