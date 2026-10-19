"""ADR-0013 (TICKET-03) — integration: a REAL bind against a kind cluster.

SATISFIES (kind half): admin-binds-a-template-and-it-applies-in-the-cluster,
rebinding-the-same-binding-is-a-no-op, unbinding-the-last-user-deletes-the-
cluster-role. kind-gated: the ``kind_cluster`` fixture skips where kind is
absent, and the whole file deselects under ``-m "not integration"``.
"""
import secrets

import pytest

from app.models.audit import AuditLog
from app.models.cluster import Cluster
from app.models.rbac_template import RBACTemplate
from app.models.user import User
from app.services import permission
from app.services.k8s_client import K8sClient

RULES = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
NS = "bind-it"


@pytest.fixture()
def _unique() -> str:
    """Per-test suffix — the shared PG container persists rows across tests."""
    return secrets.token_hex(4)


@pytest.mark.integration
def test_bind_rebind_unbind_gc_on_kind(app, db_sess, kind_cluster, _unique: str) -> None:
    from kubernetes import client as k8s_client
    from kubernetes.client.exceptions import ApiException

    from app.extensions import db as ext_db

    k8s = K8sClient(kind_cluster)  # the kind kubeconfig, built the registry way
    # The per-file conftest teardown may have just recreated the cluster — wait
    # for the API server to answer an RBAC list before the assertions run.
    # (readyz() is NOT used: kind's `get kubeconfig` omits the CA, so its
    # httpx verify=True fallback cannot verify the kind CA.)
    import time

    deadline = time.monotonic() + 120
    while True:
        try:
            k8s._rbac.list_cluster_role()
            break
        except Exception:
            if time.monotonic() > deadline:
                pytest.fail("kind API server did not become ready within 120 s")
            time.sleep(2)

    suffix = _unique
    template = f"bindit-{suffix}"
    p = RBACTemplate(name=template, scope="namespace", rules=RULES, builtin=True)
    ext_db.session.add(p)
    ext_db.session.add(User(sub=f"bind-user-{suffix}", status="active"))
    c = Cluster(
        name=f"kind-bind-{suffix}", api_server="https://127.0.0.1:6443", kubeconfig_enc=b""
    )
    ext_db.session.add(c)
    ext_db.session.commit()
    cid = c.id

    # Namespace-scoped objects need a namespace — create it, 409-tolerant (a
    # reused cluster may already carry it). Clean up any stale objects from a
    # prior run (the shared cluster survives across test files).
    try:
        k8s._v1.create_namespace(k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=NS)))
    except ApiException as e:
        if e.status != 409:
            raise
    for delete_fn, args in (
        (k8s._rbac.delete_namespaced_role_binding, (f"kubedash-bind-user-{suffix}-{NS}", NS)),
        (k8s._rbac.delete_namespaced_role, (f"kubedash-{template}", NS)),
    ):
        try:
            delete_fn(*args)
        except ApiException as e:
            if e.status != 404:
                raise

    ext_db.session.execute(
        ext_db.select(RBACTemplate).filter_by(name=template)
    ).scalar_one()

    # --- bind: the cluster must carry a Role + RoleBinding (rules + labels) ---
    permission.bind(
        user_sub=f"bind-user-{suffix}", cluster_id=cid, namespace=NS,
        template_name=template, actor_sub=f"bind-user-{suffix}",
        db_session=ext_db.session, k8s=k8s,
    )
    role = k8s._rbac.read_namespaced_role(f"kubedash-{template}", NS)
    assert role.metadata.labels == {"kubedash.io/template": template}
    got_rules = [r.to_dict() for r in role.rules]
    assert got_rules == [
        {"api_groups": [""], "non_resource_urls": None, "resource_names": None,
         "resources": ["pods"], "verbs": ["get", "list"]},
    ]
    rb = k8s._rbac.read_namespaced_role_binding(f"kubedash-bind-user-{suffix}-{NS}", NS)
    assert rb.role_ref.name == f"kubedash-{template}"
    # The API server normalizes a User subject's apiGroup to the rbac group
    # (we send ""); assert on kind + name only.
    assert [s.to_dict()["kind"] for s in rb.subjects] == ["User"]
    assert [s.to_dict()["name"] for s in rb.subjects] == [f"bind-user-{suffix}"]

    # --- re-bind: no-op (exactly one RoleBinding, no new audit row) ---
    n_audit = ext_db.session.execute(
        ext_db.select(AuditLog).filter_by(action="bind", template=template)
    ).scalars().all()
    assert len(n_audit) == 1
    permission.bind(
        user_sub=f"bind-user-{suffix}", cluster_id=cid, namespace=NS,
        template_name=template, actor_sub=f"bind-user-{suffix}",
        db_session=ext_db.session, k8s=k8s,
    )
    # The shared cluster may carry other objects — count only THIS user's
    # RoleBinding (re-bind must not create a second one).
    bindings = k8s._rbac.list_namespaced_role_binding(NS)
    mine = [b for b in bindings.items if f"bind-user-{suffix}" in (b.metadata.name or "")]
    assert len(mine) == 1
    n_audit2 = ext_db.session.execute(
        ext_db.select(AuditLog).filter_by(action="bind", template=template)
    ).scalars().all()
    assert len(n_audit2) == 1

    # --- unbind the last referrer: RoleBinding AND Role both gone ---
    permission.unbind(
        user_sub=f"bind-user-{suffix}", cluster_id=cid, namespace=NS,
        actor_sub=f"bind-user-{suffix}", db_session=ext_db.session, k8s=k8s,
    )
    with pytest.raises(ApiException) as e:
        k8s._rbac.read_namespaced_role(f"kubedash-{template}", NS)
    assert e.value.status == 404
    with pytest.raises(ApiException) as e2:
        k8s._rbac.read_namespaced_role_binding(f"kubedash-bind-user-{suffix}-{NS}", NS)
    assert e2.value.status == 404

    # --- teardown: drop the namespace so the per-file cluster stays clean ---
    try:
        k8s._v1.delete_namespace(NS)
    except ApiException as e:
        if e.status != 404:
            raise
