"""ADR-0013 (TICKET-03) — the tracer core: idempotent bind/unbind + Role GC.

DB tier: the shared Testcontainers app (``app``/``db_sess`` fixtures — Docker
required, like the rest of the services tier). The K8s world is a ``FakeK8s``
double standing in for ``K8sClient``. NOTE: the ``app`` fixture rolls the
session back, but the session-scoped PG container PERSISTS committed rows
across tests — every seeded name therefore carries a per-test suffix
(``_unique``). SATISFIES:
admin-binds-a-template-and-it-applies-in-the-cluster;
rebinding-the-same-binding-is-a-no-op; binding-with-a-mismatched-scope-is-rejected;
unbinding-the-last-user-deletes-the-cluster-role; unbinding-a-missing-binding-is-a-404;
binding-against-an-unreachable-cluster-records-nothing.
"""
import secrets
from types import SimpleNamespace
from typing import Any

import pytest
from flask import g as flask_g
from kubernetes.client.exceptions import ApiException

from app.core.errors import (
    ClusterNotFoundError,
    ClusterUnreachableError,
    InvalidKubeconfigError,
    NoBindingsError,
    RbacDeniedError,
    ResourceKindNotSupportedError,
)
from app.models.audit import AuditLog
from app.models.binding import ClusterBinding
from app.models.cluster import Cluster
from app.models.rbac_template import RBACTemplate
from app.models.user import User
from app.services import permission

RULES_NS = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
RULES_CLUSTER = [{"api_groups": [""], "resources": ["nodes"], "verbs": ["get"]}]
NS = "team-a"


class FakeK8s:
    """Records every apply/delete call; raise_unreachable simulates a dead
    cluster by raising on ANY call (the kubernetes client does the same)."""

    last_rules: list[dict[str, Any]]
    last_labels: dict[str, str]

    def __init__(self, raise_unreachable: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.raise_unreachable = raise_unreachable

    def _maybe_raise(self) -> None:
        if self.raise_unreachable:
            raise ApiException(status=500, reason="connection refused")

    def apply_role(
        self, namespace: str, name: str, rules: list[dict[str, Any]], labels: dict[str, str]
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_role", namespace, name))
        self.last_rules = rules
        self.last_labels = labels

    def apply_role_binding(
        self, namespace: str, name: str, role_name: str, subject_user: str, labels: dict[str, str]
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_role_binding", namespace, name, role_name, subject_user))
        self.last_labels = labels

    def apply_cluster_role(
        self, name: str, rules: list[dict[str, Any]], labels: dict[str, str]
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_cluster_role", name))
        self.last_rules = rules
        self.last_labels = labels

    def apply_cluster_role_binding(
        self, name: str, role_name: str, subject_user: str, labels: dict[str, str]
    ) -> None:
        self._maybe_raise()
        self.calls.append(("apply_cluster_role_binding", name, role_name, subject_user))
        self.last_labels = labels

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
def _unique() -> str:
    """Per-test suffix for the seeded names (the PG container persists
    committed rows across tests — see the module docstring)."""
    return secrets.token_hex(4)


def _seed(db, suffix: str, *, template_scope: str = "namespace",
          rules: list[dict[str, Any]] | None = None) -> SimpleNamespace:
    """Seed one user + one admin actor + one template + one cluster (all
    names suffixed); return the ids + subs as a SimpleNamespace."""
    t = RBACTemplate(
        name=f"viewer-{suffix}", scope=template_scope, rules=rules or RULES_NS, builtin=True
    )
    db.session.add(t)
    admin = User(sub=f"admin-{suffix}", role="admin", status="active")
    db.session.add(admin)
    u = User(sub=f"sub-{suffix}", status="active")
    db.session.add(u)
    c = Cluster(name=f"c-{suffix}", api_server="https://127.0.0.1:6443", kubeconfig_enc=b"")
    db.session.add(c)
    db.session.commit()
    return SimpleNamespace(
        template=f"viewer-{suffix}", admin_sub=f"admin-{suffix}",
        user_sub=f"sub-{suffix}", user_id=u.id, cluster_id=c.id,
    )


def _bind(p: SimpleNamespace, k8s: FakeK8s, db, *, namespace: str | None = NS,
          user_sub: str | None = None, template: str | None = None,
          cluster_id: int | None = None) -> Any:
    return permission.bind(
        user_sub=user_sub or p.user_sub,
        cluster_id=cluster_id if cluster_id is not None else p.cluster_id,
        namespace=namespace,
        template_name=template or p.template,
        actor_sub=p.admin_sub,
        db_session=db.session,
        k8s=k8s,
    )


def test_bind_applies_role_and_rolebinding(app, db_sess, _unique: str) -> None:
    """SATISFIES admin-binds-a-template-and-it-applies-in-the-cluster (unit
    half; the kind half is tests/integration/test_bind_kind.py)."""
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    binding = _bind(p, k8s, db_sess)
    assert isinstance(binding, ClusterBinding)
    assert binding.namespace == NS
    assert binding.template == p.template
    # The cluster got Role then RoleBinding, template rules + kubedash.io labels.
    assert k8s.calls == [
        ("apply_role", NS, f"kubedash-{p.template}"),
        (
            "apply_role_binding", NS, f"kubedash-{p.user_sub}-{NS}",
            f"kubedash-{p.template}", p.user_sub,
        ),
    ]
    assert k8s.last_rules == RULES_NS
    assert k8s.last_labels == {"kubedash.io/user": p.user_sub, "kubedash.io/template": p.template}
    # The binding row was committed + audited (visible now; the fixture rolls
    # the session back afterwards, not the committed rows).
    row = db_sess.session.get(ClusterBinding, binding.id)
    assert row is not None and row.user_id == p.user_id
    audit = db_sess.session.execute(
        db_sess.select(AuditLog).filter_by(action="bind", actor_sub=p.admin_sub)
    ).scalar_one()
    assert audit.target == p.user_sub
    assert audit.template == p.template
    assert audit.namespace == NS


def test_bind_cluster_scoped_template(app, db_sess, _unique: str) -> None:
    """TRIANGULATE: a cluster-scoped template (no namespace) takes the
    cluster Role/ClusterRoleBinding path with the ``-cluster`` suffix."""
    p = _seed(db_sess, _unique, template_scope="cluster", rules=RULES_CLUSTER)
    k8s = FakeK8s()
    binding = _bind(p, k8s, db_sess, namespace=None)
    assert binding.namespace is None
    assert k8s.calls == [
        ("apply_cluster_role", f"kubedash-{p.template}"),
        ("apply_cluster_role_binding", f"kubedash-{p.user_sub}-cluster",
         f"kubedash-{p.template}", p.user_sub),
    ]
    assert k8s.last_rules == RULES_CLUSTER


def test_rebind_is_noop(app, db_sess, _unique: str) -> None:
    """SATISFIES rebinding-the-same-binding-is-a-no-op: the existence check
    runs BEFORE any k8s call — no second apply, no new audit row."""
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    b1 = _bind(p, k8s, db_sess)
    calls_after_first = len(k8s.calls)
    b2 = _bind(p, k8s, db_sess)
    assert b2.id == b1.id
    assert len(k8s.calls) == calls_after_first  # no second apply
    n_audit = db_sess.session.execute(
        db_sess.select(AuditLog).filter_by(action="bind", actor_sub=p.admin_sub)
    ).scalars().all()
    assert len(n_audit) == 1  # no new audit row


@pytest.mark.parametrize("scope, namespace", [("cluster", NS), ("namespace", None)])
def test_scope_mismatch_is_422(
    app, db_sess, _unique: str, scope: str, namespace: str | None
) -> None:
    """SATISFIES binding-with-a-mismatched-scope-is-rejected: the only stable
    422 is InvalidKubeconfigError; nothing is applied in the cluster."""
    p = _seed(db_sess, _unique, template_scope=scope)
    k8s = FakeK8s()
    with pytest.raises(InvalidKubeconfigError) as exc:
        _bind(p, k8s, db_sess, namespace=namespace)
    assert k8s.calls == []
    if namespace is not None:
        assert "cluster-scoped" in str(exc.value.message)
    else:
        assert "requires a namespace" in str(exc.value.message)


def test_missing_template_is_404(app, db_sess, _unique: str) -> None:
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    with pytest.raises(ResourceKindNotSupportedError) as exc:
        _bind(p, k8s, db_sess, template="nope")
    assert "template 'nope' not found" in str(exc.value.message)
    assert k8s.calls == []


def test_missing_user_is_404(app, db_sess, _unique: str) -> None:
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    with pytest.raises(ResourceKindNotSupportedError) as exc:
        _bind(p, k8s, db_sess, user_sub="ghost")
    assert "user 'ghost' not found" in str(exc.value.message)
    assert k8s.calls == []


def test_missing_cluster_is_404(app, db_sess, _unique: str) -> None:
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    with pytest.raises(ClusterNotFoundError):
        _bind(p, k8s, db_sess, cluster_id=9999)


def test_unreachable_cluster_records_nothing(app, db_sess, _unique: str) -> None:
    """SATISFIES binding-against-an-unreachable-cluster-records-nothing:
    the k8s call raises, ClusterUnreachableError (502) propagates, and NO
    binding row is committed."""
    p = _seed(db_sess, _unique)
    k8s = FakeK8s(raise_unreachable=True)
    with pytest.raises(ClusterUnreachableError):
        _bind(p, k8s, db_sess)
    rows = db_sess.session.execute(
        db_sess.select(ClusterBinding).filter_by(user_id=p.user_id)
    ).scalars().all()
    assert rows == []


def test_unbind_deletes_rolebinding_and_gc_keeps_role(app, db_sess, _unique: str) -> None:
    """SATISFIES unbinding-the-last-user-deletes-the-cluster-role (first
    half: a second user still references the Role, so it stays)."""
    p = _seed(db_sess, _unique)
    sub2 = f"sub2-{_unique}"
    db_sess.session.add(User(sub=sub2, status="active"))
    db_sess.session.commit()
    k8s = FakeK8s()
    _bind(p, k8s, db_sess)
    _bind(p, k8s, db_sess, user_sub=sub2)
    permission.unbind(
        user_sub=p.user_sub, cluster_id=p.cluster_id, namespace=NS,
        actor_sub=p.admin_sub, db_session=db_sess.session, k8s=k8s,
    )
    assert ("delete_role_binding", NS, f"kubedash-{p.user_sub}-{NS}") in k8s.calls
    assert not any(c[0] == "delete_role" for c in k8s.calls)  # sub2 still bound
    assert (
        db_sess.session.execute(
            db_sess.select(ClusterBinding).filter_by(user_id=p.user_id)
        ).scalars().all()
        == []
    )


def test_unbind_last_referrer_deletes_role(app, db_sess, _unique: str) -> None:
    """SATISFIES unbinding-the-last-user-deletes-the-cluster-role (second
    half: the last referrer's unbind deletes the Role)."""
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    _bind(p, k8s, db_sess)
    permission.unbind(
        user_sub=p.user_sub, cluster_id=p.cluster_id, namespace=NS,
        actor_sub=p.admin_sub, db_session=db_sess.session, k8s=k8s,
    )
    assert ("delete_role", NS, f"kubedash-{p.template}") in k8s.calls
    audit = db_sess.session.execute(
        db_sess.select(AuditLog).filter_by(action="unbind", actor_sub=p.admin_sub)
    ).scalar_one()
    assert audit.target == p.user_sub


def test_unbind_cluster_scoped_gc_deletes_cluster_role(app, db_sess, _unique: str) -> None:
    """TRIANGULATE (GC, cluster scope): a cluster-scoped binding's unbind
    deletes the ClusterRole (not a namespaced Role)."""
    p = _seed(db_sess, _unique, template_scope="cluster")
    k8s = FakeK8s()
    _bind(p, k8s, db_sess, namespace=None)
    permission.unbind(
        user_sub=p.user_sub, cluster_id=p.cluster_id, namespace=None,
        actor_sub=p.admin_sub, db_session=db_sess.session, k8s=k8s,
    )
    assert ("delete_cluster_role_binding", f"kubedash-{p.user_sub}-cluster") in k8s.calls
    assert ("delete_cluster_role", f"kubedash-{p.template}") in k8s.calls
    assert not any(c[0] in ("delete_role", "delete_role_binding") for c in k8s.calls)


def test_unbind_missing_is_404(app, db_sess, _unique: str) -> None:
    """SATISFIES unbinding-a-missing-binding-is-a-404: NoBindingsError and
    nothing is deleted in the cluster."""
    p = _seed(db_sess, _unique)
    k8s = FakeK8s()
    with pytest.raises(NoBindingsError):
        permission.unbind(
            user_sub=p.user_sub, cluster_id=p.cluster_id, namespace=NS,
            actor_sub=p.admin_sub, db_session=db_sess.session, k8s=k8s,
        )
    assert k8s.calls == []


# ---------------------------------------------------------------------------
# core.security — SATISFIES disabled-user-is-rejected + the T4 admin gate.
# ---------------------------------------------------------------------------


def test_disabled_user_rejected_at_auth(app, db_sess, _unique: str) -> None:
    """SATISFIES disabled-user-is-rejected: _load_user_for_claims is the
    single choke point both entry paths (_auth_check AND require_auth) hit;
    a disabled row 401s there."""
    from app.core import security
    from app.core.errors import UnauthorizedError

    sub = f"disabled-{_unique}"
    db_sess.session.add(User(sub=sub, status="disabled"))
    db_sess.session.commit()
    with app.app_context(), pytest.raises(UnauthorizedError):
        security._load_user_for_claims({"sub": sub})


def test_require_admin_denies_non_admin(app) -> None:
    from app.core import security

    with app.app_context():
        flask_g.current_user = SimpleNamespace(role="user")
        with pytest.raises(RbacDeniedError):
            security.require_admin()
    # Clean up: the app fixture's rollback does not reset g (it is per-context,
    # not per-DB-transaction) — the context push above already popped on exit,
    # which discards the attribute with it.


def test_require_admin_passes_admin(app) -> None:
    from app.core import security

    with app.app_context():
        flask_g.current_user = SimpleNamespace(role="admin")
        security.require_admin()
