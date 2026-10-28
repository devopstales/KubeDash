"""Task 6 — the SAR verdict cache on the Postgres ``kv`` table
(ADR-0030, TICKET-06).

Scenarios (acceptance.feature):
- ``sar-cache-hit-never-reasks-the-cluster`` — ``rbac.can`` on a cached
  key serves from ``kv`` and the throwing ``pool.get`` is never called;
  a miss asks the cluster once and stores the verdict under the UNCHANGED
  ADR-0004 key shape (``sar:<...>`` with every SAR attribute in the key).

The ``app`` fixture (tests/conftest.py) is Testcontainers Postgres +
``db.create_all()``; the ``kv`` table comes from Task 1's model.
Isolation: the Postgres CONTAINER is session-scoped, so every test keys
off a unique ``sar:`` prefix (its own uuid sub) and sweeps its rows in
teardown (same pattern as Task 4's test files).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.extensions import db
from app.services import rbac


@pytest.fixture()
def engine(app):
    """The fixture app's engine, with its app context active (same
    contract as Task 4's engine fixtures — own connections, dispose on
    teardown so a pooled idle transaction cannot roll back commits)."""
    with app.app_context():
        try:
            yield db.engine
        finally:
            db.session.rollback()
            db.engine.dispose()


def _user(sub: str = "u-1") -> SimpleNamespace:
    return SimpleNamespace(sub=sub)


def _cluster(cid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=cid)


def _client_allows(verbs: set[str]) -> SimpleNamespace:
    """A FakeK8s whose AuthorizationV1Api answers a canned SAR verdict."""

    class FakeStatus:
        def __init__(self, ok: bool) -> None:
            self.allowed = ok

    class FakeSarApi:
        def create_self_subject_access_review(self, body) -> SimpleNamespace:
            # The SAR nests the attributes under ``spec`` (k8s wire shape);
            # the kubernetes client builds ``resource_attributes`` into a
            # V1ResourceAttributes model (k8s_client.py's _sar_allowed
            # passes a dict; the model validates + camelCase-aliases it).
            return SimpleNamespace(
                status=FakeStatus(body.spec.resource_attributes.verb in verbs)
            )

    return SimpleNamespace(_auth_api=FakeSarApi())


def _boom(_c):
    raise AssertionError("pool.get called on a cache hit")


def _sub() -> str:
    """A unique sub per test: its rows are then exact (the kv table is
    shared across the session-scoped container, so constant subs would
    carry rows across tests)."""
    return f"u-{uuid.uuid4().hex}"


def test_cache_hit_never_reasks_the_cluster(app, engine, monkeypatch):
    # BDD: sar-cache-hit-never-reasks-the-cluster
    sub = _sub()
    key = rbac._cache_key(1, sub, "list", "pods")
    rbac._cache_set(engine, key, "1")
    monkeypatch.setattr(rbac.pool, "get", _boom)
    assert rbac.can(_user(sub), _cluster(), "list", "pods", None, None, engine=engine) is True


def test_cache_hit_serves_denial_from_kv(app, engine, monkeypatch):
    # BDD: sar-cache-hit-never-reasks-the-cluster (the "0" half — a cached
    # DENIAL also answers without re-asking the cluster).
    sub = _sub()
    key = rbac._cache_key(1, sub, "delete", "pods")
    rbac._cache_set(engine, key, "0")
    monkeypatch.setattr(rbac.pool, "get", _boom)
    assert rbac.can(_user(sub), _cluster(), "delete", "pods", None, None, engine=engine) is False


def test_miss_asks_once_and_caches_under_the_unchanged_key(app, engine, monkeypatch):
    # BDD: sar-cache-hit-never-reasks-the-cluster — a miss goes to the
    # cluster ONCE, stores the verdict under the ADR-0004 key shape
    # (unchanged verbatim), and the next call is a hit.
    sub = _sub()
    key = rbac._cache_key(1, sub, "list", "pods")
    monkeypatch.setattr(rbac.pool, "get", lambda c: _client_allows({"list"}))
    assert rbac.can(_user(sub), _cluster(), "list", "pods", None, None, engine=engine) is True
    # The verdict is in the kv table under the exact frozen key.
    with db.engine.connect() as conn:
        stored = conn.execute(
            text("SELECT value FROM kv WHERE key = :k"), {"k": key}
        ).scalar_one()
    assert stored == "1"
    # The next call is a hit: the pool is never reached again.
    monkeypatch.setattr(rbac.pool, "get", _boom)
    assert rbac.can(_user(sub), _cluster(), "list", "pods", None, None, engine=engine) is True


def test_can_threads_the_engine_to_the_storage_seam(app, engine, monkeypatch):
    # TRIANGULATE: ``can`` must forward the caller's engine to BOTH the
    # read and the write (a stale/globally-captured engine would cache in
    # the wrong place — the seam the api-tier tests rely on).
    seen: list[tuple[object, str]] = []
    monkeypatch.setattr(rbac, "_cache_get", lambda e, k: seen.append(("get", (e, k))) or None)
    monkeypatch.setattr(rbac, "_cache_set", lambda e, k, v: seen.append(("set", (e, k))) or None)
    monkeypatch.setattr(rbac.pool, "get", lambda c: _client_allows({"list"}))
    rbac.can(_user("u-1"), _cluster(), "list", "pods", None, None, engine=engine)
    assert seen == [
        ("get", (engine, "sar:1:u-1:list:pods:::")),
        ("set", (engine, "sar:1:u-1:list:pods:::")),
    ]


def test_expired_verdict_is_a_miss(app, engine, monkeypatch):
    # TRIANGULATE: a backdated (TTL-passed) verdict reads as a miss — the
    # cluster is asked again (the TTL half).
    sub = _sub()
    key = rbac._cache_key(1, sub, "list", "pods")
    rbac._cache_set(engine, key, "1")
    with db.engine.begin() as conn:
        conn.execute(
            text("UPDATE kv SET expires_at = now() - interval '1 hour' WHERE key = :k"),
            {"k": key},
        )
    monkeypatch.setattr(rbac.pool, "get", lambda c: _client_allows(set()))
    assert rbac.can(_user(sub), _cluster(), "list", "pods", None, None, engine=engine) is False
    # the re-ask re-cached the fresh denial
    with db.engine.connect() as conn:
        stored = conn.execute(
            text("SELECT value FROM kv WHERE key = :k"), {"k": key}
        ).scalar_one()
    assert stored == "0"


def test_a_different_sub_is_a_different_key(app, engine, monkeypatch):
    # TRIANGULATE: a hit for u-1 must not answer for u-2 (the sub is in
    # the key — ADR-0004 addendum). Both subs are unique, so u-1's row
    # exists and u-2's key is absent.
    u1, u2 = _sub(), _sub()
    monkeypatch.setattr(rbac.pool, "get", lambda c: _client_allows({"list"}))
    assert rbac.can(_user(u1), _cluster(), "list", "pods", None, None, engine=engine) is True
    # u-2 is unknown → a miss that asks the pool (which would be _boom on a
    # hit, so it throws if u-1's row answers for u-2). A throwing client
    # proves the miss reached the cluster, i.e. u-2's own key was absent.
    import pytest

    monkeypatch.setattr(rbac.pool, "get", _boom)
    with pytest.raises(AssertionError, match="pool.get called"):
        rbac.can(_user(u2), _cluster(), "list", "pods", None, None, engine=engine)

