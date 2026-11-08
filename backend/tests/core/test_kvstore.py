"""Task 4 — the Postgres TTL key-value core on ``kv`` (ADR-0030).

Scenarios (acceptance.feature):
- ``oidc-state-is-stored-and-consumed-once`` (kv half — the set/get/delete
  round-trip; the "second consume" half lands in the Task 6 call site)

The ``app`` fixture (tests/conftest.py) is Testcontainers Postgres +
``db.create_all()``; the ``kv`` table comes from Task 1's model.

Isolation: the ``app`` fixture is function-scoped but the Postgres
CONTAINER is session-scoped, so the ``kv`` table is shared across the
whole file and rows of earlier tests are still sitting in it. Every test
therefore (a) keys off its own rows via a unique key prefix, and (b) the
``keys`` fixture sweeps its rows in teardown. The ``kv_reap`` test sweeps
the table in setup so its count is exact.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.core import kvstore
from app.extensions import db


@pytest.fixture()
def engine(app):
    """The fixture app's engine, with its app context active.

    Every read/write in these tests goes through ``db.engine`` connections
    (the kvstore functions AND the test's own asserts) — never the
    app-scoped ``db.session``: the kvstore functions run on their OWN
    connections, and the app-scoped session's identity map would hand back
    pre-mutation stale copies. The teardown ``dispose()`` is load-bearing:
    a test may leave a pooled connection checked back in mid-transaction,
    and an idle open transaction on a pooled connection is rolled back when
    the NEXT test checks out a connection — which silently undoes other
    connections' commits mid-session.
    """
    with app.app_context():
        try:
            yield db.engine
        finally:
            db.session.rollback()
            db.engine.dispose()


@pytest.fixture()
def keys(app, engine):
    """One unique key prefix per test, swept away in teardown."""
    base = uuid.uuid4().hex
    yield f"kvtest.{base}."
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM kv WHERE key LIKE :p"), {"p": f"kvtest.{base}%"})


def _expire(key: str) -> None:
    """Backdate a row into the past — the test-side equivalent of a TTL
    elapsing, without sleeping."""
    with db.engine.begin() as conn:
        conn.execute(
            text("UPDATE kv SET expires_at = now() - interval '1 hour' WHERE key = :k"),
            {"k": key},
        )


def test_set_then_get_round_trips(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once
    kvstore.kv_set(engine, keys + "state", "nonce-value", ttl_seconds=300)
    assert kvstore.kv_get(engine, keys + "state") == "nonce-value"


def test_get_absent_key_is_none(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once
    assert kvstore.kv_get(engine, keys + "absent") is None


def test_expired_key_reads_as_absent(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once
    kvstore.kv_set(engine, keys + "state", "nonce-value", ttl_seconds=300)
    _expire(keys + "state")
    # an expired row is a miss, not an error, and the row is NOT deleted on
    # read (kv_delete is the one-shot delete; the reaper prunes)
    assert kvstore.kv_get(engine, keys + "state") is None
    with db.engine.connect() as conn:
        present = conn.execute(
            text("SELECT 1 FROM kv WHERE key = :k"), {"k": keys + "state"}
        ).scalar_one()
    assert present == 1


def test_set_overwrites_an_existing_key(app, engine, keys):
    # TRIANGULATE: the upsert path (existing key, different value).
    kvstore.kv_set(engine, keys + "state", "first", ttl_seconds=300)
    kvstore.kv_set(engine, keys + "state", "second", ttl_seconds=60)
    assert kvstore.kv_get(engine, keys + "state") == "second"


def test_tombstone_round_trips(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once — a one-shot state can be
    # stored as a NULL value; the row (not the value) is what the consumer
    # reads.
    kvstore.kv_set(engine, keys + "tombstone", None, ttl_seconds=300)
    with db.engine.connect() as conn:
        row = conn.execute(
            text("SELECT value FROM kv WHERE key = :k"), {"k": keys + "tombstone"}
        ).one()
    assert row.value is None


def test_delete_is_one_shot(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once — consume is one-shot.
    kvstore.kv_set(engine, keys + "state", "nonce-value", ttl_seconds=300)
    assert kvstore.kv_delete(engine, keys + "state") is True  # first consume
    assert kvstore.kv_get(engine, keys + "state") is None
    assert kvstore.kv_delete(engine, keys + "state") is False  # second consume
    assert kvstore.kv_delete(engine, keys + "absent") is False


def test_reap_deletes_only_expired_rows(app, engine, keys):
    # BDD: oidc-state-is-stored-and-consumed-once (reaper half)
    # Sweep the shared table in setup so the reaped count is exact.
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM kv"))
    expired = keys + "expired"
    fresh = keys + "fresh"
    kvstore.kv_set(engine, expired, "old", ttl_seconds=300)
    kvstore.kv_set(engine, fresh, "new", ttl_seconds=300)
    _expire(expired)

    assert kvstore.kv_reap(engine) == 1  # only the backdated row

    assert kvstore.kv_get(engine, expired) is None
    assert kvstore.kv_get(engine, fresh) == "new"
