"""Task 4 — the Postgres jti deny-list on ``revoked_jtis`` (ADR-0030).

Scenarios (acceptance.feature):
- ``revoked-jti-is-rejected-on-the-verify-hook`` (deny-list half — the PK
  lookup; the 401 half lands in the Task 6 verify-hook call site)

The ``app`` fixture (tests/conftest.py) is Testcontainers Postgres +
``db.create_all()``; the ``revoked_jtis`` table comes from Task 1's model.

Isolation: the ``app`` fixture is function-scoped but the Postgres
CONTAINER is session-scoped, so the ``revoked_jtis`` table is shared
across the whole file and rows of earlier tests are still sitting in it.
Every test therefore (a) uses fresh uuid4 jtis, and (b) the ``jti``
fixture sweeps its row in teardown. The ``reap_expired`` test sweeps the
table in setup so its count is exact.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.extensions import db
from app.services import revocation


@pytest.fixture()
def engine(app):
    """The fixture app's engine, with its app context active.

    Every read/write in these tests goes through ``db.engine`` connections
    (the revocation functions AND the test's own asserts) — never the
    app-scoped ``db.session``: the revocation functions run on their OWN
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
def jti(app, engine):
    """One fresh jti per test, swept away in teardown."""
    j = uuid.uuid4()
    yield j
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM revoked_jtis WHERE jti = :j"), {"j": j})


def _expire(j: uuid.UUID) -> None:
    """Backdate a row into the past — the test-side equivalent of a TTL
    elapsing, without sleeping."""
    with db.engine.begin() as conn:
        conn.execute(
            text("UPDATE revoked_jtis SET expires_at = now() - interval '1 hour' WHERE jti = :j"),
            {"j": j},
        )


def test_revoke_then_is_revoked(app, engine, jti):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook
    assert revocation.is_revoked(engine, jti) is False
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    assert revocation.is_revoked(engine, jti) is True


def test_a_different_jti_is_not_revoked(app, engine, jti):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    assert revocation.is_revoked(engine, uuid.uuid4()) is False


def test_expired_jti_reads_as_not_revoked(app, engine, jti):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook — a deny-list hit
    # only counts before the token's own expiry.
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    _expire(jti)
    assert revocation.is_revoked(engine, jti) is False


def test_reap_expired_deletes_only_passed_jtis(app, engine, jti):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook (reaper half)
    # Sweep the shared table in setup so the reaped count is exact.
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM revoked_jtis"))
    passed = jti
    fresh = uuid.uuid4()
    revocation.revoke_jti(engine, passed, ttl_seconds=900)
    revocation.revoke_jti(engine, fresh, ttl_seconds=900)
    _expire(passed)

    assert revocation.reap_expired(engine) == 1  # only the backdated row

    assert revocation.is_revoked(engine, passed) is False
    assert revocation.is_revoked(engine, fresh) is True


def test_double_revoke_is_idempotent(app, engine, jti):
    # TRIANGULATE: a double-revoke must not raise (the jti is the PK).
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    assert revocation.is_revoked(engine, jti) is True
    with db.engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM revoked_jtis WHERE jti = :j"), {"j": jti}
        ).scalar_one()
    assert n == 1


def test_lookup_plans_as_pk_index_scan(app, engine, jti):
    # findings #1: the verify hook is a PK lookup with jti bound as a
    # parameter — no function in the WHERE clause on the key, so the jti
    # predicate plans as an index scan on the PK. The plan is a plain
    # ``Index Scan`` (NOT an ``Index Only Scan``): ``expires_at`` is not
    # indexed, so Postgres fetches the row's value (a heap recheck, not an
    # index-only heap scan — either way one PK probe, no seq scan).
    # (``expires_at > now()`` stays in the WHERE — TTL logic, not a lookup
    # key.)
    revocation.revoke_jti(engine, jti, ttl_seconds=900)
    with db.engine.connect() as conn:
        plan = "\n".join(
            r[0]
            for r in conn.execute(
                text("EXPLAIN SELECT jti FROM revoked_jtis WHERE jti = :j AND expires_at > now()"),
                {"j": jti},
            )
        )
    assert "Index Scan using revoked_jtis_pkey" in plan
