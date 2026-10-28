"""Task 2 — the Postgres task-queue core on ``tasks`` (ADR-0029).

Queue scenarios (acceptance.feature):
- ``enqueue-then-claim-returns-the-task-path``
- ``concurrent-claimers-never-double-claim``
- ``failed-task-retries-with-backoff-then-dead-letters``
- ``crashed-claim-is-requeued-by-the-time-based-reaper``

The ``app`` fixture (tests/conftest.py) is Testcontainers Postgres +
``db.create_all()``; the ``tasks`` table comes from Task 1's model.

Isolation: the ``app`` fixture is function-scoped but the Postgres
CONTAINER is session-scoped, so the ``tasks`` table is shared across the
whole file and rows of earlier tests are still sitting in it. Every test
therefore (a) keys off its own row via a unique path / id, and (b) the
``task_id`` fixture sweeps its rows in teardown. The reaper test's
``reap()`` counts only its own stale row (every other row is
non-``processing`` or fresh — its own post-reap row is pending, the
concurrent test's rows were all claimed, nothing else is stale).
"""

from __future__ import annotations

import threading
import uuid

import pytest
from sqlalchemy import text

from app.core import pgqueue
from app.extensions import db


def _row(task_id: int):
    """Fresh connection per read — never trust the app-scoped session's
    identity map for a row another connection mutated mid-test."""
    with db.engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT status, attempts, locked_by, locked_at, available_at, path "
                "FROM tasks WHERE id = :id"
            ),
            {"id": task_id},
        ).one()


def _task_id(path: str) -> int:
    with db.engine.connect() as conn:
        return conn.execute(text("SELECT id FROM tasks WHERE path = :p"), {"p": path}).scalar_one()


@pytest.fixture()
def engine(app):
    """The fixture app's engine, with its app context active.

    Every read/write in these tests goes through ``db.engine`` connections
    (the queue functions AND the test's own asserts) — never the
    app-scoped ``db.session``: claim/fail/reap run on their OWN connections,
    and the app-scoped session's identity map would hand back pre-claim
    stale copies. The teardown ``dispose()`` is load-bearing: a test may
    leave a pooled connection checked back in mid-transaction, and an idle
    open transaction on a pooled connection is rolled back when the NEXT
    test checks out a connection — which silently undoes other
    connections' commits mid-session.
    """
    with app.app_context():
        try:
            yield db.engine
        finally:
            db.session.rollback()
            db.engine.dispose()


@pytest.fixture()
def task_id(app, engine):
    """One fresh, immediately-claimable pending row per test (isolated by a
    unique path), swept away in teardown."""
    path = f"app.tasks.test.{uuid.uuid4().hex}"
    pgqueue.enqueue(path, engine)
    yield _task_id(path)
    with db.engine.begin() as conn:
        # sweep by path (the row may have been re-queued mid-test; the path
        # is unique per test, so it is the stable key)
        conn.execute(text("DELETE FROM tasks WHERE path = :p"), {"p": path})


def test_enqueue_then_claim_returns_path(app, engine, task_id):
    # BDD: enqueue-then-claim-returns-the-task-path
    path = _row(task_id).path
    assert pgqueue.claim(engine, "replica-a") == (path, task_id)

    row = _row(task_id)
    assert row.status == "processing"
    assert row.locked_by == "replica-a"
    assert row.locked_at is not None
    assert row.attempts == 0  # attempts counts failures, not claims


def test_two_concurrent_claimers_do_not_double_claim(app, engine):
    # BDD: concurrent-claimers-never-double-claim
    base = uuid.uuid4().hex
    ids = []
    for i in range(50):
        pgqueue.enqueue(f"app.tasks.test.{base}.{i}", engine)
        ids.append(_task_id(f"app.tasks.test.{base}.{i}"))

    claims: list[tuple[str, int] | None] = [None] * 10
    barrier = threading.Barrier(10)  # fire all 10 claims at the same instant

    def _claim(i: int) -> None:
        barrier.wait()
        claims[i] = pgqueue.claim(engine, f"replica-{i}")

    threads = [threading.Thread(target=_claim, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    got = [c for c in claims if c is not None]
    assert len(got) == 10, "exactly one claim per thread"
    assert len({c[0] for c in got}) == 10, "no two threads claimed the same row"

    with db.engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, locked_by FROM tasks WHERE id = ANY(:ids)"),
            {"ids": ids},
        ).all()
    claimed = [r for r in rows if r.locked_by is not None]
    assert len(claimed) == 10
    assert len({r.id for r in claimed}) == 10  # 10 distinct rows
    assert len({r.locked_by for r in claimed}) == 10  # 10 distinct claimants
    # teardown: remove this test's 50 rows
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM tasks WHERE id = ANY(:ids)"), {"ids": ids})


def test_reaper_requeues_stale_processing(app, engine, task_id):
    # BDD: crashed-claim-is-requeued-by-the-time-based-reaper
    path = _row(task_id).path
    assert pgqueue.claim(engine, "crashed-replica") == (path, task_id)

    # crash the worker: backdate locked_at 3 min (past the 120 s stale line)
    with db.engine.begin() as conn:
        conn.execute(
            text("UPDATE tasks SET locked_at = now() - interval '3 minutes' WHERE id = :id"),
            {"id": task_id},
        )

    assert pgqueue.reap(engine, stale_seconds=120) == 1

    row = _row(task_id)
    assert row.status == "pending"
    assert row.locked_by is None
    assert row.locked_at is None
    # a crashed claim does not count as a failure: attempts stays 0, and the
    # reaper's backoff (60 * 5^0 = 60 s) defers the row's re-availability
    assert row.attempts == 0
    with db.engine.connect() as conn:
        delta = conn.execute(
            text(
                "SELECT EXTRACT(EPOCH FROM (available_at - now()))::int FROM tasks WHERE id = :id"
            ),
            {"id": task_id},
        ).scalar_one()
    assert pgqueue.backoff_seconds(0) <= delta <= pgqueue.backoff_seconds(0) + 15


def test_fail_dead_letters_at_three_attempts(app, engine, task_id):
    # BDD: failed-task-retries-with-backoff-then-dead-letters
    pgqueue.claim(engine, "replica-b")
    for _ in range(3):
        pgqueue.fail(task_id, engine)

    row = _row(task_id)
    assert row.status == "failed"
    assert row.attempts == 3


def test_fail_backoff_requeues(app, engine, task_id):
    # BDD: failed-task-retries-with-backoff-then-dead-letters
    pgqueue.claim(engine, "replica-c")
    pgqueue.fail(task_id, engine)

    row = _row(task_id)
    assert row.status == "pending"
    assert row.attempts == 1  # the first observed failure
    assert row.locked_by is None
    assert row.locked_at is None
    with db.engine.connect() as conn:
        future = conn.execute(
            text("SELECT available_at > now() FROM tasks WHERE id = :id"),
            {"id": task_id},
        ).scalar_one()
    assert future is True


def test_backoff_curve():
    # TRIANGULATE: the curve the reaper and fail share, at several points.
    assert pgqueue.backoff_seconds(0) == 60
    assert pgqueue.backoff_seconds(1) == 300
    assert pgqueue.backoff_seconds(2) == 600  # 900 capped
    assert pgqueue.backoff_seconds(3) == 600
    assert pgqueue.MAX_ATTEMPTS == 3
    assert pgqueue.BACKOFF_CAP_SECONDS == 600
    assert pgqueue.REAPER_STALE_SECONDS == 120
