"""Worker-gate tests (Task 7 / ADR-0008).

Tier split:
- follower / leader-candidate gate: pure — reloads ``app.wsgi`` with a faked
  Leader and asserts the daemon worker thread spawns only on the leader role.
- enqueued-job-runs: needs a live Redis (``rq``'s queue) — marked
  ``integration``; env-blocked on this host, green in CI (with Docker).
- ``_schedule_if_leader``: pure unit tier on a fake leader + fake queue.
"""

import importlib
import importlib.util
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.leader import Leader

# wsgi.py lives at backend/wsgi.py (next to the app package), NOT at
# backend/app/wsgi.py — so `import app.wsgi` does not work. Load it by
# explicit path so the test is location-stable.
_WSGI_PATH = Path(__file__).resolve().parents[1] / "wsgi.py"


def _import_wsgi():
    spec = importlib.util.spec_from_file_location("wsgi", _WSGI_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {_WSGI_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["wsgi"] = module
    spec.loader.exec_module(module)
    return module


import sys  # noqa: E402

wsgi = _import_wsgi()  # module-level import; reload below re-executes


def _reload_wsgi(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    """Re-execute wsgi.py with the role faked + Leader.start() faked — a real
    Leader would race for the PG advisory lock on the sqlite test app.
    create_app() runs per reload with the default (dev) settings; the gate
    under test is the role branch, not the app factory.

    Note: pydantic-settings with ``env_prefix="KUBEDASH_"`` doubles the
    prefix for the ``kubedash_role`` field, so the env name is
    ``KUBEDASH_KUBEDASH_ROLE`` (same pattern as the existing
    ``KUBEDASH_KUBEDASH_JWT_SECRET``). Tests patch the Settings instance
    directly to keep the intent explicit.

    The default Redis (localhost:6379) is NOT dialed on this host — the
    ``rq.Worker`` constructor is faked so the gate test stays pure.
    """
    import rq

    class _FakeWorker:
        """Stand-in for rq.Worker — the gate test only asserts the thread
        is spawned, not that the worker drains a real queue. ``work`` is a
        no-op so the loop never touches a real Redis."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def work(self, *args: object, **kwargs: object) -> bool:
            return False

    class _FakeRedis:
        """Stand-in for the FlaskRedis instance — the worker thread's
        ``rq.Queue`` would otherwise dial the default Redis (localhost:6379)
        which is not up on this host."""

        def ping(self) -> bool:
            return True

    monkeypatch.setattr(wsgi.get_settings(), "kubedash_role", role)
    monkeypatch.setattr(Leader, "start", lambda self: None)
    monkeypatch.setattr(rq, "Worker", _FakeWorker)
    importlib.reload(wsgi)


@pytest.fixture(autouse=True)
def _stop_worker(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stop the worker thread a leader-role test may have spawned (its loop
    would otherwise keep draining the default-redis queue for the rest of
    the suite) and reset the wsgi globals for later tests.

    The fake ``rq.Worker.work`` returns immediately (no real Redis), so
    ``join`` returns as soon as the thread notices the stop — no 5 s block.
    """
    yield
    thread = wsgi.worker_thread
    if thread is not None:
        # The _run loop calls worker.work(max_idle_time=5) — the fake's
        # work() returns instantly, so the thread is between work() calls
        # most of the time and join(timeout=1) is enough.
        thread.join(timeout=1)
        monkeypatch.setattr(wsgi, "worker_thread", None, raising=False)
        monkeypatch.setattr(wsgi, "worker", None, raising=False)


def test_worker_thread_not_started_on_follower(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "follower")
    assert wsgi.worker_thread is None


def test_worker_thread_started_on_leader_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "leader")
    assert wsgi.worker_thread is not None
    assert wsgi.worker_thread.daemon
    assert wsgi.worker_thread.name == "kubedash-worker"
    assert wsgi.worker is not None


def test_schedule_if_leader_skips_when_not_leader() -> None:
    enqueued: list[str] = []

    class _Leader:
        def is_leader(self) -> bool:
            return False

    class _Queue:
        def enqueue(self, path: str) -> None:
            enqueued.append(path)

    wsgi._schedule_if_leader(_Leader(), _Queue())
    assert enqueued == []


def test_schedule_if_leader_enqueues_due_tasks_when_leader() -> None:
    enqueued: list[str] = []

    class _Leader:
        def is_leader(self) -> bool:
            return True

    class _Queue:
        def enqueue(self, path: str) -> None:
            enqueued.append(path)

    wsgi._schedule_if_leader(_Leader(), _Queue())
    assert sorted(enqueued) == sorted(wsgi.INTERVALS)


@pytest.mark.integration
def test_enqueued_job_runs_when_leader(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate must not just exist — a job enqueued while this replica is
    the leader's must actually execute (ADR-0008 prevents duplicate runs,
    not all runs). Needs a live Redis (Testcontainers): env-blocked on this
    host (no Docker), green in CI.

    The brief's snippet calls ``wsgi.worker.work_one()`` — rq 2.x has no
    work_one; the deterministic equivalent is a fresh ``rq.Worker`` on the
    Testcontainers Redis drained with ``work(burst=True)`` (process queued
    jobs, then return — never blocks).
    """
    import rq

    from app.extensions import redis_client

    client = redis_client._redis_client  # underlying redis-py client
    assert client is not None

    ran: list[int] = []

    def fake_health() -> None:
        ran.append(1)

    monkeypatch.setattr("app.tasks.health.run", fake_health)

    q = rq.Queue("kubedash", connection=client)
    q.enqueue("app.tasks.health.run")

    worker = rq.Worker(["kubedash"], connection=client)
    worker.work(burst=True)

    assert ran == [1]
