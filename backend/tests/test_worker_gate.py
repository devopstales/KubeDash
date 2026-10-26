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
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core import ini_config
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
# ADR-0028: wsgi.main() builds the app (create_app) — it now fail-fasts on
# missing REQUIRED keys, so set a fixture KUBEDASH_HOME + required env before
# the first main() call (below). Importing wsgi is a no-op (app stays None).
_ini_config_home = Path(__file__).resolve().parents[1] / "tests" / "_worker_gate_home"
_ini_config_home.mkdir(exist_ok=True)
(_ini_config_home / "kubedash.ini").write_text(
    "[DEFAULT]\napp_mode = development\n"
    "[security]\njwt_secret = test-jwt\nsecret_key = test-enc-key-32-bytes-long!!!!\nadmin_password = test-pw\n"
    "[database]\nurl = sqlite://\n"
    "[remote_cache]\nurl = redis://localhost:6390/0\n"
    "[bootstrap]\nbootstrap_admin_email = admin@local\n"
    "[deployment]\nadmin_kubeconfig = /test/admin.kubeconfig\n"
)
os.environ["KUBEDASH_HOME"] = str(_ini_config_home)
ini_config.reset()
wsgi.main()  # build app + start worker (leader-gated; role=worker by default)


def _reload_wsgi(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    """Re-execute wsgi.py with the role faked + Leader.start() faked — a real
    Leader would race for the PG advisory lock on the sqlite test app.
    create_app() runs per reload with the default (dev) settings; the gate
    under test is the role branch, not the app factory.

    The scheduler thread reads ``leader.is_leader()`` every 5 s poll, so the
    fake Leader must stub BOTH ``start`` (no thread) and ``is_leader`` (the
    scheduler's gate). A real Leader would also race for the PG advisory lock
    on the sqlite test app.

    ADR-0040: the RQ worker is a child process spawned lazily on the first
    due enqueue. With ``is_leader`` faked False (default) the scheduler never
    enqueues, so no child is spawned and the test stays pure — no Redis, no
    subprocess. (The old thread-hosted worker needed a faked ``rq.Worker`` to
    avoid dialing Redis at import; that seam is gone.)
    """
    class _FakeLeader:
        """Structural fake for Leader — the gate test only asserts the
        scheduler thread is spawned on the leader role. ``start`` is a no-op
        (no real advisory-lock thread); ``is_leader`` is False so the
        scheduler never enqueues or spawns a worker child. Accepts the
        ``(settings, app)`` constructor args ``wsgi`` passes."""

        def __init__(self, settings: object, app: object, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def is_leader(self) -> bool:
            return False

    import app.core.leader as _leader_mod

    monkeypatch.setattr(wsgi.get_settings(), "kubedash_role", role)
    monkeypatch.setattr(_leader_mod, "Leader", _FakeLeader)
    # FU-1: no-op the bootstrap hook at its SOURCE (the app package) so the
    # reload's `from app import _bootstrap_local_admin` re-binds the no-op
    # instead of the real PG upsert (which would run under a leaked Settings
    # singleton from the api-tier fixtures — order-dependent cross-tier bleed).
    import app as _app_pkg
    monkeypatch.setattr(_app_pkg, "_bootstrap_local_admin", lambda app: None)
    importlib.reload(wsgi)
    # ADR-0028: main() builds the app + starts the worker (the reload's
    # _start_worker_if_leader is now inside main). The role was faked above
    # via monkeypatch.setattr(wsgi.get_settings(), "kubedash_role", role), so
    # the gate branch is exercised by main()'s _start_worker_if_leader call.
    wsgi.main()


@pytest.fixture(autouse=True)
def _stop_worker(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stop the scheduler thread a leader-role test may have spawned (its loop
    would otherwise keep polling for the rest of the suite) and reset the wsgi
    globals for later tests.

    ADR-0040: the RQ worker is no longer thread-hosted — it's a child process
    spawned lazily on the first enqueue. The scheduler thread here only
    enqueues + spawns; with no tasks due it never spawns a child, so there's
    nothing to reap. ``join(timeout=1)`` is enough: the loop sleeps 5 s, so
    the thread is in its sleep most of the time.
    """
    yield
    thread = wsgi.worker_thread
    if thread is not None:
        thread.join(timeout=1)
        monkeypatch.setattr(wsgi, "worker_thread", None, raising=False)
        monkeypatch.setattr(wsgi, "worker_process", None, raising=False)


def test_worker_thread_not_started_on_follower(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "follower")
    assert wsgi.worker_thread is None
    assert wsgi.worker_process is None


def test_worker_thread_started_on_leader_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "leader")
    assert wsgi.worker_thread is not None
    assert wsgi.worker_thread.daemon
    assert wsgi.worker_thread.name == "kubedash-worker"
    # ADR-0040: no worker child is spawned until the first task is due; the
    # scheduler thread (not a worker) is what the leader role starts eagerly.
    assert wsgi.worker_process is None


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
