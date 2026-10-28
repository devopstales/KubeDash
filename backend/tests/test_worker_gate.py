"""Worker-gate tests (Task 7 / ADR-0008).

Tier split:
- follower / leader-candidate gate: pure — reloads ``wsgi`` with a faked
  Leader and asserts the daemon worker thread spawns only on the leader role.
- enqueued-job-runs: needs Testcontainers Postgres (the pgqueue ``tasks``
  table) — marked ``integration``; env-blocked on this host, green in CI.
- ``_run_once``: pure unit tier on a fake leader + a pgqueue-shaped fake
  (``enqueue(path, engine)``).
"""

import importlib
import importlib.util
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core import ini_config

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
    "[security]\njwt_secret = test-jwt\n"
    "secret_key = test-enc-key-32-bytes-long!!!!\nadmin_password = test-pw\n"
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

    The worker thread reads ``leader.is_leader()`` every 5 s poll, so the
    fake Leader must stub BOTH ``start`` (no thread) and ``is_leader`` (the
    scheduler's gate). A real Leader would also race for the PG advisory lock
    on the sqlite test app.

    ADR-0029: the pgqueue worker is a daemon THREAD, not a child process —
    with ``is_leader`` faked False (default) the scheduler never enqueues and
    the sqlite claim/reap statements are no-ops, so the gate test stays pure
    — no Redis, no subprocess.
    """

    class _FakeLeader:
        """Structural fake for Leader — the gate test only asserts the
        worker thread is spawned on the leader role. ``start`` is a no-op
        (no real advisory-lock thread); ``is_leader`` is False so the
        scheduler never enqueues. Accepts the ``(settings, app)``
        constructor args ``wsgi`` passes."""

        def __init__(self, settings: object, app: object, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
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
    # ADR-0028: a prior module's KUBEDASH_HOME (e.g. conftest's session
    # home) wins on reload and the required [deployment]/[database] keys
    # are missing — restore both the home and the env DB/redis URLs the
    # module-level main() started with.
    monkeypatch.setenv("KUBEDASH_HOME", str(_ini_config_home))
    monkeypatch.setenv("KUBEDASH_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("KUBEDASH_REDIS_URL", "redis://localhost:6390/0")
    importlib.reload(wsgi)
    # ADR-0028: main() builds the app + starts the worker (the reload's
    # _start_worker_if_leader is now inside main). The role was faked above
    # via monkeypatch.setattr(wsgi.get_settings(), "kubedash_role", role), so
    # the gate branch is exercised by main()'s _start_worker_if_leader call.
    wsgi.main()


@pytest.fixture(autouse=True)
def _stop_worker(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stop the worker thread a leader-role test may have spawned (its loop
    would otherwise keep polling for the rest of the suite) and reset the wsgi
    globals for later tests.

    ADR-0029: there is no worker child process to reap — the worker IS the
    daemon thread. ``stop.wait(5)`` makes ``join(timeout=1)`` enough: the
    thread is in its wait most of the time.
    """
    yield
    thread = wsgi.worker_thread
    if thread is not None:
        thread.join(timeout=1)
        monkeypatch.setattr(wsgi, "worker_thread", None, raising=False)


def test_worker_thread_not_started_on_follower(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "follower")
    assert wsgi.worker_thread is None


def test_worker_thread_started_on_leader_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_wsgi(monkeypatch, "leader")
    assert wsgi.worker_thread is not None
    assert wsgi.worker_thread.daemon
    assert wsgi.worker_thread.name == "kubedash-worker"
    # ADR-0029: no RQ child process at all — the worker IS the daemon
    # thread the leader role starts eagerly. (The old worker_process global
    # is gone with the RQ child; its absence is the no-child assertion.)


def test_run_once_skips_when_not_leader() -> None:
    enqueued: list[tuple[str, object]] = []

    class _Leader:
        def is_leader(self) -> bool:
            return False

    class _Queue:
        def enqueue(self, path: str, engine: object) -> None:
            enqueued.append((path, engine))

    assert wsgi._run_once(_Leader(), _Queue(), object(), {}) is False
    assert enqueued == []


def test_run_once_enqueues_due_tasks_when_leader() -> None:
    enqueued: list[tuple[str, object]] = []

    class _Leader:
        def is_leader(self) -> bool:
            return True

    class _Queue:
        def enqueue(self, path: str, engine: object) -> None:
            enqueued.append((path, engine))

    last: dict[str, float] = {}
    assert wsgi._run_once(_Leader(), _Queue(), object(), last) is True
    assert sorted(path for path, _ in enqueued) == sorted(wsgi.INTERVALS)
    # the due-map is advanced, so an immediate second tick enqueues nothing
    assert wsgi._run_once(_Leader(), _Queue(), object(), last) is False
    assert len(enqueued) == len(wsgi.INTERVALS)


def test_reap_once_skips_when_not_leader() -> None:
    """The reaper is leader-gated: a follower sweeps nothing (the ADR-0029
    'crashed-claim-is-requeued' wiring half — only the leader runs it)."""
    import app.core.kvstore as _kv
    import app.core.pgqueue as _pq
    import app.services.revocation as _rev

    # The module must read the sweep functions from these modules at call
    # time (not bind them at its own import) for the monkeypatch to reach.
    assert wsgi.pgqueue is _pq
    assert wsgi.revocation is _rev
    assert wsgi.kvstore is _kv

    called: list[str] = []

    class _Leader:
        def is_leader(self) -> bool:
            return False

    mp = pytest.MonkeyPatch()
    mp.setattr(_pq, "reap", lambda engine, *a, **k: called.append("pgqueue") or 0)
    mp.setattr(_rev, "reap_expired", lambda engine: called.append("revocation") or 0)
    mp.setattr(_kv, "kv_reap", lambda engine: called.append("kv") or 0)
    try:
        wsgi._reap_once(_Leader(), object())
    finally:
        mp.undo()
    assert called == []


def test_reap_once_sweeps_when_leader() -> None:
    """The leader sweeps pgqueue.reap + revocation.reap_expired + kvstore.kv_reap
    — the 'crashed-claim-is-requeued-by-the-time-based-reaper' wiring half."""
    import app.core.kvstore as _kv
    import app.core.pgqueue as _pq
    import app.services.revocation as _rev

    called: list[str] = []

    class _Leader:
        def is_leader(self) -> bool:
            return True

    mp = pytest.MonkeyPatch()
    mp.setattr(_pq, "reap", lambda engine, *a, **k: called.append("pgqueue") or 3)
    mp.setattr(_rev, "reap_expired", lambda engine: called.append("revocation") or 1)
    mp.setattr(_kv, "kv_reap", lambda engine: called.append("kv") or 2)
    try:
        wsgi._reap_once(_Leader(), object())
    finally:
        mp.undo()
    assert called == ["pgqueue", "revocation", "kv"]


@pytest.mark.integration
def test_enqueued_job_runs_when_leader(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate must not just exist — a job enqueued while this replica is
    the leader's must actually execute (ADR-0008 prevents duplicate runs,
    not all runs). No Redis (ADR-0029): the queue is the Postgres ``tasks``
    table; the deterministic equivalent of draining the old RQ queue is one
    claim + run + complete against a Testcontainers engine.
    """
    from app.core import pgqueue
    from app.extensions import db

    with app.app_context():
        engine = db.engine
        ran: list[int] = []

        def fake_health() -> None:
            ran.append(1)

        monkeypatch.setattr("app.tasks.health.run", fake_health)

        pgqueue.enqueue("app.tasks.health.run", engine)
        claimed = pgqueue.claim(engine, "test-replica")
        assert claimed is not None
        path, task_id = claimed
        mod, _, fn = path.rpartition(".")
        import importlib as _importlib

        getattr(_importlib.import_module(mod), fn)()
        pgqueue.complete(task_id, engine)

    assert ran == [1]
