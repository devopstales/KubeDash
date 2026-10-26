"""Gunicorn entrypoint (ADR-0006 single container: API + static SPA).

``KUBEDASH_ROLE=leader`` (default: ``worker``) additionally starts:
  - the ``Leader`` (Task 2, ADR-0008) — PG advisory lock + leader_lease row;
  - a daemon scheduler thread that enqueues the due tasks from ``INTERVALS``
    ONLY while ``leader.is_leader()`` is true. RQ's built-in cron is
    deliberately NOT used — it would fire on every replica regardless of
    leadership (the exact duplicate-job failure ADR-0008's gate prevents).

ADR-0040 (Gunicorn dev): the RQ worker itself runs in a CHILD PROCESS
(``_rq_worker_main``), not a daemon thread. WHY: RQ installs signal handlers
(``signal.signal`` for SIGINT/SIGTERM, plus a SIGALRM death-penalty around
each job) that only work on a process's MAIN thread. Under ``python wsgi.py``
the old thread was the main thread, so it worked; under Gunicorn the master's
main thread is the arbiter loop, so a thread-hosted worker raised ``ValueError:
signal only works in main thread``. A child process makes the RQ worker the
main thread of its own process — signals, the horse monitor, and per-job
forking all behave as RQ expects. The scheduler thread stays in the master and
reads ``leader.is_leader()`` (cheap cross-thread bool); it spawns the worker
child lazily on the first enqueue and lets it exit (``work(burst=True)``) when
the queue drains, re-spawning on the next interval.
"""
import logging
import os
import subprocess
import sys
import threading
import time

import rq
from flask import Flask

from app import _bootstrap_local_admin, create_app
from app.core.config import get_settings

log = logging.getLogger(__name__)


def _apply_proxyfix(app: Flask) -> None:
    """ADR-0026: trust the TLS edge's ``X-Forwarded-*`` when (and only when)
    we run behind it.

    WHY env-gated: the test client and the plain-HTTP dev fast path send no
    forwarded headers; unconditional ProxyFix would let a spoofed
    ``X-Forwarded-Proto`` flip ``request.is_secure`` — and with it the HSTS
    emission (security_headers reads ``request.is_secure``) and the
    Secure-cookie semantics. The gate reads Settings at CALL time (not import
    time) so the test can flip ``KUBEDASH_TLS_EDGE`` and re-apply.
    """
    if not get_settings().tls_edge:
        return
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


import os

# ADR-0028: the app is built in main() (not at import) so that importing
# wsgi is a no-op (test_worker_gate reloads it; test_proxyfix imports it for
# _apply_proxyfix). Gunicorn loads the module and calls main(); running as a
# script keeps dev behavior identical.
app: Flask | None = None

# RQ task path -> enqueue interval (seconds). The worker thread below is the
# scheduler: it enqueues a task only when it is due AND this replica leads.
INTERVALS: dict[str, int] = {
    "app.tasks.health.run": 60,
    "app.tasks.cluster_sync.run": 300,
}

# The scheduler thread (leader-gated) lives in the master; the RQ worker runs
# in a child PROCESS (ADR-0040 — see module docstring). worker_thread is the
# scheduler; worker_process is the spawned RQ child (None between drains).
worker_thread: threading.Thread | None = None
worker_process: subprocess.Popen | None = None
_worker_lock = threading.Lock()


def _rq_worker_main() -> None:
    """RQ worker entry point — runs as the MAIN thread of the child process.

    ``work(burst=True)`` drains the queue once and returns, so the process
    exits cleanly after each scheduler interval; the scheduler re-spawns it on
    the next due enqueue. ``app.app_context()`` wraps the drain so the task
    functions' ``db.session`` (Flask-SQLAlchemy, app-bound) resolves.
    """
    from app.extensions import redis_client

    with app.app_context():
        w = rq.Worker(["kubedash"], connection=redis_client)
        w.work(burst=True)


def _schedule_if_leader(leader_obj: object, queue: rq.Queue) -> None:
    """One scheduler tick: enqueue due tasks ONLY while this replica leads.

    ``leader_obj`` is typed as ``object``: the brief's unit test passes a
    structural fake (duck-typed ``is_leader()``), while ``_run`` passes a real
    ``Leader``. The interval accounting lives in ``_run``'s ``last`` map —
    this tick is intentionally pure so it can be driven with a fake leader +
    fake queue.
    """
    # leader_obj is a Leader (or a structural fake in tests) — the attribute
    # access is duck-typed by design. The brief's unit test passes a fake with
    # is_leader(); a missing attribute would be a caller bug (not a follower).
    is_leader = leader_obj.is_leader  # type: ignore[attr-defined]
    if not is_leader():
        return
    for path in INTERVALS:
        queue.enqueue(path)


def _start_worker_if_leader() -> None:
    """Spawn the leader-gated RQ scheduler (wsgi-level, not app-factory level
    — the factory must stay pure so tests can create apps freely).

    ADR-0040: the scheduler is a daemon thread in the master; it spawns the
    RQ worker as a CHILD PROCESS on the first enqueue (``_run_worker_child``)
    and lets it exit after each drain (``work(burst=True)``). The child is
    the main thread of its own process, so RQ's signal handlers + SIGALRM
    death-penalty work — the exact failure mode a thread-hosted worker hit
    under Gunicorn (master main thread = arbiter loop).
    """
    global worker_thread, worker_process

    settings = get_settings()
    if settings.kubedash_role != "leader":
        log.info("KUBEDASH_ROLE=%r — no RQ worker on this replica", settings.kubedash_role)
        return

    from app.core.leader import Leader
    from app.extensions import redis_client

    leader = Leader(settings, app)
    leader.start()

    def _run_worker_child() -> None:
        """Spawn (or re-spawn) the RQ worker child. Idempotent per interval.

        A live child is left alone (it will drain the freshly-enqueued job);
        a dead/absent one is re-spawned. ``start_new_session`` detaches the
        child from the master's process group so a Ctrl-C on ``task backend-run``
        doesn't signal the worker child mid-drain.
        """
        global worker_process
        with _worker_lock:
            if worker_process is not None and worker_process.poll() is None:
                return  # a live child is already draining the queue
            env = dict(os.environ)
            env.setdefault("PYTHONPATH", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            worker_process = subprocess.Popen(
                [sys.executable, "-c", "import wsgi; wsgi._rq_worker_main()"],
                env=env,
                start_new_session=True,
            )

    def _run() -> None:
        queue = rq.Queue("kubedash", connection=redis_client)
        last: dict[str, float] = {}
        while True:
            now = time.monotonic()
            due = False
            for path, interval in INTERVALS.items():
                # The leader check is PER TASK AND PER POLL — a leadership
                # loss stops all scheduling within one 5 s drain window.
                if leader.is_leader() and now - last.get(path, 0.0) >= interval:
                    queue.enqueue(path)
                    last[path] = now
                    due = True
            if due:
                _run_worker_child()
            time.sleep(5)  # poll cadence == the old max_idle_time drain window

    worker_thread = threading.Thread(target=_run, name="kubedash-worker", daemon=True)
    worker_thread.start()
    log.info("leader-gated RQ scheduler started (queue=kubedash, intervals=%s)", INTERVALS)


def main() -> Flask:
    """Build the app and start the leader-gated RQ scheduler.

    Called by Gunicorn (``wsgi:main``) and by ``python wsgi.py``. Importing
    wsgi is a no-op: ``app`` stays ``None`` until ``main()`` runs, so
    test modules that import wsgi (test_worker_gate reloads it; test_proxyfix
    imports ``_apply_proxyfix``) do not trigger the create_app fail-fast.
    """
    global app
    # ADR-0028: the static dir is derived from KUBEDASH_HOME (ini_config
    # .home_paths()["static"]), so there is no KUBEDASH_STATIC_DIR env to pass.
    app = create_app()

    # ADR-0026: wrap in ProxyFix only when behind the TLS edge. Ordered
    # BEFORE _bootstrap_local_admin on purpose: the bootstrap is a one-time
    # DB upsert that never reads request.is_secure, so the two are
    # independent — the ordering is documented here only so a future reader
    # doesn't "fix" it.
    _apply_proxyfix(app)

    # ADR-0021: the local-admin upsert runs at boot, after the factory (which
    # stays pure — no DB init inside create_app) and BEFORE Leader/RQ startup,
    # so the row exists before any task or request can read it. No-op when the
    # bootstrap env is unset. A missing table (tests that build the app before
    # db.create_all) is non-fatal: log and continue — the next boot (or an
    # explicit create_all) will upsert the row.
    try:
        _bootstrap_local_admin(app)
    except Exception:
        log.exception("local-admin bootstrap skipped (will retry next boot)")

    # Gunicorn loads the module without executing ``__main__`` (workers use
    # the module-level ``app``); running as a script keeps dev behavior
    # identical.
    _start_worker_if_leader()
    return app


if __name__ == "__main__":
    main()
    cert = os.environ.get("KUBEDASH_SSL_CERT")
    ssl_context = (
        (cert, os.environ["KUBEDASH_SSL_KEY"])
        if cert
        else None
    )
    # WHY env-only (not INI): FLASK_RUN_PORT, KUBEDASH_SSL_CERT, and
    # KUBEDASH_SSL_KEY are process-level knobs — they control HOW the server
    # listens, not WHAT the app is configured with. The INI is the app's
    # identity; the process port/SSL is the deployment's concern.
    cert = os.environ.get("KUBEDASH_SSL_CERT")
    ssl_context = (
        (cert, os.environ["KUBEDASH_SSL_KEY"])
        if cert
        else None
    )
    port = int(os.environ.get("FLASK_RUN_PORT", "8080"))
    app.run(port=port, ssl_context=ssl_context)
