"""Gunicorn entrypoint (ADR-0006 single container: API + static SPA).

``KUBEDASH_ROLE=leader`` (default: ``worker``) additionally starts:
  - the ``Leader`` (ADR-0008) — PG advisory lock + leader_lease row;
  - a daemon worker thread (``kubedash-worker``) that is BOTH the scheduler
    and the worker (ADR-0029): it enqueues the due tasks from ``INTERVALS``
    ONLY while ``leader.is_leader()`` is true, and it claims from the
    Postgres ``tasks`` queue every 5 s regardless of leadership (the claim
    is cluster-wide via ``FOR UPDATE SKIP LOCKED`` — any replica may work).

ADR-0029 (RQ gone): the queue is Postgres, not Redis. The old RQ worker child
process (ADR-0040) is a daemon THREAD now — RQ is what needed signal handlers
in a main thread; plain task callables do not. The worker thread stays in
the master and reads ``leader.is_leader()`` (cheap cross-thread bool). The
leader-gated reaper (``_reap_once``) sweeps ``pgqueue.reap`` +
``revocation.reap_expired`` + ``kvstore.kv_reap`` — the time-based re-queue of
a crashed claim is what ADR-0029's reaper contract depends on, and it runs
only while this replica leads (a stale leader's brief double-reap is
idempotent — it only re-queues rows; ledger ruling, Task 3).
"""

import importlib
import logging
import os
import threading
import time

from flask import Flask

from app import _bootstrap_local_admin, create_app
from app.core import kvstore, pgqueue
from app.core.config import get_settings
from app.services import revocation

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


# ADR-0028: the app is built in main() (not at import) so that importing
# wsgi is a no-op (test_worker_gate reloads it; test_proxyfix imports it for
# _apply_proxyfix). Gunicorn loads the module and calls main(); running as a
# script keeps dev behavior identical.
app: Flask | None = None

# pgqueue task path -> enqueue interval (seconds). The worker thread below is
# the scheduler: it enqueues a task only when it is due AND this replica leads.
INTERVALS: dict[str, int] = {
    "app.tasks.health.run": 60,
    "app.tasks.cluster_sync.run": 300,
}

# ADR-0029: the worker IS the scheduler thread (no RQ child process).
worker_thread: threading.Thread | None = None
# ADR-0029: the reaper sweeps at most this often (the ticket's 30 s gate —
# the queue reaper's 120 s stale window is the row-level threshold, not the
# sweep cadence).
REAP_INTERVAL_SECONDS: float = 30.0


def _run_once(leader_obj: object, queue: object, engine: object, last: dict[str, float]) -> bool:
    """One scheduler tick: enqueue due tasks ONLY while this replica leads.

    ``leader_obj`` is typed as ``object``: the unit test passes a structural
    fake (duck-typed ``is_leader()``), while ``_worker_loop`` passes a real
    ``Leader``. ``queue`` is the pgqueue-shaped seam (``enqueue(path,
    engine)``); ``engine`` is ``db.engine`` from the loop's app-context
    window; ``last`` is the loop's per-path due map (mutated here). A path
    is enqueued only when due AND this replica leads — the ADR-0008
    duplicate-job gate. Returns whether anything was enqueued.
    """
    is_leader = leader_obj.is_leader  # type: ignore[attr-defined]
    if not is_leader():
        return False
    now = time.monotonic()
    enqueued = False
    for path, interval in INTERVALS.items():
        # The leader check is PER TASK AND PER POLL — a leadership loss
        # stops all scheduling within one 5 s window.
        if now - last.get(path, 0.0) >= interval:
            queue.enqueue(path, engine)
            last[path] = now
            enqueued = True
    return enqueued


def _reap_once(leader_obj: object, engine: object) -> None:
    """One leader-gated reaper sweep: stale claims + expired jtis + expired
    kv rows.

    Any replica CAN run all three (idempotent ``UPDATE``/``DELETE``
    statements, no lock involved), but only the leader DOES — a single
    reaper keeps the sweep attributable to one node and matches the
    scenario's "the leader runs the reaper". A stale leader whose demote is
    a heartbeat away may double-reap one overlap window: the reaper only
    re-queues rows, so the duplicate is harmless (ledger ruling, Task 3).
    """
    is_leader = leader_obj.is_leader  # type: ignore[attr-defined]
    if not is_leader():
        return
    requeued = pgqueue.reap(engine)
    jtis = revocation.reap_expired(engine)
    kv = kvstore.kv_reap(engine)
    if requeued or jtis or kv:
        log.info("reaper swept %d stale claims, %d expired jtis, %d kv rows", requeued, jtis, kv)


def _worker_loop(leader_obj: object, stop: threading.Event) -> None:
    """The pgqueue poll loop: schedule (leader-gated) + claim + run + reap.

    Runs as the ``kubedash-worker`` daemon thread. Each tick opens ONE
    app-context window (the leader.py ``_engine_ctx`` pattern: the thread
    is outside any request, so ``db.engine`` — Flask-SQLAlchemy, app-bound —
    only resolves inside ``app.app_context()``), does its work, and waits
    5 s (the old RQ drain window).

    Claiming is NOT leader-gated: ``FOR UPDATE SKIP LOCKED`` is
    cluster-wide, so the queue keeps draining during a failover gap. The
    reaper IS leader-gated (``_reap_once`` + the 30 s gate here).
    """
    from app.extensions import db

    assert app is not None  # _start_worker_if_leader runs after create_app
    replica = get_settings().kubedash_replica_id
    last: dict[str, float] = {}
    last_reap: float = 0.0
    while not stop.is_set():
        try:
            with app.app_context():
                engine = db.engine
                _run_once(leader_obj, pgqueue, engine, last)
                claimed = pgqueue.claim(engine, replica)
                if claimed is not None:
                    path, task_id = claimed
                    # Reopen the context per task: the task's own
                    # ``db.session`` use must not share the tick's
                    # transaction window.
                    with app.app_context():
                        try:
                            mod, _, fn = path.rpartition(".")
                            getattr(importlib.import_module(mod), fn)()
                            pgqueue.complete(task_id, engine)
                        except Exception:
                            log.exception("pgqueue task %s failed", path)
                            pgqueue.fail(task_id, engine)
                if time.monotonic() - last_reap >= REAP_INTERVAL_SECONDS:
                    _reap_once(leader_obj, engine)
                    last_reap = time.monotonic()
        except Exception:
            # A dead loop is a dead queue: log and keep polling (transient
            # DB blips, and the sqlite test app whose claim SQL is
            # Postgres-shaped).
            log.exception("pgqueue worker tick failed — continuing")
        stop.wait(5)  # poll cadence == the old RQ drain window


def _start_worker_if_leader() -> None:
    """Spawn the leader-gated pgqueue worker (wsgi-level, not app-factory
    level — the factory must stay pure so tests can create apps freely).

    ADR-0029: the ``kubedash-worker`` daemon thread is BOTH scheduler and
    worker (the RQ child process is gone — nothing left needs main-thread
    signals). It schedules only while leading (the ADR-0008 duplicate-job
    gate); it claims regardless of leadership (``FOR UPDATE SKIP LOCKED``
    is cluster-wide, so the queue keeps draining during a failover gap).
    The reaper sweep is leader-gated per ticket.
    """
    global worker_thread

    settings = get_settings()
    if settings.kubedash_role != "leader":
        log.info("KUBEDASH_ROLE=%r — no pgqueue worker on this replica", settings.kubedash_role)
        return

    from app.core.leader import Leader

    leader = Leader(settings, app)
    leader.start()

    stop = threading.Event()

    def _loop_then_stop() -> None:
        try:
            _worker_loop(leader, stop)
        finally:
            # ponytail: no graceful shutdown hook under Gunicorn — the
            # daemon thread dies with the process; leader.stop() only
            # matters on the ``python wsgi.py`` script path.
            leader.stop()

    worker_thread = threading.Thread(target=_loop_then_stop, name="kubedash-worker", daemon=True)
    worker_thread.start()
    log.info("leader-gated pgqueue worker started (intervals=%s)", INTERVALS)


def main() -> Flask:
    """Build the app and start the leader-gated pgqueue worker.

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
    # stays pure — no DB init inside create_app) and BEFORE Leader/worker
    # startup, so the row exists before any task or request can read it.
    # No-op when the bootstrap env is unset. A missing table (tests that build
    # the app before db.create_all) is non-fatal: log and continue — the next
    # boot (or an explicit create_all) will upsert the row.
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
    ssl_context = (cert, os.environ["KUBEDASH_SSL_KEY"]) if cert else None
    # WHY env-only (not INI): FLASK_RUN_PORT, KUBEDASH_SSL_CERT, and
    # KUBEDASH_SSL_KEY are process-level knobs — they control HOW the server
    # listens, not WHAT the app is configured with. The INI is the app's
    # identity; the process port/SSL is the deployment's concern.
    cert = os.environ.get("KUBEDASH_SSL_CERT")
    ssl_context = (cert, os.environ["KUBEDASH_SSL_KEY"]) if cert else None
    port = int(os.environ.get("FLASK_RUN_PORT", "8080"))
    app.run(port=port, ssl_context=ssl_context)
