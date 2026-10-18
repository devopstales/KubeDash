"""Gunicorn entrypoint (ADR-0006 single container: API + static SPA).

``KUBEDASH_ROLE=leader`` (default: ``worker``) additionally starts:
  - the ``Leader`` (Task 2, ADR-0008) — PG advisory lock + leader_lease row;
  - a daemon thread running ``rq.Worker`` on the ``kubedash`` queue that
    doubles as the scheduler: each iteration it enqueues the due tasks from
    ``INTERVALS`` ONLY while ``leader.is_leader()`` is true, then drains via
    ``worker.work(timeout=5)``. A replica that loses leadership stops
    scheduling within one 5 s poll; a promoted replica resumes within one
    interval. RQ's built-in cron is deliberately NOT used — it would fire on
    every replica regardless of leadership (the exact duplicate-job failure
    ADR-0008's gate prevents).
"""
import logging
import threading
import time

import rq
from flask import Flask

from app import _bootstrap_local_admin, create_app
from app.core.config import get_settings

log = logging.getLogger(__name__)

app: Flask = create_app()

# ADR-0021: the local-admin upsert runs at boot, after the factory (which
# stays pure — no DB init inside create_app) and BEFORE Leader/RQ startup,
# so the row exists before any task or request can read it. No-op when the
# bootstrap env is unset.
_bootstrap_local_admin(app)

# RQ task path -> enqueue interval (seconds). The worker thread below is the
# scheduler: it enqueues a task only when it is due AND this replica leads.
INTERVALS: dict[str, int] = {
    "app.tasks.health.run": 60,
    "app.tasks.cluster_sync.run": 300,
}

worker: rq.Worker | None = None
worker_thread: threading.Thread | None = None


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
    """Spawn the leader-gated RQ worker (wsgi-level, not app-factory level —
    the factory must stay pure so tests can create apps freely)."""
    global worker, worker_thread

    settings = get_settings()
    if settings.kubedash_role != "leader":
        log.info("KUBEDASH_ROLE=%r — no RQ worker on this replica", settings.kubedash_role)
        return

    from app.core.leader import Leader
    from app.extensions import redis_client

    leader = Leader(settings)
    leader.start()
    worker = rq.Worker(["kubedash"], connection=redis_client)
    w = worker  # capture in closure (avoids the global-lookup on every poll)

    def _run() -> None:
        queue = rq.Queue("kubedash", connection=redis_client)
        last: dict[str, float] = {}
        while True:
            now = time.monotonic()
            for path, interval in INTERVALS.items():
                # The leader check is PER TASK and PER POLL — a leadership
                # loss stops all scheduling within one 5 s drain window.
                if leader.is_leader() and now - last.get(path, 0.0) >= interval:
                    queue.enqueue(path)
                    last[path] = now
            # rq 2.x dropped work(timeout=...); work() blocks up to 5 s
            # (max_idle_time) between job polls, which is the drain window.
            w.work(max_idle_time=5)

    worker_thread = threading.Thread(target=_run, name="kubedash-worker", daemon=True)
    worker_thread.start()
    log.info("leader-gated RQ worker started (queue=kubedash, intervals=%s)", INTERVALS)


# Gunicorn loads the module without executing ``__main__`` (workers use the
# module-level ``app``); running as a script keeps dev behavior identical.
_start_worker_if_leader()

if __name__ == "__main__":
    import os
    app.run(port=int(os.environ.get("FLASK_RUN_PORT", "8080")))
