"""Postgres task-queue core on the ``tasks`` table (ADR-0029).

Redis removal: the queue is Postgres, not RQ. The claim is one atomic
``UPDATE ... RETURNING`` whose ``WHERE`` picks a row with
``SELECT ... FOR UPDATE SKIP LOCKED`` — concurrent claimants skip each
other's locked rows, so two replicas can never claim one row. The reaper
is TIME-based (not lock-based): a ``processing`` row whose ``locked_at``
is older than ``REAPER_STALE_SECONDS`` (a crashed worker) is re-queued by
a single ``UPDATE``; the row's attempts keep their backoff curve, so a
crashed claim re-appears after ``backoff_seconds(attempts)`` instead of
wedging the queue.

Engine-bound ``text()`` SQL, no Flask imports — a core module that takes
an ``Engine`` (callers pass ``db.engine`` inside an app context; the
wsgi task runner does this per claim in Task 5). Keys are bound params
(findings #1); ``now()``/``make_interval`` stay on the SQL side — they
are the reaper's time-based logic, not a lookup key.
"""

from sqlalchemy import Engine, text

REAPER_STALE_SECONDS = 120  # > longest task runtime (findings #6)
MAX_ATTEMPTS = 3
BACKOFF_CAP_SECONDS = 600


def backoff_seconds(attempts: int) -> int:
    """Backoff after ``attempts`` failures: 60 * 5^attempts, capped at 600 s."""
    return min(BACKOFF_CAP_SECONDS, 60 * (5**attempts))


def enqueue(path: str, engine: Engine) -> None:
    """Queue one task; claimable immediately (available_at = now())."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tasks (path, enqueued_at, available_at, status) "
                "VALUES (:p, now(), now(), 'pending')"
            ),
            {"p": path},
        )


def claim(engine: Engine, replica_id: str) -> tuple[str, int] | None:
    """Atomically claim the oldest claimable row; return ``(path, task_id)``,
    or None when nothing is claimable.

    Single statement: the subselect locks one row (``FOR UPDATE SKIP
    LOCKED`` — concurrent claimants skip it), the update marks it
    ``processing``. ``attempts`` is NOT touched here — it counts
    observed failures (``fail`` increments it), not claims, so a
    re-claimed row keeps its failure count and dead-letters at exactly
    ``MAX_ATTEMPTS`` failures.
    """
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "UPDATE tasks "
                "SET status = 'processing', locked_at = now(), "
                "locked_by = :rid "
                "WHERE id = ("
                "  SELECT id FROM tasks "
                "  WHERE status = 'pending' AND available_at <= now() "
                "  ORDER BY enqueued_at LIMIT 1 FOR UPDATE SKIP LOCKED"
                ") "
                "RETURNING path, id"
            ),
            {"rid": replica_id},
        ).first()
    # the id travels with the claim — the worker needs it to complete/fail
    return (row.path, row.id) if row is not None else None


def complete(task_id: int, engine: Engine) -> None:
    """Mark a claimed row done."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE tasks SET status = 'done' WHERE id = :id"),
            {"id": task_id},
        )


def fail(task_id: int, engine: Engine) -> None:
    """Record a failed run of the claimed row.

    Increment and dead-letter check live in ONE statement (``CASE WHEN
    attempts + 1 >= :max``) — a SELECT-then-UPDATE would race two replicas
    failing the same row. ``attempts`` = the number of observed failures
    (claim leaves it at 0; this increments once per failure), so the row
    dead-letters after exactly ``MAX_ATTEMPTS`` failures. Backoff uses
    the count BEFORE this increment (first failure -> 60 s).
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tasks "
                "SET attempts = attempts + 1, "
                "status = CASE "
                "  WHEN attempts + 1 >= :max THEN 'failed' "
                "  ELSE 'pending' END, "
                "locked_at = NULL, locked_by = NULL, "
                "available_at = CASE "
                "  WHEN attempts + 1 >= :max THEN now() "
                "  ELSE now() + make_interval(secs => "
                "  LEAST(:cap, 60 * power(5, attempts))) END "
                "WHERE id = :id"
            ),
            {"id": task_id, "max": MAX_ATTEMPTS, "cap": BACKOFF_CAP_SECONDS},
        )


def reap(engine: Engine, stale_seconds: int = REAPER_STALE_SECONDS) -> int:
    """Re-queue ``processing`` rows whose ``locked_at`` is older than
    ``stale_seconds`` (a crashed worker). Returns the re-queued count.

    Time-based, not lock-based: any replica can run it, and it never
    waits on a lock. Re-queued rows keep ``attempts`` and get the same
    backoff curve as a failed one, so a crash mid-task delays the retry
    exactly as a failure would.
    """
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "UPDATE tasks "
                "SET status = 'pending', locked_at = NULL, locked_by = NULL, "
                "available_at = now() + make_interval(secs => "
                f"LEAST({BACKOFF_CAP_SECONDS}, 60 * power(5, attempts))) "
                "WHERE status = 'processing' "
                "AND locked_at < now() - make_interval(secs => :stale)"
            ),
            {"stale": stale_seconds},
        )
        return result.rowcount
