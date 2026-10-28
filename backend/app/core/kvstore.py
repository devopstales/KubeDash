"""Postgres TTL key-value core on the ``kv`` table (ADR-0030).

Redis removal: the OIDC ``state`` nonce and the SAR verdict cache move
off Redis onto one generic ``kv`` table. A write is an upsert with
``expires_at = now() + make_interval(secs => :ttl)``; ``value`` may be
NULL — a tombstone row is a legal one-shot state (the ROW is what the
consumer reads, not the value). Reads and deletes are key lookups with
the key bound as a parameter (findings #1); an expired row is a miss
(``kv_get`` -> None), and the row stays put — ``kv_delete`` is the
one-shot delete, and ``kv_reap`` (run by the leader-gated reaper) is
what prunes expired rows.

Engine-bound ``text()`` SQL, no Flask imports — a core module that takes
an ``Engine`` (callers pass ``db.engine`` inside an app context). Keys
are bound params (findings #1); ``now()``/``make_interval`` stay on the
SQL side — they are the TTL logic, not a lookup key.
"""

from sqlalchemy import Engine, text

# ponytail: ttl_seconds is a Python int bound as :ttl — a caller can pass a
# negative or a very large value (make_interval accepts int8; a negative TTL
# is simply already-expired). No clamp here: callers (security.py, rbac.py)
# pass sane constants. Upgrade path: validate ttl_seconds >= 1 if a dynamic
# TTL ever comes from user input.
#
# ponytail: the Docker-free sqlite api-tier (tests/api/conftest.py) cannot
# run Postgres's ``make_interval``/``now()`` — the dialect-aware branches
# below keep that tier on a functionally equivalent ``strftime``/
# ``CURRENT_TIMESTAMP`` path. Production is Postgres-only (ADR-0030); the
# sqlite path exists solely so the api-tier tests run without a container
# runtime. Both paths keep ``now()``/the timestamp on the SQL side.

_PG_SET_SQL = (
    "INSERT INTO kv (key, value, expires_at) "
    "VALUES (:k, :v, now() + make_interval(secs => :ttl)) "
    "ON CONFLICT (key) DO UPDATE SET "
    "value = EXCLUDED.value, expires_at = EXCLUDED.expires_at"
)
_SQLITE_SET_SQL = (
    "INSERT INTO kv (key, value, expires_at) "
    "VALUES (:k, :v, datetime('now', :ttl || ' seconds')) "
    "ON CONFLICT (key) DO UPDATE SET "
    "value = EXCLUDED.value, expires_at = EXCLUDED.expires_at"
)
_PG_NOW_SQL = "SELECT value FROM kv WHERE key = :k AND expires_at > now()"
_SQLITE_NOW_SQL = "SELECT value FROM kv WHERE key = :k AND expires_at > datetime('now')"


def kv_set(engine: Engine, key: str, value: str | None, ttl_seconds: int) -> None:
    """Upsert a row with ``expires_at = now() + ttl_seconds``.

    ``value`` may be None (a tombstone row is a legal one-shot state).
    Re-setting the same key overwrites its value AND extends its TTL.
    """
    sql = _PG_SET_SQL if engine.dialect.name == "postgresql" else _SQLITE_SET_SQL
    with engine.begin() as conn:
        conn.execute(text(sql), {"k": key, "v": value, "ttl": ttl_seconds})


def kv_get(engine: Engine, key: str) -> str | None:
    """Return the value if the row exists and is not expired, else None.

    A miss (absent OR expired) does NOT delete the row — ``kv_delete``
    is the one-shot delete and ``kv_reap`` is the pruner, so a read
    never hides a tombstone from its consumer's delete.
    """
    sql = _PG_NOW_SQL if engine.dialect.name == "postgresql" else _SQLITE_NOW_SQL
    with engine.begin() as conn:
        row = conn.execute(text(sql), {"k": key}).first()
    return row.value if row is not None else None


def kv_delete(engine: Engine, key: str) -> bool:
    """One-shot delete: return True if a row was deleted, False if absent."""
    with engine.begin() as conn:
        result = conn.execute(text("DELETE FROM kv WHERE key = :k"), {"k": key})
        return result.rowcount == 1


def kv_reap(engine: Engine) -> int:
    """Delete every row whose ``expires_at`` has passed. Returns the
    count deleted.

    Any replica can run it (no lock is involved), and the leader-gated
    reaper in ``wsgi`` does — it is what bounds the table, since reads
    never prune.
    """
    with engine.begin() as conn:
        result = conn.execute(text("DELETE FROM kv WHERE expires_at <= now()"))
        return result.rowcount
