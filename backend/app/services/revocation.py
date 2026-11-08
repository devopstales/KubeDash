"""Access-token ``jti`` deny-list on the ``revoked_jtis`` table (ADR-0030).

Redis removal: logout writes the access token's ``jti`` here, and the
verify hook reads it back. A revoke is an upsert with
``expires_at = now() + make_interval(secs => :ttl)`` — a token is only
deny-listed until it would have expired anyway, so the deny-list stays
bounded even if the reaper lags. The lookup (``is_revoked``) is a
PRIMARY-KEY read with ``jti`` bound as a parameter — no function in the
WHERE clause (findings #1) — so it plans as a single PK index scan, and
it is what the verify hook calls on every authenticated request.
``reap_expired`` (run by the leader-gated reaper) prunes passed rows.

Pure Python over an ``Engine`` (``db.engine`` from the caller) — no
Flask imports, per the ``app/services/`` seam rule.

The Docker-free sqlite api-tier (tests/api/conftest.py) cannot run
Postgres's ``make_interval``/``now()`` — the dialect-aware branches
below keep that tier on a functionally equivalent ``strftime``/
``CURRENT_TIMESTAMP`` path. Production is Postgres-only (ADR-0030).
"""

from uuid import UUID

from sqlalchemy import Engine, text

# ponytail: sqlite api-tier compatibility — see module docstring. Both
# paths keep the timestamp on the SQL side (no Python-side now()).

_PG_REVOKE_SQL = (
    "INSERT INTO revoked_jtis (jti, expires_at) "
    "VALUES (:j, now() + make_interval(secs => :ttl)) "
    "ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at"
)
_SQLITE_REVOKE_SQL = (
    "INSERT INTO revoked_jtis (jti, expires_at) "
    "VALUES (:j, datetime('now', :ttl || ' seconds')) "
    "ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at"
)
_PG_NOW_SQL = "SELECT jti FROM revoked_jtis WHERE jti = :j AND expires_at > now()"
_SQLITE_NOW_SQL = "SELECT jti FROM revoked_jtis WHERE jti = :j AND expires_at > datetime('now')"
_PG_REAP_SQL = "DELETE FROM revoked_jtis WHERE expires_at <= now()"
_SQLITE_REAP_SQL = "DELETE FROM revoked_jtis WHERE expires_at <= datetime('now')"


def _is_pg(engine: Engine) -> bool:
    return engine.dialect.name == "postgresql"


def _bind(engine: Engine, jti: UUID) -> str:
    # ponytail: the sqlite api-tier binds the UUID as a string (sqlite has
    # no native UUID type); Postgres keeps the typed UUID binding (the PK
    # plans as an index scan on the UUID column). Both store the canonical
    # hyphenated form, so the value is interchangeable across tiers.
    return str(jti) if not _is_pg(engine) else jti


def revoke_jti(engine: Engine, jti: UUID, ttl_seconds: int) -> None:
    """Insert the ``jti`` with ``expires_at = now() + ttl_seconds``.

    Idempotent: a double-revoke of the same ``jti`` upserts (``ON
    CONFLICT DO UPDATE``) instead of failing on the PK.
    """
    sql = _PG_REVOKE_SQL if _is_pg(engine) else _SQLITE_REVOKE_SQL
    with engine.begin() as conn:
        conn.execute(text(sql), {"j": _bind(engine, jti), "ttl": ttl_seconds})


def is_revoked(engine: Engine, jti: UUID) -> bool:
    """True if the ``jti`` is on the deny-list and not yet expired.

    PK lookup with ``jti`` bound as a parameter (findings #1): the
    planner turns it into an index scan on the PK — one probe, no seq
    scan — which is the hot path of every authenticated request.
    ``expires_at > now()`` is the TTL logic, not a lookup key.
    """
    sql = _PG_NOW_SQL if _is_pg(engine) else _SQLITE_NOW_SQL
    with engine.begin() as conn:
        row = conn.execute(text(sql), {"j": _bind(engine, jti)}).first()
    return row is not None


def reap_expired(engine: Engine) -> int:
    """Delete every row whose ``expires_at`` has passed. Returns the
    count deleted.

    Any replica can run it (no lock is involved), and the leader-gated
    reaper in ``wsgi`` does — a revoke only lives until the token's own
    expiry, so this is what bounds the table.
    """
    sql = _PG_REAP_SQL if _is_pg(engine) else _SQLITE_REAP_SQL
    with engine.begin() as conn:
        result = conn.execute(text(sql))
        return result.rowcount
