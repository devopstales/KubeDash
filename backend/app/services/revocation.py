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
"""

from uuid import UUID

from sqlalchemy import Engine, text


def revoke_jti(engine: Engine, jti: UUID, ttl_seconds: int) -> None:
    """Insert the ``jti`` with ``expires_at = now() + ttl_seconds``.

    Idempotent: a double-revoke of the same ``jti`` upserts (``ON
    CONFLICT DO UPDATE``) instead of failing on the PK.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO revoked_jtis (jti, expires_at) "
                "VALUES (:j, now() + make_interval(secs => :ttl)) "
                "ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at"
            ),
            {"j": jti, "ttl": ttl_seconds},
        )


def is_revoked(engine: Engine, jti: UUID) -> bool:
    """True if the ``jti`` is on the deny-list and not yet expired.

    PK lookup with ``jti`` bound as a parameter (findings #1): the
    planner turns it into an index scan on the PK — one probe, no seq
    scan — which is the hot path of every authenticated request.
    ``expires_at > now()`` is the TTL logic, not a lookup key.
    """
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT jti FROM revoked_jtis WHERE jti = :j AND expires_at > now()"),
            {"j": jti},
        ).first()
    return row is not None


def reap_expired(engine: Engine) -> int:
    """Delete every row whose ``expires_at`` has passed. Returns the
    count deleted.

    Any replica can run it (no lock is involved), and the leader-gated
    reaper in ``wsgi`` does — a revoke only lives until the token's own
    expiry, so this is what bounds the table.
    """
    with engine.begin() as conn:
        result = conn.execute(text("DELETE FROM revoked_jtis WHERE expires_at <= now()"))
        return result.rowcount
