"""Leader election — advisory lock mutex + lease-row observable state (ADR-0008).

Mechanism per ARCHITECTURE §3.7:
- the Postgres **advisory lock** is the mutex — key ``hashtext(:rid)``,
  per-replica (NOT a fixed constant: a fixed key would let a second ``Leader``
  object on the same engine report spuriously non-leader and break failover);
- the ``leader_lease`` row is the observable state — the leader heartbeats
  it every ``heartbeat_seconds`` (default 5 s);
- a non-leader takes over when the row is absent or its ``heartbeat_at`` is
  older than ``stale_seconds`` (default 10 s). ``acquire_once()`` never
  blocks on staleness; it attempts and returns ``False`` when the lease is
  fresh and held by another replica.
- ``stop()`` releases the advisory lock (``pg_advisory_unlock``) and deletes
  the row, so a follower can take over immediately.

The ``SELECT ... FOR UPDATE SKIP LOCKED`` path in §3.7 is subsumed by the
advisory lock for a single-row lease (recorded so it is not "fixed" back).
"""

import threading
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.core.config import Settings
from app.extensions import db


class Leader:
    """One replica's view of the election; the advisory-lock call is the seam."""

    def __init__(
        self, settings: Settings, *, stale_seconds: int = 10, heartbeat_seconds: int = 5
    ) -> None:
        self.replica_id: str = settings.kubedash_replica_id
        self._token = uuid.uuid4()
        self._stale = stale_seconds
        self._beat = heartbeat_seconds
        self._is_leader = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._loop, name="leader", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._is_leader:
            self._release()
            self._is_leader = False

    def is_leader(self) -> bool:
        return self._is_leader

    def _lock_key(self) -> str:
        # hashtext(:rid) — the brief spells it "hashintext"; the real Postgres
        # function is hashtext.
        return "hashtext(:rid)"

    def _binds(self) -> dict[str, object]:
        return {"rid": self.replica_id}

    def acquire_once(self) -> bool:
        """One attempt; returns False when the lock is held or the lease is
        fresh and owned by another replica. Never blocks on staleness."""
        with db.engine.connect() as conn:
            row = conn.execute(
                text("SELECT replica_id, heartbeat_at FROM leader_lease WHERE id = 1")
            ).first()
            if row is not None and row.replica_id != self.replica_id:
                if row.heartbeat_at.tzinfo is None:
                    heartbeat_at = row.heartbeat_at.replace(tzinfo=UTC)
                else:
                    heartbeat_at = row.heartbeat_at
                if (datetime.now(UTC) - heartbeat_at) <= timedelta(seconds=self._stale):
                    return False
            got = conn.execute(
                text(f"SELECT pg_try_advisory_lock({self._lock_key()})"), self._binds()
            ).scalar()
            if got != 1:
                return False
            conn.execute(
                text(
                    "INSERT INTO leader_lease (id, replica_id, token, acquired_at, heartbeat_at) "
                    "VALUES (1, :rid, :tok, now(), now()) "
                    "ON CONFLICT (id) DO UPDATE SET replica_id = :rid, token = :tok, "
                    "acquired_at = now(), heartbeat_at = now()"
                ),
                {**self._binds(), "tok": str(self._token)},
            )
            conn.commit()
        self._is_leader = True
        return True

    def _heartbeat(self) -> None:
        with db.engine.connect() as conn:
            conn.execute(
                text("UPDATE leader_lease SET heartbeat_at = now() "
                     "WHERE id = 1 AND replica_id = :rid"),
                self._binds(),
            )
            conn.commit()

    def _release(self) -> None:
        with db.engine.connect() as conn:
            conn.execute(text(f"SELECT pg_advisory_unlock({self._lock_key()})"), self._binds())
            conn.execute(
                text("DELETE FROM leader_lease WHERE id = 1 AND replica_id = :rid"),
                self._binds(),
            )
            conn.commit()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self._is_leader:
                self._heartbeat()
            else:
                self.acquire_once()
            self._stop.wait(self._beat if self._is_leader else 1)
