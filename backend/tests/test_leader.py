"""Task 2 — leader election on the Postgres advisory lock (ADR-0008)."""
import time

from app.core.config import get_settings
from app.core.leader import Leader


def test_single_replica_becomes_leader(app):
    with app.app_context():
        leader = Leader(get_settings())
        leader.replica_id = "r1"
        assert leader.acquire_once() is True
        assert leader.is_leader() is True
        leader.stop()


def test_second_replica_does_not_double_lead(app):
    with app.app_context():
        first = Leader(get_settings())
        first.replica_id = "r1"
        second = Leader(get_settings())
        second.replica_id = "r2"
        assert first.acquire_once() is True
        assert second.acquire_once() is False  # lock held by r1
        assert first.is_leader() is True
        assert second.is_leader() is False
        first.stop()
        second.stop()


def test_failover_after_leader_stop_is_fast(app):
    """ARCHITECTURE §3.7: kill leader, follower acquires within the stale
    threshold (10 s default; test budget 15 s)."""
    with app.app_context():
        first = Leader(get_settings())
        first.replica_id = "r1"
        # stale_seconds=1: takeover after a fresh heartbeat instead of waiting 10 s
        second = Leader(get_settings(), stale_seconds=1)
        second.replica_id = "r2"
        assert first.acquire_once() is True
        first.stop()  # leader dies
        t0 = time.monotonic()
        # r2 waits for the stale threshold, then takes over
        deadline = t0 + 15
        while time.monotonic() < deadline and not second.acquire_once():
            time.sleep(0.2)
        elapsed = time.monotonic() - t0
        assert second.is_leader() is True
        assert elapsed <= 15
        second.stop()
