"""Task 3 — strict fence on leader_lease (ADR-0031).

SATISFIES: stale-leader-write-is-rejected-by-the-fence

The advisory lock is session-local, NOT a cross-node mutex — the fence
(fence+1 on every acquire, WHERE fence=:f on every leader write) is the
cross-node LWW tiebreaker: the peer whose upsert commits second holds the
higher fence and wins; the stale leader's writes affect zero rows.
"""
from sqlalchemy import text

from app.core.config import get_settings
from app.core.leader import Leader
from app.extensions import db


def _settings(replica_id: str):
    # Leader.__init__ only reads settings.kubedash_replica_id; hand it the
    # real Settings and set the id, mirroring tests/test_leader.py.
    s = get_settings()
    s.kubedash_replica_id = replica_id
    return s


def test_acquire_increments_fence_and_exposes_it(app):
    with app.app_context():
        leader = Leader(_settings("r1"))
        assert leader.fence is None  # not acquired yet
        assert leader.acquire_once() is True
        assert leader.is_leader() is True
        assert leader.fence == 1
        row = db.session.execute(text("SELECT fence FROM leader_lease WHERE id = 1")).scalar_one()
        assert row == 1
        leader.stop()


def test_stale_fence_write_affects_zero_rows(app):
    with app.app_context():
        a = Leader(_settings("ra"))
        b = Leader(_settings("rb"), stale_seconds=0)  # bypass A's fresh heartbeat
        assert a.acquire_once() is True
        assert a.fence == 1
        assert b.acquire_once() is True  # B's upsert commits second -> fence 2
        assert b.fence == 2

        # A's fenced heartbeat: 0 rows, and A demotes to non-leader.
        r = a._heartbeat()
        assert r == 0
        assert a.is_leader() is False

        # A stale-fence write is rejected while the current holder's commits.
        stale = db.session.execute(
            text("UPDATE leader_lease SET heartbeat_at = now() WHERE id = 1 AND fence = 1")
        )
        assert stale.rowcount == 0
        holder = db.session.execute(
            text("UPDATE leader_lease SET heartbeat_at = now() WHERE id = 1 AND fence = 2")
        )
        assert holder.rowcount == 1
        db.session.rollback()
        b.stop()
        a.stop()
