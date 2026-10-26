"""Cluster sync — RQ task, leader-gated (ADR-0007 / ADR-0008).

``run()`` is the RQ entry point enqueued by ``wsgi.py`` (INTERVALS, 300 s)
only while this replica leads. Same probe shape as
``app.tasks.health.run`` (per-cluster ``/readyz``, 5 s timeout inside the
client, no exception escape); the difference is the downstream reaction:
a ``down`` cluster logs a WARNING — the alert path (ADR-0003) is a later
change and consumes this log line / a dedicated alerts task.

No model changes: ``last_probe_at`` came in Task 2's migration and
``consecutive_down`` was dropped (critic: scope creep).
"""
import logging
from datetime import UTC, datetime

from app.extensions import db
from app.models.cluster import Cluster
from app.services.k8s_client import pool

log = logging.getLogger(__name__)


def run() -> None:
    """Probe every registered cluster; warn on down (alert path later)."""
    for c in db.session.query(Cluster).all():
        try:
            ok = bool(pool.get(c).readyz())
        except Exception as e:  # decryption failure, client construction, ...
            log.warning("cluster_sync probe failed for cluster %r: %s", c.name, e)
            ok = False
        c.status = "up" if ok else "down"
        c.last_probe_at = datetime.now(UTC)
        # Flush per-row so the commit does NOT use psycopg3 executemany: the
        # RQ work-horse reuses a prepared statement name across rows and
        # psycopg3 raises DuplicatePreparedStatement on a bulk executemany
        # (ADR-0040 surfaced this — the task path was previously dead under
        # the KUBEDASH_ROLE env bug). flush() issues one UPDATE per row.
        db.session.flush()
        if not ok:
            log.warning("cluster %r (id=%s) is down — alert path is a later change", c.name, c.id)
    db.session.commit()
