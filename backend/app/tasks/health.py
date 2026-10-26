"""Cluster health probe — RQ task, leader-gated (ADR-0007 / ADR-0008).

``run()`` is the RQ entry point enqueued by ``wsgi.py`` (INTERVALS, 60 s)
only while this replica leads. For each ``Cluster`` row it probes the
cluster's ``/readyz`` (5 s timeout lives inside ``K8sClient.readyz``) and
writes ``status`` (``"up"``/``"down"``) + ``last_probe_at``.

No exception escapes ``run()``: any probe failure (including a
``pool.get`` decryption error on a malformed ``kubeconfig_enc``) marks the
cluster ``down``. ``last_probe_at`` comes from Task 2's migration — no
column is added by this task (``consecutive_down`` was dropped as scope
creep per the critic).
"""
import logging
from datetime import UTC, datetime

from app.extensions import db
from app.models.cluster import Cluster
from app.services.k8s_client import pool

log = logging.getLogger(__name__)


def run() -> None:
    """Probe every registered cluster and persist status + last_probe_at."""
    for c in db.session.query(Cluster).all():
        try:
            ok = bool(pool.get(c).readyz())
        except Exception as e:  # decryption failure, client construction, ...
            log.warning("health probe failed for cluster %r: %s", c.name, e)
            ok = False
        c.status = "up" if ok else "down"
        c.last_probe_at = datetime.now(UTC)
        # Flush per-row so the commit does NOT use psycopg3 executemany (same
        # RQ work-horse DuplicatePreparedStatement issue as cluster_sync).
        db.session.flush()
    db.session.commit()
