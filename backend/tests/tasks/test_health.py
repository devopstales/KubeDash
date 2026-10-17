"""Unit tier for the leader-gated task bodies (Task 7 / ADR-0008).

Docker-free: sqlite app + monkeypatched ``K8sClientPool``. The ``pool.get``
seam is the only boundary — these tests prove the probe mapping (readyz bool
-> status) and the no-exception-escape contract, not the HTTP call.

``test_health_task_*`` use the brief's verbatim assertions against a
``tasks_app`` sqlite app (the brief's snippet names it ``app``; the parent
Testcontainers fixture of the same name is env-blocked on this host and would
need Postgres + Redis containers).
"""

import app.tasks.cluster_sync as cluster_sync
import app.tasks.health as health
from app.extensions import db
from app.models.cluster import Cluster


class _FakeClient:
    def __init__(self, readyz_ok: bool) -> None:
        self._ok = readyz_ok

    def readyz(self) -> bool:
        return self._ok


def test_health_task_marks_down_cluster(tasks_app, monkeypatch):
    """pool.get patched to raise — the task must catch it and mark the
    cluster down without the exception escaping run()."""
    with tasks_app.app_context():
        c = Cluster(name="dead", api_server="https://127.0.0.1:1",
                    kubeconfig_enc=b"", context="dead")
        db.session.add(c)
        db.session.commit()
        cid = c.id

    def _raise(cluster):
        raise ValueError("no kubeconfig")

    monkeypatch.setattr(health.pool, "get", _raise)
    health.run()

    with tasks_app.app_context():
        row = db.session.get(Cluster, cid)
        assert row.status == "down"
        assert row.last_probe_at is not None


def test_health_task_marks_up_cluster(tasks_app, monkeypatch):
    with tasks_app.app_context():
        c = Cluster(name="live", api_server="https://1.2.3.4:6443",
                    kubeconfig_enc=b"", context="live")
        db.session.add(c)
        db.session.commit()
        cid = c.id

    monkeypatch.setattr(health.pool, "get", lambda cluster: _FakeClient(True))
    health.run()

    with tasks_app.app_context():
        row = db.session.get(Cluster, cid)
        assert row.status == "up"
        assert row.last_probe_at is not None


def test_cluster_sync_warns_on_down_and_still_probes(tasks_app, monkeypatch, caplog):
    """cluster_sync.run(): same probe shape as health; a down cluster logs a
    warning (the alert path is a later change) but status/last_probe_at are
    still maintained."""
    with tasks_app.app_context():
        c = Cluster(name="flaky", api_server="https://10.0.0.1:6443",
                    kubeconfig_enc=b"", context="flaky")
        db.session.add(c)
        db.session.commit()
        cid = c.id

    monkeypatch.setattr(cluster_sync.pool, "get", lambda cluster: _FakeClient(False))
    import logging

    with caplog.at_level(logging.WARNING, logger="app.tasks.cluster_sync"):
        cluster_sync.run()

    with tasks_app.app_context():
        row = db.session.get(Cluster, cid)
        assert row.status == "down"
        assert row.last_probe_at is not None
    assert any(r.levelno >= logging.WARNING and "flaky" in r.message for r in caplog.records)
