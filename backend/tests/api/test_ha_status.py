"""HA status endpoint (spec 2026-11-10-ha-status-page) — API tier.

The derivation matrix lives in tests/services/test_ha_status.py (unit tier,
fake catalog + fake engines). This file pins the WIRE contract of
``GET /api/v1/admin/ha-status``: the admin gate (403 RBAC_DENIED for
non-admins) and the 200 envelope through the ``HaStatusOut`` dump —
including ``queue.failed`` (the pgqueue dead-letter count after
MAX_ATTEMPTS; the queue section shows counts by status, so the field is on
the wire even when the catalog read found no failed rows).
"""
from __future__ import annotations

import pytest


def _seed(api_client, api_app, sub: str, email: str, role: str) -> dict[str, str]:
    """Seed a local user directly and return a bearer header for it."""
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub=sub, email=email, role=role, auth_source="local")
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    return {"Authorization": f"Bearer {access}"}


def _report(queue: dict | None = None) -> dict:
    """A minimal build_report-shaped dict (the endpoint's schema dump is
    the assertion target, so only the fields the dump needs are set)."""
    return {
        "probed_at": "2026-11-13T09:00:00+00:00",
        "spock_version": "5.0.1",
        "nodes": [],
        "leader": {
            "replica_id": "replica-1",
            "fence": 1,
            "heartbeat_age_s": 0.5,
            "lock_verdict": "held on n1 (pid 7899, idle)",
            "token": "tok",
            "acquired_at": "2026-11-13 08:00:00",
            "renew_at": "2026-11-13 08:59:59",
            "lease_duration_s": 10.0,
            "candidates": None,
        },
        "queue": {"pending": 0, "processing": 0, "done": 0, **(queue or {})},
        "status": "healthy",
        "reasons": [],
        "database": {"status": "healthy", "reasons": []},
        "election": {"status": "healthy", "reasons": []},
    }


def test_ha_status_admin_200_carries_queue_failed_on_the_wire(
    api_client, api_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import ha_status

    headers = _seed(api_client, api_app, "local:admin@local", "admin@local", "admin")
    monkeypatch.setattr(
        ha_status, "build_report", lambda *a, **kw: _report(queue={"failed": 3})
    )
    r = api_client.get("/api/v1/admin/ha-status", headers=headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "healthy"
    # The dead-letter count reaches the wire (pgqueue.fail() after
    # MAX_ATTEMPTS — the queue section shows counts by status).
    assert body["queue"]["failed"] == 3

    # No failed rows: the catalog dict lacks the key and the schema's
    # dump_default supplies 0 (the wire field is always present).
    monkeypatch.setattr(ha_status, "build_report", lambda *a, **kw: _report())
    body = api_client.get("/api/v1/admin/ha-status", headers=headers).get_json()
    assert body["queue"]["failed"] == 0


def test_ha_status_non_admin_403(api_client, api_app) -> None:
    headers = _seed(api_client, api_app, "local:user@local", "user@local", "user")
    r = api_client.get("/api/v1/admin/ha-status", headers=headers)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
