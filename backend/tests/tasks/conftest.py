"""Docker-free fixtures for the task unit tier (Task 7).

The session-scoped Postgres/Redis containers in ``tests/conftest.py`` need a
container runtime. Where the runtime is absent (this host), the task unit tier
runs against a sqlite app + monkeypatched ``K8sClientPool`` instead — the
Testcontainers ``app`` fixture (parent conftest) remains the CI backstop for
the container-dependent worker-gate tier.

Mirrors the sqlite app construction from ``tests/api/conftest.py``; the
``tasks_app`` alias keeps the brief's ``app``-named test calls readable while
the parent Testcontainers fixture stays available to sibling suites.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app import create_app


@pytest.fixture()
def tasks_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    from app.core.security import _oauth

    # authlib keeps ONE bound app per OAuth() registry; reset before/after so
    # each sqlite app rebinds cleanly (same reason as tests/api/conftest.py).
    _oauth.app = None
    _oauth._clients.clear()
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": "sqlite://",
        "REDIS_URL": "redis://localhost:6390/0",  # never dialed
        "KUBEDASH_KUBEDASH_JWT_SECRET": "test-jwt-secret-32-bytes-long!!!!!01",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    with application.app_context():
        from app.extensions import db

        db.create_all()
        try:
            yield application
        finally:
            _oauth.app = None
            _oauth._clients.clear()
            db.session.rollback()
            db.session.remove()
            db.drop_all()
