"""Docker-free test app + mock OIDC provider for the auth tests.

The session-scoped Postgres/Redis containers in ``tests/conftest.py`` need a
container runtime. Where the runtime is absent (this host), the auth suite runs
against a sqlite + monkeypatched-redis app instead — the full Testcontainers
backstop remains CI.
"""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import parse_qs, urlparse

import pytest

from app import create_app


class _FakeRedis:
    """Minimal in-memory redis for oidc_state / jti revocation keys.

    ``delete`` returns the number of keys removed (redis semantics), which
    ``consume_state`` relies on for the STATE_MISMATCH mapping.
    """

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.store[key] = value
        return True

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def delete(self, key: str) -> int:
        return int(self.store.pop(key, None) is not None)

    def flushall(self) -> None:
        self.store.clear()


@pytest.fixture()
def app(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    import app.extensions as ext
    from app.core.security import _oauth

    # The authlib OAuth() registry keeps ONE bound app for its lifetime; a
    # stale app from a previous fixture app (or the gunicorn module level)
    # breaks the LocalProxy resolution inside create_app. Reset before and
    # after so each test app rebinds cleanly.
    _oauth.app = None
    _oauth._clients.clear()
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": "sqlite://",
        "REDIS_URL": "redis://localhost:6390/0",  # never dialed; client swapped
        "KUBEDASH_KUBEDASH_JWT_SECRET": "test-jwt-secret-32-bytes-long!!!!!01",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    fake = _FakeRedis()
    with application.app_context():
        import app.extensions as ext

        monkeypatch.setattr(ext, "redis_client", fake)
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


@pytest.fixture()
def client(app) -> object:
    return app.test_client()  # type: ignore[no-any-return]


class MockOIDC:
    """In-test OIDC provider. The mock pair patches exactly the two seams
    security.py exposes: ``oidc_authorize_url(state)`` and ``oidc_exchange(code)``.

    ``exchange`` returns the fixed user for ANY code (the brief's ``assert``
    version turned every wrong-code request into an unhandled 500 instead of
    the frozen 401 contract, so the assertion lives in the tests that care).
    """

    CODE = "fixed-code"
    USER = {"sub": "sub-oidc-1", "email": "jdoe@example.com",
            "name": "J Doe", "groups": ["devs"]}

    def __init__(self) -> None:
        self.last_state: str | None = None

    def authorize_url(self, state: str) -> str:
        self.last_state = state
        return f"http://mock-oidc.test/authorize?state={state}"

    def exchange(self, code: str) -> dict[str, object]:
        return dict(self.USER)


@pytest.fixture()
def mock_oidc(monkeypatch: pytest.MonkeyPatch) -> MockOIDC:
    m = MockOIDC()
    import app.core.security as sec

    monkeypatch.setattr(sec, "oidc_exchange", m.exchange)
    monkeypatch.setattr(sec, "oidc_authorize_url", m.authorize_url)
    return m


def _jwt_of(client) -> str:
    """Replay the login flow and return the access JWT from the callback's
    302 location (?token=... per the JWT delivery contract)."""
    r1 = client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    q = parse_qs(urlparse(cb).query)
    state = q["state"][0]
    r2 = client.get(f"{cb}&code={MockOIDC.CODE}&state={state}")
    return parse_qs(urlparse(r2.headers["Location"]).query)["token"][0]


@pytest.fixture()
def auth_client(client, mock_oidc):
    """``client.login()`` performs the full OIDC round trip; ``client.jwt`` is
    the resulting access token, ``client.refresh`` the raw refresh token."""

    def login() -> None:
        r1 = client.post("/api/v1/auth/login")
        assert r1.status_code == 302
        cb = r1.headers["Location"]
        state = parse_qs(urlparse(cb).query)["state"][0]
        r2 = client.get(f"{cb}&code={mock_oidc.CODE}&state={state}")
        assert r2.status_code == 302
        loc = r2.headers["Location"]
        assert loc.startswith("/?token=")
        q = parse_qs(urlparse(loc).query)
        client.jwt = q["token"][0]
        client.refresh = q["refresh"][0]

    client.login = login
    return client
