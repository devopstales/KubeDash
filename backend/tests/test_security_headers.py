"""R3/R4 unit suite for the ADR-0026 security-header layer.

Docker-free: the ``_app`` fixture mirrors ``tests/api/conftest.py``'s
``api_app`` (sqlite; oidc_state/jti revocation run on the sqlite kv/
revocation tables after the Redis removal, ADR-0029/0030) but builds
a fixture ``KUBEDASH_HOME`` that also carries a ``static/`` dir with a
hashed ``assets/`` file and a root ``favicon.ico`` — so the ADR-0006
caching-preserved scenarios exercise a real static response, not a 404.

The test client speaks ``http://localhost`` (plain HTTP) — that is precisely
the HSTS-absent case; the TLS case is proven by overriding the WSGI
url-scheme on a single request.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from app import create_app
from app.core import ini_config


def _make_fixture_home(tmp_path: Path) -> Path:
    """Fixture home: the INI the api-tier app needs, plus a ``static/`` dir
    carrying a hashed asset and a root favicon so the static-caching
    scenarios hit a real 200 (ADR-0006)."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "kubedash.ini").write_text(
        "[DEFAULT]\napp_mode = development\n"
        "[database]\nurl = sqlite://\n"
        "[deployment]\nadmin_kubeconfig = /test/admin.kubeconfig\n"
    )
    (home / "static").mkdir()
    (home / "static" / "assets").mkdir()
    (home / "static" / "assets" / "app.abc123.js").write_text("/* asset */\n")
    (home / "static" / "favicon.ico").write_bytes(b"\x00\x01")
    (home / "static" / "index.html").write_text("<html></html>\n")
    return home


@pytest.fixture()
def _app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[object]:
    from app.core.security import _oauth

    # The authlib OAuth() registry keeps ONE bound app for its lifetime; a
    # stale app from a previous fixture app breaks the LocalProxy resolution
    # inside create_app. Reset before and after so each test app rebinds
    # cleanly.
    _oauth.app = None
    _oauth._clients.clear()
    # Bootstrap env ON + Settings reset BEFORE create_app (setenv + reset
    # order is load-bearing; config_overrides alone never reach get_settings).
    home = _make_fixture_home(tmp_path)
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_EMAIL", "admin@local")
    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "correct-horse")
    ini_config.reset()
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": "sqlite://",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret-32-bytes-long!!!!!01",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
        # ADR-0025: http://localhost test client — Secure cookies are stored
        # but never sent back, so the session would vanish between calls.
        "KUBEDASH_COOKIE_SECURE": False,
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


def _nonce(r) -> str:
    csp = r.headers.get("Content-Security-Policy", "")
    for part in csp.split(";"):
        if "nonce-" in part:
            return part.split("nonce-")[1].strip("'")
    return ""


def test_api_response_carry_all_security_headers(_app):
    client = _app.test_client()  # type: ignore[union-attr]
    # A 3xx login response — the after_request must run for 3xx too.
    r = client.post(
        "/api/v1/auth/local",
        json={"email": "admin@local", "password": "correct-horse"},
    )
    assert r.status_code in (302, 401)
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert r.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert r.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
    assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' 'nonce-" in csp
    assert "unsafe-eval" not in csp
    assert "wss:" in csp and "ws:" in csp


def test_unauthenticated_error_response_carry_all_security_headers(_app):
    # 401 envelope (auth-required route) — the header layer must cover the
    # smorest error path, not just successful responses.
    client = _app.test_client()  # type: ignore[union-attr]
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_csp_nonce_changes_per_request(_app):
    client = _app.test_client()  # type: ignore[union-attr]
    n1 = _nonce(client.get("/healthz"))
    n2 = _nonce(client.get("/healthz"))
    assert n1 and n2 and n1 != n2


def test_hsts_absent_over_plain_http(_app):
    client = _app.test_client()  # type: ignore[union-attr]
    assert "Strict-Transport-Security" not in client.get("/healthz").headers


def test_hsts_present_over_tls(_app):
    client = _app.test_client()  # type: ignore[union-attr]
    r = client.get("/healthz", environ_overrides={"wsgi.url_scheme": "https"})
    assert r.headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_api_no_store(_app):
    client = _app.test_client()  # type: ignore[union-attr]
    r = client.post(
        "/api/v1/auth/local",
        json={"email": "admin@local", "password": "correct-horse"},
    )
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Pragma"] == "no-cache"
    assert r.headers["Expires"] == "0"


def test_api_no_store_scoped_to_matched_rule_not_raw_path(_app):
    # Regression for the review finding: scope no-store on the MATCHED
    # (registered) rule, not the raw request.path. A path that literally
    # starts with "/api/" but matches the SPA catch-all (e.g. /api/whatever/xyz
    # — no API route is registered for it) must NOT be no-stored: under the
    # old raw startswith("/api/") it would have been, even though the matched
    # rule is the SPA catch-all, not an API route. The hook keys off
    # url_rule.rule, so only responses that matched a route registered under
    # /api/ are no-stored.
    client = _app.test_client()  # type: ignore[union-attr]
    # A literal "/api/"-prefixed path with no matching API route → SPA
    # catch-all 404. The SPA route sets no-cache on 200s; a 404 404 envelope
    # must NOT carry the API no-store set (the matched rule is not under /api/).
    spa = client.get("/api/whatever/xyz")
    assert spa.headers.get("Cache-Control") != "no-store"
    # The same shape with a real API route (POST — the registered method) →
    # no-store on the matched rule.
    api = client.post("/api/v1/auth/local", json={"email": "admin@local", "password": "x"})
    assert api.headers.get("Cache-Control") == "no-store"


def test_static_caching_preserved(_app):
    # ADR-0006: the no-store hook must NOT clobber the static caching set
    # per-route in register_static — assets stay immutable, index stays
    # no-cache.
    client = _app.test_client()  # type: ignore[union-attr]
    asset = client.get("/assets/app.abc123.js")
    assert asset.status_code == 200
    assert asset.headers["Cache-Control"] == "immutable, max-age=31536000"
    index = client.get("/")
    assert index.status_code == 200
    assert index.headers["Cache-Control"] == "no-cache"
    root = client.get("/favicon.ico")
    assert root.status_code == 200
    assert root.headers["Cache-Control"] == "immutable, max-age=31536000"
