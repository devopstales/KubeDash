"""ProxyFix gate (ADR-0026, blueprint Task 2).

The decision lives in ``wsgi.py`` (the gunicorn entrypoint), which imports
the whole app at module level. ``import wsgi`` is a no-op in tests: the
leader-gated RQ worker only starts when ``KUBEDASH_ROLE=leader`` (default
``worker``) — these tests prove that by simply importing the module and
finishing in under a second without Redis.

SATISFIES: proxyfix-applied-behind-edge, proxyfix-inactive-without-edge.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flask import Flask, jsonify, request

import app.core.config as _config


@pytest.fixture()
def probe_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[Flask]:
    """A bare Flask app with one /probe route that echoes ``request.is_secure``.

    ``KUBEDASH_TLS_EDGE`` is UNSET here — the fixture applies the gate with
    the flag off; the edge test flips it and re-applies (the gate reads
    Settings at CALL time, never at import time).
    """
    monkeypatch.delenv("KUBEDASH_TLS_EDGE", raising=False)
    _config._settings = None

    app = Flask(__name__)

    @app.get("/probe")
    def probe() -> object:
        return jsonify(secure=request.is_secure)

    # The import must be a no-op (KUBEDASH_ROLE defaults to "worker"); if the
    # RQ path were reached, this import would try to start a daemon thread
    # against a real Redis and hang or fail.
    from wsgi import _apply_proxyfix

    _apply_proxyfix(app)
    return app


def test_proxyfix_applied_when_edge(probe_app: Flask, monkeypatch: pytest.MonkeyPatch):
    # Flip the flag, reset the cached Settings (the gate must see it at call
    # time), and re-apply: one ProxyFix layer lands on the probe app.
    monkeypatch.setenv("KUBEDASH_TLS_EDGE", "true")
    _config._settings = None
    from wsgi import _apply_proxyfix

    _apply_proxyfix(probe_app)
    client = probe_app.test_client()
    assert (
        client.get("/probe", headers={"X-Forwarded-Proto": "https"}).get_json()["secure"]
        is True
    )
    # No forwarded header → still plain HTTP (ProxyFix does not lie by default).
    assert client.get("/probe").get_json()["secure"] is False


def test_proxyfix_inactive_without_edge(probe_app: Flask):
    # Gate off: the raw X-Forwarded-Proto is untrusted — a spoof must NOT
    # flip request.is_secure.
    client = probe_app.test_client()
    assert (
        client.get("/probe", headers={"X-Forwarded-Proto": "https"}).get_json()["secure"]
        is False
    )
