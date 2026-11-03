"""Security header layer (ADR-0026) — the 4.1 initializer's 5.0 descendant.

4.1 set these in ``src/kubedash/lib/initializers/security.py``; the rebase
dropped the whole layer. Restored here as plain Flask hooks (no Talisman —
4.1 disabled Talisman's CSP anyway and hand-rolled the nonce; one less
dependency to keep honest under the air-gap, ADR-0020).

WHY the nonce is per-request in ``g``: a single startup-time nonce would
make every page's CSP identical — fine in itself, but a response cached
(by a proxy, or by a future mis-scoped Cache-Control) would carry a nonce
that is stale for its siblings. Per-request is what 4.1 did; keep it.
"""
from __future__ import annotations

import secrets

from flask import Flask, g, request
from werkzeug.wrappers import Response


def register_security_headers(app: Flask) -> None:
    """Register the before/after request hooks that emit the R3 header set.

    Called from ``create_app`` after ``register_errors`` (so smorest 4xx/5xx
    envelopes get the headers) and before ``register_static``. The hooks run
    on EVERY response — API, static, health, error — because they attach to
    the app, not to a route.
    """

    @app.before_request
    def _csp_nonce() -> None:
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def _headers(resp: Response) -> Response:
        # Static framing/nosniff/referrer + cross-origin isolation — the
        # same set on every response, TLS or not.
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # HSTS only when the request arrived over TLS. request.is_secure is
        # ProxyFix-corrected when KUBEDASH_TLS_EDGE=true (wsgi.py); over the
        # plain-HTTP fast path / test client it is False, so the header is
        # absent — it is a promise about *future* requests, meaningless on a
        # request that was not secure.
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        # CSP carries the per-request nonce (4.1 parity). No unsafe-eval, no
        # CDN source (air-gap, ADR-0020).
        nonce = getattr(g, "csp_nonce", "")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "font-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "connect-src 'self' wss: ws:; "
            "img-src 'self' data:"
        )
        # ADR-0006: static caching is set per-route in register_static and
        # MUST win. Setting no-store here would clobber ``immutable`` on
        # /assets/* — so scope the no-store invariant to the API surface.
        # (4.1 set it globally; that clobber was the bug.)
        # Scope on the MATCHED rule, not the raw path: request.path is
        # percent-ENCODED, so a semantically-identical API route reached as
        # /%41%70%69/... would skip the literal startswith("/api/") check
        # (same regression class the 4.1 global clobber was). url_rule.rule
        # is the registered, normalized pattern — every encoding of the same
        # route is covered; non-API rules (static/health/SPA) are untouched.
        if request.url_rule is not None and request.url_rule.rule.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        return resp
