"""Shared Smorest auth hook (R9).

Extracted from Task 3's ``ClustersApi._auth`` exemplar so the stub APIs (and
Tasks 4-5's real ones) call one helper instead of re-copying the pattern.

flask-smorest 0.47 has no ``Api.on_before_request``: the hook is registered
app-wide and must SCOPE itself to the domain routes it protects — only
``/api/v1/*`` paths that are NOT the auth namespace (auth routes self-manage
via ``require_auth``) and NOT the OpenAPI doc paths. Everything else —
/healthz, /readyz, /api/docs, /api/openapi.json, the SPA root — passes
through untouched. Upgrade path: smorest's ``Api.on_before_request(fn,
blueprint=False)`` when it ships.
"""
from flask import request

from app.core.security import _auth_check


def _check() -> None:
    """The shared JWT-verify hook: enforce auth on ``/api/v1/*`` domain routes
    only, skipping the auth namespace (self-managed via ``require_auth``)."""
    path = request.path
    # Only enforce auth on /api/v1/* domain routes. Health probes, the
    # OpenAPI doc, and the SPA live outside /api/v1/ and stay open.
    if not path.startswith("/api/v1/"):
        return
    if path.startswith("/api/v1/auth/"):
        return  # auth routes are open pre-JWT; /auth/me uses require_auth
    if path.startswith("/api/v1/kubectl/"):
        # ADR-0011: the kubectl credential plugin calls this BEFORE it has a
        # token (bootstrapping auth) — the route is open by design.
        return
    _auth_check()


def apply_auth(app: object) -> None:
    """Register the path-scoped JWT verify on the REAL Flask ``app``.

    ``app`` is untyped on purpose: callers pass ``Flask.__name__``-typed
    ``app`` from their ``on_init(self, app)``. Flask deduplicates identical
    before_request functions, so multiple domain APIs registering the SAME
    ``_check`` coexist as a single hook — registration is idempotent.
    """
    app.before_request(_check)  # type: ignore[attr-defined]
