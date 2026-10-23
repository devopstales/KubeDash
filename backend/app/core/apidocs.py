"""Swagger UI air-gap (ADR-0020): serve the UI assets from the app, never a CDN.

Reads the vendored ``swagger-ui-bundle`` files via ``importlib.resources`` so
the bundle rides in the Python image (ADR-0006 single container) and the page
makes zero outbound calls at runtime.

NOTE: the blueprint's ``swagger-ui-dist`` is the NPM package name; the PyPI
distribution is ``swagger-ui-bundle`` (module ``swagger_ui_bundle``), which
vendors the dist files under ``vendor/swagger-ui-<version>/`` rather than at
the package root — hence ``_DIST_SUBDIR``.
"""
from __future__ import annotations

import importlib.resources

from flask import Blueprint, Flask, Response, abort
from flask_smorest import Api

# Package-relative dir holding the dist files. The package ships a
# versioned subdir under vendor/ (currently swagger-ui-4.15.5). Kept as a
# module-level constant so a version bump is a one-line edit.
_DIST_SUBDIR = "vendor/swagger-ui-4.15.5"
_DIST_PKG = "swagger_ui_bundle"

# route suffix -> (package-relative filename, media type). The handler and
# the tests both read this map, so a renamed file edits one place.
_JS = "application/javascript"
SWAGGER_ASSETS: dict[str, tuple[str, str]] = {
    "swagger-ui.css": ("swagger-ui.css", "text/css"),
    "swagger-ui-standalone-preset.js": ("swagger-ui-standalone-preset.js", _JS),
    "swagger-ui-bundle.js": ("swagger-ui-bundle.js", _JS),
}


def _asset_bytes(filename: str) -> bytes:
    root = importlib.resources.files(_DIST_PKG).joinpath(_DIST_SUBDIR)
    return root.joinpath(filename).read_bytes()


def register_asset_routes(app: Flask) -> None:
    """Register /api/docs/<asset> routes (same /api prefix as the smorest
    api-docs blueprint). Called BEFORE register_static so the SPA catch-all
    never sees these paths."""
    bp = Blueprint("swagger_assets", __name__, url_prefix="/api/docs")

    @bp.route("/<name>")
    def asset(name: str) -> Response:
        if name not in SWAGGER_ASSETS:
            abort(404)
        filename, media_type = SWAGGER_ASSETS[name]
        return Response(_asset_bytes(filename), mimetype=media_type)

    # Fail at boot, not on first request: a pin/subdir drift (e.g. a future
    # swagger-ui-bundle 1.x release renaming the vendored dir) must raise here.
    try:
        for filename, _ in SWAGGER_ASSETS.values():
            _asset_bytes(filename)
    except OSError as exc:
        msg = f"swagger-ui asset missing from {_DIST_PKG}/{_DIST_SUBDIR}: {filename}"
        raise RuntimeError(msg) from exc

    app.register_blueprint(bp)


_BEARER_SCHEME = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
_BEARER_ID = "BearerAuth"
#: ADR-0025: the browser source. Documented alongside Bearer because both are
#: accepted by `_auth_check`; the OpenAPI UI cannot set an HttpOnly cookie, so
#: this exists to make the contract visible, not to drive "Try it out".
_COOKIE_SCHEME = {"type": "apiKey", "in": "cookie", "name": "kd_access"}
_COOKIE_ID = "CookieAuth"


def register_security_scheme(api: Api) -> None:
    """Idempotently add the BearerAuth JWT and CookieAuth schemes to the spec
    (called after api.init_app, so api.spec exists). A no-op if a scheme is
    already present on this spec — tested by double-invocation in
    test_register_security_scheme_is_idempotent."""
    spec = api.spec
    if spec is None:
        return
    if _BEARER_ID not in spec.components.security_schemes:
        spec.components.security_scheme(_BEARER_ID, _BEARER_SCHEME)
    if _COOKIE_ID not in spec.components.security_schemes:
        spec.components.security_scheme(_COOKIE_ID, _COOKIE_SCHEME)
