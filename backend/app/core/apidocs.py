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

    app.register_blueprint(bp)
