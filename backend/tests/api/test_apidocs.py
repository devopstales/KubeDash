"""Swagger UI air-gap (R1/R2): the page is app-served, never a CDN.

Lives in tests/api/ to use the docker-free ``client`` fixture (tests/api/conftest.py).
"""
from __future__ import annotations

import importlib.resources
import json

from app.core import apidocs

_DIST = "swagger_ui_bundle"
_DIST_SUBDIR = apidocs._DIST_SUBDIR


def _read_package(filename: str) -> bytes:
    return (
        importlib.resources.files(_DIST).joinpath(_DIST_SUBDIR).joinpath(filename).read_bytes()
    )


def test_package_ships_bundle():
    # T3b / T8 proxy: the runtime venv actually resolves the asset file.
    assert (
        importlib.resources.files(_DIST)
        .joinpath(_DIST_SUBDIR)
        .joinpath("swagger-ui-bundle.js")
        .is_file()
    )


def test_docs_page_uses_local_asset_routes(client):
    html = client.get("/api/docs").get_data(as_text=True)
    assert "/api/docs/swagger-ui.css" in html
    assert "/api/docs/swagger-ui-standalone-preset.js" in html
    assert "/api/docs/swagger-ui-bundle.js" in html
    # No egress: no CDN and no other external asset URL in the page.
    assert "cdn.jsdelivr.net" not in html
    assert "https://" not in html
    assert "http://" not in html


def test_asset_routes_serve_real_files(client):
    css = client.get("/api/docs/swagger-ui.css")
    assert css.status_code == 200
    assert css.content_type.split(";")[0].strip() == "text/css"
    assert css.get_data()
    for js in ("swagger-ui-standalone-preset.js", "swagger-ui-bundle.js"):
        resp = client.get(f"/api/docs/{js}")
        assert resp.status_code == 200
        # Werkzeug may append a charset; the media type is the contract.
        assert resp.content_type.split(";")[0].strip() in {
            "application/javascript",
            "text/javascript",
        }
        assert resp.get_data()


def test_docs_assets_map_to_swagger_assets_not_spa(client):
    # Route-ordering guard: the asset routes win over the SPA catch-all.
    # (If register_asset_routes ran AFTER register_static, these 404.)
    #
    # NOTE: the blueprint registers ONE rule, /api/docs/<name>, per asset
    # (Flask url_map has no per-value rules; the blueprint's Step 3 code is a
    # single dynamic route). The guard therefore asserts (a) the dynamic rule
    # exists and (b) it does NOT fall through to the SPA catch-all — the
    # catch-all would also match /api/docs/swagger-ui.css, so this passes only
    # because the more specific /api/docs/<name> rule is registered and wins
    # on specificity.
    rules = {r.rule for r in client.application.url_map.iter_rules()}
    assert "/api/docs/<name>" in rules
    assert "/<path:path_>" in rules  # SPA catch-all exists
    # Behavior check: a request for a known asset path hits the asset handler,
    # NOT the SPA catch-all (which would 404 the .css/.js suffix or serve
    # index.html).
    css = client.get("/api/docs/swagger-ui.css")
    assert css.status_code == 200
    assert css.content_type.split(";")[0].strip() == "text/css"
    js = client.get("/api/docs/swagger-ui-bundle.js")
    assert js.status_code == 200
    assert js.content_type.split(";")[0].strip() in {"application/javascript", "text/javascript"}


def test_served_bundle_is_byte_identical_to_package(client):
    # Proves identity with the vendored file (catches a transform/encoding
    # bug or a stale in-repo copy). It does NOT by itself prove "not a CDN
    # fetch" — that is test_docs_page_uses_local_asset_routes (no external URL).
    served = client.get("/api/docs/swagger-ui-bundle.js").get_data()
    assert served == _read_package("swagger-ui-bundle.js")
    # Every asset in the map resolves to a real package file.
    for filename, _ in apidocs.SWAGGER_ASSETS.values():
        assert _read_package(filename)


def test_spec_declares_bearer_scheme(client):
    # T4
    spec = client.get("/api/openapi.json").get_json()
    assert spec["components"]["securitySchemes"]["BearerAuth"] == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }


def test_docs_page_is_open_without_token(client):
    # T5: the page is browsable with no Authorization header.
    resp = client.get("/api/docs")  # no Authorization header
    assert resp.status_code == 200


def test_register_security_scheme_is_idempotent():
    # T7 — test the GUARD directly by double-invocation on one built spec.
    # Building a second app does NOT test this (api.spec is rebuilt fresh per
    # init_app), so a second-create_app test would pass trivially.
    from app import create_app
    from app.extensions import api

    create_app({"DATABASE_URL": "sqlite://", "REDIS_URL": "redis://localhost:1/0"})
    assert api.spec is not None  # init_app built it
    apidocs.register_security_scheme(api)  # factory already called it once
    apidocs.register_security_scheme(api)  # must be a no-op, not a raise
    assert "BearerAuth" in api.spec.components.security_schemes


def test_spec_paths_superset_of_baseline(client):
    # T9 / R4: no previously documented operation vanished. Baseline = the
    # paths present before this change (captured once; see Step 3 note).
    from pathlib import Path

    spec = client.get("/api/openapi.json").get_json()
    baseline = set(json.loads((Path(__file__).parent / "apidocs_paths_baseline.json").read_text()))
    assert baseline <= set(spec["paths"])
