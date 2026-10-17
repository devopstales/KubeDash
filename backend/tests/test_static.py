# The conftest `app` fixture is rebuilt for these tests with a fake dist dir
# passed via config_overrides BEFORE create_app() (no re-registration):
import pytest


@pytest.fixture()
def static_app(pg_container, redis_container, tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "main.abc.js").write_text("console.log(1)")
    (tmp_path / "index.html").write_text("<html>kubedash</html>")
    from app import create_app
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": pg_container.get_connection_url(),
        "REDIS_URL": f"redis://{redis_container.get_container_host()}:{redis_container.exposed_port(6379)}",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
        "KUBEDASH_STATIC_DIR": str(tmp_path),
    })
    with application.app_context():
        from app.extensions import db
        db.create_all()
    return application

@pytest.fixture()
def static_client(static_app):
    return static_app.test_client()

def test_register_static_is_idempotent(static_app):
    # A second explicit call must not re-register routes (OD-4 guard).
    from app import register_static
    register_static(static_app)
    rules = [str(r) for r in static_app.url_map.iter_rules()]
    assert rules.count("/<path:path_>") == 1
    assert rules.count("/assets/<path:filename>") == 1

def test_index_served_at_root_and_spa_fallback(static_client):
    r = static_client.get("/")
    assert r.status_code == 200 and b"kubedash" in r.data
    assert r.headers["Cache-Control"] == "no-cache"
    r2 = static_client.get("/clusters/123")  # non-API path → SPA fallback
    assert r2.status_code == 200 and b"kubedash" in r2.data
    r3 = static_client.get("/assets/main.abc.js")
    assert r3.status_code == 200
    assert "immutable" in r3.headers["Cache-Control"]

def test_api_not_shadowed_by_catchall(static_client):
    r = static_client.get("/api/v1/clusters")
    assert r.status_code == 401  # auth hook, NOT index.html
    assert b"<html>" not in r.data
