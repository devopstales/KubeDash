def test_readyz_ok_when_deps_up(client, app):
    # ADR-0028: readyz's admin-kubeconfig probe is LAZY — it resolves
    # get_settings() on the first request, after create_app's config_overrides
    # are applied. Re-clear the Settings singleton (a wsgi import may have
    # cached it before the overrides) so the probe sees this app's config.
    import app.core.config as _config

    _config._settings = None
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["database"] == "ok"
    assert body["redis"] == "ok"


def test_readyz_names_failing_dependency(client, app, monkeypatch):
    import app.core.config as _config

    from app.extensions import redis_client

    # Same lazy-probe reset as test_readyz_ok_when_deps_up (ADR-0028).
    _config._settings = None

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise ConnectionError("down")

    # FlaskRedis delegates via __getattr__, so patch the instance's client
    # (not the class) for the failure to be visible in /readyz.
    monkeypatch.setattr(redis_client._redis_client, "ping", _raise)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["redis"] == "down"
    assert body["database"] == "ok"


def test_readyz_names_failing_database(client, monkeypatch):
    from app.extensions import db

    class _BrokenEngine:
        def connect(self) -> None:
            raise ConnectionError("db down")

    # flask-sqlalchemy exposes ``engine`` as a read-only property — patch the class.
    monkeypatch.setattr(type(db), "engine", property(lambda _self: _BrokenEngine()))
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["database"] == "down"
    assert body["redis"] == "ok"
