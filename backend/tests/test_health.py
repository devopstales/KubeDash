"""ADR-0029/0030: /readyz is Postgres-only — there is no redis check.

The failing-dependency scenario is the database probe: a broken engine
reports ``database: down`` and the endpoint answers 503. (The
admin-kubeconfig probe, ADR-0021 I-NEW-6, stays but the session fixture
home leaves it in the in-cluster branch — the file probe is not the tier's
failing-dep scenario.)
"""


def test_readyz_ok_when_deps_up(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["database"] == "ok"
    # ADR-0029/0030: redis is gone — there is no redis check in the body.
    assert "redis" not in body


def test_readyz_names_failing_dependency(client, monkeypatch):
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
    assert "redis" not in body
