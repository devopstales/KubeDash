import os

from lib.replica_mode import (
    DEFAULT_REPLICA_MODE,
    DEFAULT_REPLICA_COUNT,
    get_replica_mode,
    get_replica_count,
    validate_replica_config,
)


def test_get_replica_mode_from_env(monkeypatch, app):
    monkeypatch.setenv('REPLICA_MODE', 'cluster')
    assert get_replica_mode(app) == 'cluster'


def test_get_replica_mode_invalid_falls_back(monkeypatch, app):
    monkeypatch.setenv('REPLICA_MODE', 'bogus')
    assert get_replica_mode(app) == DEFAULT_REPLICA_MODE


def test_get_replica_count_from_env(monkeypatch, app):
    monkeypatch.setenv('REPLICA_COUNT', '3')
    assert get_replica_count(app) == 3


def test_get_replica_count_invalid_falls_back(monkeypatch, app):
    monkeypatch.setenv('REPLICA_COUNT', 'not-a-number')
    assert get_replica_count(app) == DEFAULT_REPLICA_COUNT


def test_validate_replica_config_cluster_requires_redis_and_postgres(monkeypatch, app):
    monkeypatch.setenv('REPLICA_MODE', 'cluster')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tmp/test.db'
    app.config['kubedash.ini'].set('remote_cache', 'redis_enabled', 'false')

    try:
        validate_replica_config(app)
        assert False, 'Expected RuntimeError when cluster mode uses SQLite and no Redis'
    except RuntimeError as exc:
        assert 'Cluster replica mode requires a shared database backend' in str(exc) or 'requires Redis session backend' in str(exc)
