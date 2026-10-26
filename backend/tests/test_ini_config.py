"""ADR-0028: kubedash.ini as the primary config source, env override, no
hard-coded in-code defaults for identities/credentials.

TICKET-01 covers the resolution core + home derivation. These tests drive
``ini_config`` directly (no container runtime) via the KUBEDASH_HOME anchor:
the INI is ``<home>/kubedash.ini`` and the static dir ``<home>/static``.
"""
from __future__ import annotations

import pathlib

import pytest

import app.core.config as _config
from app.core import ini_config


def _home(tmp_path: pathlib.Path) -> pathlib.Path:
    """A fresh temp KUBEDASH_HOME; the INI is <home>/kubedash.ini."""
    home = tmp_path / "home"
    home.mkdir()
    return home


def _write_ini(home: pathlib.Path, text: str) -> pathlib.Path:
    (home / "kubedash.ini").write_text(text)
    return home


# A complete INI: every REQUIRED key present, so create_app (which constructs
# the full Settings and therefore fails fast on any missing REQUIRED key) boots.
_FULL_INI = """
[DEFAULT]
app_mode = development

[security]
jwt_secret = from-ini
secret_key = from-ini
admin_password = from-ini

[database]
url = sqlite://

[remote_cache]
url = redis://localhost:6390/0

[bootstrap]
bootstrap_admin_email = admin@local

[deployment]
admin_kubeconfig = /test/admin.kubeconfig
"""


def test_ini_provides_value(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(_home(tmp_path), "[security]\njwt_secret = from-ini\n")
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    assert _config.get_settings().kubedash_jwt_secret == "from-ini"


def test_env_overrides_ini(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(_home(tmp_path), "[security]\njwt_secret = from-ini\n")
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    monkeypatch.setenv("KUBEDASH_KUBEDASH_JWT_SECRET", "from-env")
    ini_config.reset()
    assert _config.get_settings().kubedash_jwt_secret == "from-env"


def test_override_beats_env_and_ini(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(_home(tmp_path), _FULL_INI)
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    monkeypatch.setenv("KUBEDASH_KUBEDASH_JWT_SECRET", "from-env")
    from app import create_app

    ini_config.reset()
    create_app({"KUBEDASH_KUBEDASH_JWT_SECRET": "from-override", "TESTING": True})
    assert _config.get_settings().kubedash_jwt_secret == "from-override"


def test_home_paths_derived_from_kubedash_home(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path)
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    hp = ini_config.home_paths()
    assert hp["ini"] == home / "kubedash.ini"
    assert hp["static"] == home / "static"


def test_home_falls_back_to_wsgi_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    # dev: KUBEDASH_HOME unset -> derived from ini_config.py's own location
    # (app/core/ini_config.py -> parents[2] == <repo>/backend)
    monkeypatch.delenv("KUBEDASH_HOME", raising=False)
    ini_config.reset()
    hp = ini_config.home_paths()
    assert hp["ini"].parent.name == "backend"
    assert hp["ini"].name == "kubedash.ini"
    assert hp["static"].name == "static"


def test_static_dir_from_home_paths(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # KUBEDASH_STATIC_DIR is gone: register_static reads home_paths()["static"]
    home = _write_ini(_home(tmp_path), _FULL_INI)
    (home / "static").mkdir()
    (home / "static" / "index.html").write_text("<html>spa</html>")
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    monkeypatch.delenv("KUBEDASH_STATIC_DIR", raising=False)
    ini_config.reset()
    from app import create_app

    app = create_app({"TESTING": True})
    resp = app.test_client().get("/")
    assert resp.status_code == 200
    assert b"spa" in resp.data


def test_optional_and_behavior_knobs_keep_defaults(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(_home(tmp_path), "[DEFAULT]\napp_mode = production\n")
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    s = _config.get_settings()
    assert s.cookie_secure is True  # fail-closed default (ADR-0025/0027)
    assert s.flask_env == "production"  # INI value
    assert s.kubedash_role == "worker"  # optional default
    assert s.kubedash_replica_id == "local"


# ---------------------------------------------------------------------------
# TICKET-02: full 4.1 schema mapping (database/remote_cache/sso/deployment)
# ---------------------------------------------------------------------------


def test_database_split_fields(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(
        _home(tmp_path),
        "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p\n",
    )
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://u:p@db:5432/kubedash"


def test_database_split_quotes_password(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(
        _home(tmp_path),
        "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p@ss:wd\n",
    )
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://u:p%40ss%3Awd@db:5432/kubedash"


def test_database_url_wins_over_split(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(
        _home(tmp_path),
        "[database]\ntype = postgres\nhost = db:5432\nname = kubedash\nuser = u\npassword = p\n"
        "url = postgresql://x:y@z/q\n",
    )
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    assert _config.get_settings().database_url == "postgresql://x:y@z/q"


def test_remote_cache_split_or_url(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(
        _home(tmp_path),
        "[remote_cache]\nredis_host = cache:6380\nredis_db = 2\n",
    )
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    assert _config.get_settings().redis_url == "redis://cache:6380/2"
    # Rewrite the INI in the SAME home (url wins over split fields).
    _write_ini(home, "[remote_cache]\nurl = redis://other:6379/9\nredis_host = cache\n")
    ini_config.reset()
    assert _config.get_settings().redis_url == "redis://other:6379/9"


def test_sso_and_deployment_and_optional(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(
        _home(tmp_path),
        "[sso_settings]\nissuer_url = https://idp\nclient_id = cid\nsecret = csec\n"
        "bootstrap_users = a@x,b@y\n"
        "[deployment]\nkubedash_role = leader\ntls_edge = true\n",
    )
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    s = _config.get_settings()
    assert s.oidc_issuer == "https://idp"
    assert s.oidc_client_id == "cid"
    assert s.oidc_client_secret == "csec"
    assert s.sso_bootstrap_users == "a@x,b@y"
    assert s.kubedash_role == "leader"
    assert s.tls_edge is True


def test_app_mode_no_default_leak(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _write_ini(_home(tmp_path), "[deployment]\napp_mode = production\n")
    monkeypatch.setenv("KUBEDASH_HOME", str(home))
    ini_config.reset()
    # app_mode under [deployment] is seen (fallback), not from a leaked DEFAULT
    assert _config.get_settings().flask_env == "production"
