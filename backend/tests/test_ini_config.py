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
