"""CI-rendered template test for charts/kubedash (pure: helm template + yaml).

No Docker needed. The seam under test is values.yaml keys → Deployment env.
"""
import pathlib
import subprocess

import yaml

CHART = str(pathlib.Path(__file__).resolve().parents[2] / "charts" / "kubedash")


def _template(*args: str) -> str:
    return subprocess.run(
        ["helm", "template", "t", CHART, *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def test_deployment_has_replica_id_from_downward_api():
    docs = [d for d in yaml.safe_load_all(_template()) if d and d.get("kind") == "Deployment"]
    assert docs, "no Deployment rendered"
    env = {e["name"]: e for e in docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]}
    rid = env["KUBEDASH_REPLICA_ID"]
    assert rid["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    assert env["KUBEDASH_ROLE"]["value"] == "leader"


def test_oidc_env_wired_from_values():
    out = _template(
        "--set", "auth.oidc.issuer=https://idp.test",
        "--set", "auth.oidc.clientId=kubedash",
        "--set", "image.repository=ghcr.io/org/kubedash",
    )
    assert "https://idp.test" in out
    assert "KUBEDASH_OIDC_CLIENT_ID" in out and "kubedash" in out
    assert "ghcr.io/org/kubedash" in out


def test_gunicorn_and_tuning_env_rendered():
    out = _template("--set", "gunicorn.workers=8", "--set", "gunicorn.threads=3")
    assert "GUNICORN_WORKERS" in out and "8" in out
    assert "GUNICORN_THREADS" in out and "3" in out
    # Only the two §7.5 keys this change adds to Settings may render; the
    # other four are ADR-0010's (env with no Settings field is dropped).
    assert "KUBEDASH_FIRST_PAINT_BACKSTOP" in out
    assert "KUBEDASH_NAMESPACE_LIST_TIMEOUT" in out
