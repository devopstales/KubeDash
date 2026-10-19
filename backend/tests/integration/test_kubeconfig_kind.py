"""ADR-0011 (TICKET-05, tracer 2) — integration: the downloaded YAML is what
kubectl expects.

kind-gated (skips where kind/docker are absent; deselects cleanly under
``-m "not integration"``): registers the kind cluster through the real
POST /clusters route (so the kubeconfig is genuinely encrypted at rest),
downloads GET /kubeconfig, and validates it with ``kubectl config view`` —
the exact consumer of the file. The exec entry's ``--server`` must match
``KUBEDASH_PLUGIN_SERVER``; the user is exec-only (no token).

SATISFIES (kind half): user-downloads-a-multi-cluster-kubeconfig;
the-kubeconfig-never-embeds-a-token.
"""
import os
import secrets

import pytest
import yaml

PLUGIN_SERVER = "https://kubedash.example.com"


@pytest.mark.integration
def test_downloaded_yaml_passes_kubectl_config_view(
    app, client, kind_cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    # A dedicated user (not the session-persisted mock-OIDC one): register the
    # kind cluster as THIS user (auto-bind, cluster-scoped) and mint a token.
    monkeypatch.setenv("KUBEDASH_PLUGIN_SERVER", PLUGIN_SERVER)
    import app.core.config as _config

    _config._settings = None

    suffix = secrets.token_hex(4)
    with app.app_context():
        u = User(sub=f"kccfg-{suffix}", email=f"kccfg-{suffix}@example.com")
        db.session.add(u)
        db.session.commit()
        u_id = u.id
        access, _ = issue_token_pair(u)

    h = {"Authorization": f"Bearer {access}"}
    # Register through the REAL route: the stored form is OD-2 ciphertext.
    r = client.post(
        "/api/v1/clusters",
        json={
            "name": f"kind-kccfg-{suffix}",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kind_cluster.decode(),
            "context": "kind-kind-kubedash-test",
        },
        headers=h,
    )
    assert r.status_code in (200, 201), r.get_json()

    r = client.get("/api/v1/kubeconfig", headers=h)
    assert r.status_code == 200, r.get_json()
    yml = r.data.decode()
    doc = yaml.safe_load(yml)

    # The consumer check: kubectl itself must accept the file.
    kc_file = f"/tmp/opencode/kccfg-{suffix}.yaml"
    with open(kc_file, "w") as f:
        f.write(yml)
    out = subprocess.run(
        ["kubectl", "config", "view", f"--kubeconfig={kc_file}", "-o", "json"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    k8s_view = yaml.safe_load(out.stdout)
    assert any(
        u["name"] == "kubedash" and "exec" in u.get("user", {})
        for u in k8s_view.get("users", [])
    ), k8s_view
    # ADR-0011: the --server matches KUBEDASH_PLUGIN_SERVER (asserted on the
    # RAW downloaded YAML — kubectl config view normalizes the exec entry on
    # output, adding env/provideClusterInfo, so the key-set check must not run
    # on kubectl's re-emission).
    raw_exec = next(u for u in doc["users"] if u["name"] == "kubedash")["user"]["exec"]
    assert raw_exec["args"] == ["kubedash", "get-token", f"--server={PLUGIN_SERVER}"]
    # No token/tokenFile/oidc-* anywhere in the RAW file.
    assert "token" not in raw_exec and "tokenFile" not in raw_exec
    flat = str(doc)
    assert "token:" not in flat and "tokenFile:" not in flat and "oidc-" not in flat
    # Clean up the temp file + the row we registered via the route.
    with app.app_context():
        from app.models.cluster import Cluster

        row = db.session.execute(
            db.select(Cluster).filter_by(name=f"kind-kccfg-{suffix}")
        ).scalar_one_or_none()
        if row is not None:
            db.session.delete(row)
            db.session.commit()
    os.unlink(kc_file)
