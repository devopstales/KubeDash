"""Docker-free smoke for Task 4 (run with: uv run python smoke_task4.py).

Proves the cluster registry spine without Testcontainers:
  1. register cluster → 201, stored encrypted (no plaintext at rest,
     version byte 0x01 present), auto-bound as admin
  2. list bound clusters → contains the registered name
  3. duplicate name → 409 CLUSTER_ALREADY_EXISTS
  4. invalid kubeconfig → 422 INVALID_KUBECONFIG (nothing stored)
  5. unbound user → empty list + 404 on the cluster
  6. health with FakeK8s → 200 up / 502 CLUSTER_UNREACHABLE
  7. /healthz → 200 (open route, no JWT)
"""
from urllib.parse import parse_qs, urlparse

import app.extensions as ext
from app import create_app
from app.core.security import _oauth

KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    "contexts:\n"
    "- name: c\n"
    "  context:\n"
    "    cluster: c\n"
    "    user: u\n"
    "current-context: c\n"
    "users:\n"
    "- name: u\n"
    "  user: {}\n"
)


class _FakeRedis:
    store: dict[str, str] = {}

    def set(self, key, value, ex=None):
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        return int(self.store.pop(key, None) is not None)

    def flushall(self):
        self.store.clear()


class FakeK8s:
    def __init__(self, kubeconfig: bytes, readyz_result: bool = False) -> None:
        self.kubeconfig = kubeconfig
        self._readyz_result = readyz_result
        FakeK8s.last = self

    def list_pods(self, namespace):
        return []

    def readyz(self) -> bool:
        return self._readyz_result


def main() -> None:
    _oauth.app = None
    _oauth._clients.clear()
    app = create_app({
        "TESTING": True,
        "DATABASE_URL": "sqlite://",
        "REDIS_URL": "redis://localhost:6399/0",
        "KUBEDASH_KUBEDASH_JWT_SECRET": "smoke-jwt-secret-32-bytes-long!!!!!01",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    ext.redis_client = _FakeRedis()

    import app.core.security as sec

    sec.oidc_authorize_url = lambda state: f"http://mock.test/authorize?state={state}"
    sec.oidc_exchange = lambda code: {
        "sub": "sub-smoke", "email": "smoke@test.com", "name": "Smoke", "groups": []
    }

    with app.app_context():
        from app.extensions import db
        from app.models.binding import ClusterBinding
        from app.models.cluster import Cluster
        from app.models.user import User
        from app.services import k8s_client as kc
        from app.services.k8s_client import decrypt_kubeconfig

        db.create_all()
        c = app.test_client()

        # login
        r1 = c.post("/api/v1/auth/login")
        state = parse_qs(urlparse(r1.headers["Location"]).query)["state"][0]
        r2 = c.get(f"{r1.headers['Location']}&code=fixed&state={state}")
        tok = parse_qs(urlparse(r2.headers["Location"]).query)["token"][0]
        h = {"Authorization": f"Bearer {tok}"}

        # 1. register → 201, encrypted at rest, auto-bound admin
        r = c.post("/api/v1/clusters", json={
            "name": "prod", "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG, "context": "prod"}, headers=h)
        assert r.status_code == 201, f"register: {r.status_code} {r.get_data(as_text=True)}"
        body = r.get_json()
        assert body["name"] == "prod" and body["id"] is not None
        row = db.session.get(Cluster, body["id"])
        assert b"apiVersion" not in row.kubeconfig_enc, "plaintext leaked at rest"
        assert row.kubeconfig_enc[0] == 0x01, "missing OD-2 version byte"
        assert decrypt_kubeconfig(row.kubeconfig_enc) == KUBECONFIG.encode(), "round-trip"
        u = db.session.execute(db.select(User).filter_by(sub="sub-smoke")).scalar_one()
        b = db.session.execute(
            db.select(ClusterBinding).filter_by(user_id=u.id, cluster_id=row.id)
        ).scalar_one()
        assert b.role == "admin", "auto-bind must be admin"
        print(f"PASS 1: register → 201, encrypted (version byte {row.kubeconfig_enc[0]:#x}), "
              f"auto-bound admin, round-trip OK")

        # 2. list bound clusters
        r = c.get("/api/v1/clusters", headers=h)
        assert r.status_code == 200
        names = [x["name"] for x in r.get_json()]
        assert "prod" in names, f"prod not in {names}"
        print(f"PASS 2: list bound clusters → {names}")

        # 3. duplicate name → 409
        r = c.post("/api/v1/clusters", json={
            "name": "prod", "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG, "context": "prod"}, headers=h)
        assert r.status_code == 409, f"dup: {r.status_code}"
        assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
        print("PASS 3: duplicate name → 409 CLUSTER_ALREADY_EXISTS")

        # 4. invalid kubeconfig → 422 (nothing stored)
        r = c.post("/api/v1/clusters", json={
            "name": "bad", "api_server": "https://1.2.3.4:6443",
            "kubeconfig": "::not-yaml", "context": "bad"}, headers=h)
        assert r.status_code == 422, f"invalid: {r.status_code} {r.get_data(as_text=True)}"
        assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"
        bad = db.session.execute(
            db.select(Cluster).filter_by(name="bad")).scalar_one_or_none()
        assert bad is None, "invalid kubeconfig must not be stored"
        print("PASS 4: invalid kubeconfig → 422 INVALID_KUBECONFIG, nothing stored")

        # 5. unbound user → empty list + 404
        from app.core.security import issue_token_pair

        u2 = User(sub="stranger", email="s@example.com")
        db.session.add(u2)
        db.session.commit()
        access2, _ = issue_token_pair(u2)
        r = c.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access2}"})
        assert r.status_code == 200 and r.get_json() == []
        r = c.get("/api/v1/clusters/1", headers={"Authorization": f"Bearer {access2}"})
        assert r.status_code == 404, f"unbound get: {r.status_code}"
        assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"
        print("PASS 5: unbound user → empty list, 404 CLUSTER_NOT_FOUND on get")

        # 6. health with FakeK8s
        kc.pool = kc.K8sClientPool(
            factory=lambda plain: FakeK8s(plain, readyz_result=True))
        r = c.get("/api/v1/clusters/1/health", headers=h)
        assert r.status_code == 200 and r.get_json() == {"status": "up"}, r.get_data(as_text=True)
        # the factory received the PLAINTEXT kubeconfig
        assert FakeK8s.last.kubeconfig == KUBECONFIG.encode()
        kc.pool = kc.K8sClientPool(
            factory=lambda plain: FakeK8s(plain, readyz_result=False))
        r = c.get("/api/v1/clusters/1/health", headers=h)
        assert r.status_code == 502, f"health down: {r.status_code}"
        assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"
        print("PASS 6: health → 200 up / 502 CLUSTER_UNREACHABLE (factory got plaintext)")

        # 7. /healthz open
        r = c.get("/healthz")
        assert r.status_code == 200, f"/healthz: {r.status_code}"
        print("PASS 7: /healthz → 200 (open route)")

    _oauth.app = None
    _oauth._clients.clear()
    print("\nAll Task 4 smoke checks passed.")


if __name__ == "__main__":
    main()
