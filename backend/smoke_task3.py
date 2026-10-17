"""Docker-free smoke for Task 3 (run with: uv run python smoke_task3.py).

Proves the pure parts of the OIDC spine without Testcontainers:
  1. unauthenticated route → 401 {error:{code:UNAUTHORIZED}}
  2. 404 → {error:{code,message}} envelope
  3. JWT issue/verify round-trip
  4. state mismatch → 400 STATE_MISMATCH
  5. unhandled exception → 500 INTERNAL_ERROR (no stack-trace leak)
"""
from urllib.parse import parse_qs, urlparse

import app.extensions as ext
from app import create_app
from app.core.security import _oauth


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
    fake = _FakeRedis()
    ext.redis_client = fake

    @app.route("/test/smoke-404")
    def not_found():
        from app.core.errors import ClusterNotFoundError

        raise ClusterNotFoundError("cluster c-99 not found")

    @app.route("/test/smoke-500")
    def boom():
        raise ValueError("secret-smoke-leak")

    with app.app_context():
        from app.extensions import db
        from app.models.token import RefreshToken
        from app.models.user import User

        db.create_all()

        # 1. unauthenticated route → 401 stable shape
        c = app.test_client()
        r = c.get("/api/v1/clusters")
        assert r.status_code == 401, f"expected 401, got {r.status_code}"
        assert r.get_json() == {
            "error": {"code": "UNAUTHORIZED", "message": "missing or invalid token"}
        }, r.get_json()
        print("PASS 1: unauthenticated → 401 UNAUTHORIZED stable shape")

        # 2. KubeDashHttpError → 404 envelope
        def _skip_auth() -> None:
            from flask import request

            request.environ["KD_SKIP_AUTH"] = True

        # Prepend so it runs before ClustersApi._auth (registered first).
        app.before_request_funcs[None].insert(0, _skip_auth)
        r = c.get("/test/smoke-404")
        assert r.status_code == 404, f"expected 404, got {r.status_code}"
        body = r.get_json()
        assert body == {"error": {"code": "CLUSTER_NOT_FOUND", "message": "cluster c-99 not found"}}
        print(f"PASS 2: KubeDashHttpError → 404 {body}")

        # 3. JWT issue/verify round-trip
        from app.core.security import issue_token_pair, verify_jwt

        u = User(sub="sub-smoke", email="smoke@test.com")
        db.session.add(u)
        db.session.commit()
        access, refresh = issue_token_pair(u)
        claims = verify_jwt(access)
        assert claims["sub"] == "sub-smoke"
        print(f"PASS 3: JWT round-trip (sub={claims['sub']}, jti={claims['jti'][:8]}…)")

        # 4. state mismatch → 400 STATE_MISMATCH (mock the OIDC pair)
        import app.core.security as sec

        sec.oidc_authorize_url = lambda state: f"http://mock.test/authorize?state={state}"
        sec.oidc_exchange = lambda code: {
            "sub": "sub-smoke", "email": "smoke@test.com", "name": "Smoke", "groups": []
        }
        r1 = c.post("/api/v1/auth/login")
        cb = r1.headers["Location"]
        state = parse_qs(urlparse(cb).query)["state"][0]
        r2 = c.get(f"/api/v1/auth/callback?state=not-{state}&code=fixed")
        assert r2.status_code == 400, f"expected 400, got {r2.status_code}"
        assert r2.get_json()["error"]["code"] == "STATE_MISMATCH"
        print(f"PASS 4: state mismatch → 400 {r2.get_json()}")

        # 5. unhandled exception → 500 INTERNAL_ERROR (no leak)
        r3 = c.get("/test/smoke-500")
        assert r3.status_code == 500
        assert r3.get_json() == {"error": {"code": "INTERNAL_ERROR", "message": "internal server error"}}
        assert "secret-smoke-leak" not in r3.get_data(as_text=True)
        print(f"PASS 5: unhandled → 500 INTERNAL_ERROR (no leak)")

        # 6. full login round-trip (mock OIDC) → 302 /?token=...&refresh=...
        r1 = c.post("/api/v1/auth/login")
        cb = r1.headers["Location"]
        state = parse_qs(urlparse(cb).query)["state"][0]
        r2 = c.get(f"/api/v1/auth/callback?state={state}&code=fixed")
        assert r2.status_code == 302, f"expected 302, got {r2.status_code}"
        loc = r2.headers["Location"]
        assert loc.startswith("/?token=")
        q = parse_qs(urlparse(loc).query)
        assert "token" in q and "refresh" in q
        print(f"PASS 6: login round-trip → 302 {loc[:60]}…")

        # 7. /auth/me with the new JWT
        r3 = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {q['token'][0]}"})
        assert r3.status_code == 200, f"expected 200, got {r3.status_code}"
        assert r3.get_json()["sub"] == "sub-smoke"
        print(f"PASS 7: /auth/me → {r3.get_json()}")

        # 8. refresh rotation: reuse → 401, row deleted
        old_refresh = q["refresh"][0]
        r4 = c.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert r4.status_code == 200
        new_refresh = r4.get_json()["refresh"]
        assert new_refresh != old_refresh
        r5 = c.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert r5.status_code == 401
        import hashlib

        h = hashlib.sha256(old_refresh.encode()).hexdigest()
        row = db.session.execute(
            db.select(RefreshToken).filter_by(token_hash=h)
        ).scalar_one_or_none()
        assert row is None, "consumed refresh row should be deleted"
        print("PASS 8: refresh rotation → reuse 401, row deleted")

    _oauth.app = None
    _oauth._clients.clear()
    print("\nAll smoke checks passed.")


if __name__ == "__main__":
    main()
