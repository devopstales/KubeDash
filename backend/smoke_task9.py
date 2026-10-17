"""Docker-free smoke for Task 9 (run with: uv run python smoke_task9.py).

Proves the register_static contract without Testcontainers/Docker:
  1. GET / -> 200 index.html + Cache-Control: no-cache
  2. GET /clusters/123 -> 200 index.html (SPA fallback)
  3. GET /assets/main.abc.js -> 200 + immutable
  4. GET /api/v1/clusters -> 401 auth envelope, NOT index.html (not shadowed)
  5. GET /healthz -> 200 {"status":"ok"}; /readyz reachable
  6. guard: api/ws/static-ext paths -> 404; idempotency guard set
"""
import tempfile
from pathlib import Path

from app import create_app

dist = Path(tempfile.mkdtemp(prefix="kd-dist-"))
(dist / "assets").mkdir()
(dist / "assets" / "main.abc.js").write_text("console.log(1)")
(dist / "index.html").write_text("<html>kubedash</html>")

app = create_app({
    "TESTING": True,
    "DATABASE_URL": "sqlite://",
    "REDIS_URL": "redis://localhost:6399/0",
    "KUBEDASH_JWT_SECRET": "test-jwt-secret",
    "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    "KUBEDASH_STATIC_DIR": str(dist),
})
c = app.test_client()

r = c.get("/")
assert r.status_code == 200 and b"kubedash" in r.data, (r.status_code, r.data)
assert r.headers["Cache-Control"] == "no-cache", r.headers["Cache-Control"]
print("PASS 1: / -> 200 index.html, Cache-Control:", r.headers["Cache-Control"])

r2 = c.get("/clusters/123")
assert r2.status_code == 200 and b"kubedash" in r2.data, (r2.status_code, r2.data)
assert r2.headers["Cache-Control"] == "no-cache", r2.headers["Cache-Control"]
print("PASS 2: /clusters/123 -> 200 index.html (SPA fallback), Cache-Control:",
      r2.headers["Cache-Control"])

r3 = c.get("/assets/main.abc.js")
assert r3.status_code == 200 and b"console.log(1)" in r3.data, (r3.status_code, r3.data)
assert "immutable" in r3.headers["Cache-Control"], r3.headers["Cache-Control"]
print("PASS 3: /assets/main.abc.js -> 200, Cache-Control:", r3.headers["Cache-Control"])

r4 = c.get("/api/v1/clusters")
assert r4.status_code == 401, r4.status_code
assert b"<html>" not in r4.data, r4.data
assert r4.get_json() == {"error": {"code": "UNAUTHORIZED", "message": "missing or invalid token"}}
print("PASS 4: /api/v1/clusters -> 401", r4.get_json(), "(NOT index.html)")

r5 = c.get("/healthz")
assert r5.status_code == 200 and r5.get_json() == {"status": "ok"}, (r5.status_code, r5.get_json())
print("PASS 5: /healthz -> 200", r5.get_json())

r6 = c.get("/readyz")
assert r6.status_code in (200, 503), r6.status_code  # 503 here: no live pg/redis
print("PASS 6: /readyz ->", r6.status_code, r6.get_json())

# guard: api/, ws/, static-ext paths fall through to 404, never index.html
for p in ("/api/whatever", "/ws/foo", "/x.js", "/y.css", "/z.json"):
    rg = c.get(p)
    assert rg.status_code == 404, (p, rg.status_code)
    assert b"<html>" not in rg.data, (p, rg.data)
print("PASS 7: api//ws//static-ext paths -> 404, never index.html")

assert app.config.get("_STATIC_REGISTERED") is True
print("PASS 8: _STATIC_REGISTERED idempotency guard set")

print("ALL PASS")
