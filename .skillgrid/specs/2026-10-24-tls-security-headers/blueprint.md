# TLS Edge + Security Headers — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files to touch, tests,
> and verification. The product *why* lives in `briefing.md` and ADR-0026. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T2 — transport + security-header change, multi-file, touches the auth delivery environment.

**Classification:** `risky` (new trust boundary — TLS edge + header policy; verification floor L3).

**Build shape:** Tracer thread — Task 1 proves the header policy end-to-end in the test
client (the thinnest path through the new layer); Tasks 2-4 thicken it (proxy trust, edge,
stack wiring); Task 5 is the runtime backstop.

**Goal:** Restore the 4.1 security-header layer (CSP/HSTS/COOP/CORE/framing/nosniff,
no-store on `/api/*`) and put a TLS edge in front of the local dev stack so the ADR-0025
`Secure` cookie is honest end-to-end.

**Architecture:** A new `core/security_headers.py` module registers Flask before/after
request hooks in `create_app` (nonce in `g`, header assembly in after_request). `wsgi.py`
gains an env-gated ProxyFix + optional SSL listener. The dev compose stack gains an `nginx`
service that terminates TLS and proxies to the backend over HTTPS. No new Python
dependency; the CSP contains no external source (air-gap, ADR-0020).

**Tech Stack:** Flask after_request hooks, werkzeug ProxyFix, nginx, mkcert, docker compose,
Playwright (e2e backstop).

**Spec:** `briefing.md` (R1-R6).
**Findings:** 4.1 branch audit — `git show 4.1:src/kubedash/lib/initializers/security.py`,
`4.1:deploy/docker-compose/dc-nginx.yaml`, `4.1:deploy/docker-compose/config/nginx-kubedash.conf`,
`4.1:docs/development/security.md` (the header reference table).
**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0006, ADR-0008, ADR-0014, ADR-0020,
ADR-0021, ADR-0025; ADR-0026 created by this change.

## Terms

None (uses the spec's vocabulary; the 4.1 initializer is cited as prior art, not a term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- Every response carries the eight R3 headers; CSP contains `default-src 'self'`,
  `script-src 'self' 'nonce-…'`, and no `unsafe-eval` (`strict-csp-with-nonce-on-api-response`).
- The CSP nonce differs between two requests to the same route (`csp-nonce-changes-per-request`).
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` is present when the
  request arrived over TLS and absent over plain HTTP (`hsts-present-over-tls-and-absent-over-plain-http`).
- `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0` on `/api/*` responses;
  `Cache-Control: immutable, max-age=31536000` still on `/assets/*` and
  `Cache-Control: no-cache` on the SPA index (`api-responses-never-cached`,
  `static-asset-caching-preserved`).
- With `KUBEDASH_TLS_EDGE=true`, a request carrying `X-Forwarded-Proto: https` is seen as
  secure by the app; without the flag it is not (`proxyfix-applied-behind-edge`,
  `proxyfix-inactive-without-edge`).
- **backstop:** with the dev stack + nginx edge up, `https://kubedash.local:443` serves the
  SPA, `http://kubedash.local` 301s to it, the cert chain verifies against the mkcert CA,
  and the login flow sets a `Secure` cookie that round-trips
  (`tls-edge-serves-https-and-redirects-http`, `secure-cookies-flow-end-to-end`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/core/security_headers.py` — the header layer (nonce, policy, after_request).
- `backend/tests/test_security_headers.py` — the R3/R4 unit suite.
- `dev/nginx/kubedash.conf` — the nginx edge config.
- `dev/certs/` (gitignored) + `dev/setup-tls.sh` — cert generation + verification.
- `.skillgrid/artifacts/04-adr-0026-tls-edge-and-security-headers.md` — the ADR (this
  blueprint's companion; already written, committed in the spec-zone step).

**Key links** (critical connections that must work together):
- `create_app` registers the hooks so EVERY response (API, static, error, health) carries
  the header set — the after_request must run for all responses, including 4xx/5xx from the
  smorest error handlers.
- The HSTS emission must read `request.is_secure`, which is only correct because ProxyFix
  (Task 3) rewrites it from `X-Forwarded-Proto` — the two tasks form one behavior; the
  `hsts-…` scenario is the integration proof.
- nginx's `proxy_ssl_trusted_certificate` must be the mkcert rootCA, and the backend's
  `:8443` cert must be signed by the same CA — the `secure-cookies-flow-end-to-end`
  scenario is the end-to-end proof.
- `dev-stack` (Task 5) must flip `KUBEDASH_COOKIE_SECURE=true` only when the edge is up —
  the flag is a property of the *stack* (edge up), not the *task*.

**One-way-door decisions:** None. (No migration, no public-API break, no dependency add;
nginx is a dev-stack image, mkcert is host tooling.)

## Global Constraints

- No new Python dependency (air-gap, ADR-0020) — the header layer is stdlib + Flask only.
- No new npm dependency (ADR-0020).
- CSP sources: `'self'`, nonce, `wss:`/`ws:`, `data:` for images ONLY — no CDN, no
  `unsafe-eval` (briefing R3).
- `X-XSS-Protection` is deliberately NOT set (ADR-0026 recorded deviation).
- `no-store` scope is `/api/*` ONLY; static caching per ADR-0006 is preserved (briefing R4).
- Backend ports: `:8080` plain (unchanged), `:8443` TLS (new). nginx: `:80`→`:443`.
- Hostname: `kubedash.local` (keeps `localhost:8080`/`:3000` fast paths intact).
- Conventional commits; spec-zone commits precede code-zone commits
  (`pre-commit` zone guard); WHY-comments on load-bearing invariants (AGENTS.md).
- The test client and `task dev-up` fast path keep `KUBEDASH_COOKIE_SECURE=false` —
  unchanged behavior (briefing R5).

## File Structure

- `backend/app/core/security_headers.py` (new) — nonce generation + the after-request
  header assembly. One function `register_security_headers(app)`; no Flask imports in
  services/ (this is `core/`, allowed to import Flask).
- `backend/app/__init__.py` — `create_app` calls `register_security_headers(app)` after
  `register_errors` (so error responses get headers too) and before `register_static`.
- `backend/wsgi.py` — ProxyFix (env-gated) + TLS listener (env-gated).
- `backend/app/core/config.py` — `tls_edge: bool = False`
  (`KUBEDASH_TLS_EDGE`, default False = today's behavior).
- `backend/tests/test_security_headers.py` (new) — the R3/R4 unit suite (test client).
- `dev/setup-tls.sh` (new) — idempotent cert generation + verification (mkcert + openssl).
- `dev/nginx/kubedash.conf` (new) — the edge config.
- `dev/docker-compose.yml` — the `nginx` service.
- `dev/.gitignore` — ignore `dev/certs/`.
- `Taskfile.yaml` — `dev-tls-setup`, `dev-up-ssl`, `e2e-ssl`; `dev-stack` edge-aware.
- `frontend/playwright.config.ts` — `E2E_TLS_CA` env → `https` baseURL + CA injection.
- `.skillgrid/specs/2026-10-24-tls-security-headers/` — spec zone (briefing, this
  blueprint, adr.md manifest, acceptance.feature).
- `.skillgrid/ASSUMPTIONS.md` — LOCKED index row for ADR-0026.

---

### Task 1: Security header layer (CSP + HSTS + framing + no-store)

**SATISFIES:** `strict-csp-with-nonce-on-api-response`, `csp-nonce-changes-per-request`,
`hsts-present-over-tls-and-absent-over-plain-http`, `static-security-headers-on-every-response`,
`api-responses-never-cached`, `static-asset-caching-preserved`

**Files:**
- Create: `backend/app/core/security_headers.py`
- Modify: `backend/app/core/config.py` (add `tls_edge`)
- Modify: `backend/app/__init__.py` (register the hooks in `create_app`)
- Test: `backend/tests/test_security_headers.py` (new)

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the first code task).
- Produces: `register_security_headers(app: Flask) -> None` — the single entry point
  `create_app` calls. The nonce lives in `g.csp_nonce`; tests assert on response headers
  only (the nonce is an implementation detail behind the CSP header).
- Seam: none (in-process Flask hooks).
- Deletion test: deleting the module removes every security header from every response —
  the exact 4.1 regression this restores.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Write the failing tests** — `backend/tests/test_security_headers.py`.

  Use the existing `api_app`/`api_client` fixtures from `backend/tests/api/conftest.py`
  (the docker-free sqlite + fake-redis app; `KUBEDASH_COOKIE_SECURE: False` already set —
  the test client speaks `http://localhost`, and plain-HTTP is precisely the HSTS-absent
  case the tests need). The `api` fixture set is available to root-tier tests because
  `backend/tests/conftest.py` declares `pytest_plugins = ["tests.api.conftest"]`
  (line 15) — but that conftest needs testcontainers. To stay docker-free, construct the
  app in this test file with the SAME pattern as `api_app` (copy the fixture body into a
  local `_app` fixture: sqlite, fake redis monkeypatched onto `app.extensions`, bootstrap
  env set + `_config._settings = None` reset). The pattern is at
  `backend/tests/api/conftest.py:55-95` — reuse it verbatim, minus the OIDC mock.

  ```python
  def test_api_response_carry_all_security_headers(_app):
      client = _app.test_client()
      r = client.post("/api/v1/auth/local",
                      json={"email": "admin@local", "password": "correct-horse"})
      # 302 (login ok) — the after_request must run for 3xx too
      assert r.status_code in (302, 401)
      assert r.headers["X-Frame-Options"] == "DENY"
      assert r.headers["X-Content-Type-Options"] == "nosniff"
      assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
      assert r.headers["Cross-Origin-Opener-Policy"] == "same-origin"
      assert r.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
      assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin"
      csp = r.headers["Content-Security-Policy"]
      assert "default-src 'self'" in csp
      assert "script-src 'self' 'nonce-" in csp
      assert "unsafe-eval" not in csp
      assert "wss:" in csp and "ws:" in csp

  def test_csp_nonce_changes_per_request(_app):
      client = _app.test_client()
      n1 = _nonce(client.get("/healthz"))
      n2 = _nonce(client.get("/healthz"))
      assert n1 and n2 and n1 != n2

  def test_hsts_absent_over_plain_http(_app):
      client = _app.test_client()
      assert "Strict-Transport-Security" not in client.get("/healthz").headers

  def test_hsts_present_over_tls(_app):
      client = _app.test_client()
      r = client.get("/healthz", environ_overrides={"wsgi.url_scheme": "https"})
      assert r.headers["Strict-Transport-Security"] == \
          "max-age=31536000; includeSubDomains"

  def test_api_no_store(_app):
      client = _app.test_client()
      r = client.post("/api/v1/auth/local",
                      json={"email": "admin@local", "password": "correct-horse"})
      assert r.headers["Cache-Control"] == "no-store"
      assert r.headers["Pragma"] == "no-cache"
      assert r.headers["Expires"] == "0"

  def test_static_caching_preserved(_app):
      # ADR-0006: assets stay immutable, index stays no-cache.
      # The test app's static dir is a fake dist (see api conftest's KUBEDASH_STATIC_DIR
      # override) — use whatever path that fixture serves, or a rootfile like /favicon.ico.
      client = _app.test_client()
      r = client.get("/favicon.ico")
      assert r.status_code == 200
      assert r.headers["Cache-Control"] == "immutable, max-age=31536000"
  ```

  (Adjust the static assertion to the real fake-dist path the api conftest wires —
  read `backend/tests/api/conftest.py` for the `KUBEDASH_STATIC_DIR` value before
  writing the assertion. The invariant is: the no-store hook does not touch
  `/assets/*`, `/favicon.ico`, or the SPA index.)

- [ ] **Step 2: Run, confirm RED** — `.venv/bin/python -m pytest tests/test_security_headers.py -q`
  from `backend/`. Expected: FAIL (no `X-Frame-Options` header / no `Content-Security-Policy`).

- [ ] **Step 3: Implement** — `backend/app/core/security_headers.py`:

  ```python
  """Security header layer (ADR-0026) — the 4.1 initializer's 5.0 descendant.

  4.1 set these in `src/kubedash/lib/initializers/security.py`; the rebase
  dropped the whole layer. Restored here as plain Flask hooks (no Talisman —
  4.1 disabled Talisman's CSP anyway and hand-rolled the nonce; one less
  dependency to keep honest under the air-gap, ADR-0020).

  WHY the nonce is per-request in `g`: a single startup-time nonce would make
  every page's CSP identical — fine in itself, but a response cached (by a
  proxy, or by a future mis-scoped Cache-Control) would carry a nonce that is
  stale for its siblings. Per-request is what 4.1 did; keep it.
  """
  import re
  import secrets

  from flask import Flask, g, request, response  # noqa: F401 (response re-exported for tests)

  _NONCE_RE = re.compile(r"nonce-([A-Za-z0-9_-]+)")

  def register_security_headers(app: Flask) -> None:
      @app.before_request
      def _csp_nonce() -> None:
          g.csp_nonce = secrets.token_urlsafe(16)

      @app.after_request
      def _headers(resp):
          resp.headers["X-Frame-Options"] = "DENY"
          resp.headers["X-Content-Type-Options"] = "nosniff"
          resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
          resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
          resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
          resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
          # HSTS only when the request arrived over TLS (request.is_secure is
          # ProxyFix-corrected when KUBEDASH_TLS_EDGE=true). Plain-HTTP must
          # NOT carry it — the header is a promise about future requests.
          if request.is_secure:
              resp.headers["Strict-Transport-Security"] = \
                  "max-age=31536000; includeSubDomains"
          nonce = getattr(g, "csp_nonce", "")
          csp = (
              "default-src 'self'; "
              "font-src 'self'; "
              "style-src 'self' 'unsafe-inline'; "
              f"script-src 'self' 'nonce-{nonce}'; "
              "connect-src 'self' wss: ws:; "
              "img-src 'self' data:"
          )
          resp.headers["Content-Security-Policy"] = csp
          # ADR-0006: static caching is set per-route in register_static and
          # MUST win. Setting no-store here would clobber `immutable` on
          # /assets/* — so scope it to the API surface only. (4.1 set it
          # globally; that was the bug.)
          if request.path.startswith("/api/"):
              resp.headers["Cache-Control"] = "no-store"
              resp.headers["Pragma"] = "no-cache"
              resp.headers["Expires"] = "0"
          return resp
  ```

  Register in `create_app` (`backend/app/__init__.py`), AFTER `register_errors(app)`
  (line ~100) so smorest error responses get the headers, BEFORE `apidocs.register_asset_routes(app)`:

  ```python
  from app.core.security_headers import register_security_headers
  register_security_headers(app)
  ```

  Add to `Settings` in `backend/app/core/config.py` (near `cookie_secure`):

  ```python
  # ADR-0026: true when the app runs behind the TLS edge (nginx, dev stack) or
  # any TLS-terminating proxy. Gates ProxyFix (wsgi.py) and the HSTS emission
  # (security_headers.py reads request.is_secure, which ProxyFix makes honest).
  # Default False = today's plain-HTTP behavior; the test client is unaffected.
  tls_edge: bool = False
  ```

- [ ] **Step 4: Run, confirm GREEN** — the focused file, then the full unit
  suite: `.venv/bin/python -m pytest tests/test_security_headers.py -q` and
  `.venv/bin/python -m pytest -m "not integration" -q` from `backend/`.
  (350 tests passed as of 2026-10-24 — no regressions allowed.)

- [ ] **Step 5: Commit** — `git add backend/app/core/security_headers.py backend/app/__init__.py backend/app/core/config.py backend/tests/test_security_headers.py`
  `git commit -m "feat(security): restore 4.1 header layer (CSP nonce, HSTS, COOP/CORE, no-store on /api/*)"`

### Task 2: ProxyFix behind the edge

**SATISFIES:** `proxyfix-applied-behind-edge`, `proxyfix-inactive-without-edge`

**Files:**
- Modify: `backend/wsgi.py` (module level, after `app = create_app(...)`)
- Test: `backend/tests/test_proxyfix.py` (new)

**Interfaces:**
- Consumes: `settings.tls_edge` (Task 1).
- Produces: none (behavior only).
- Seam: none (in-process WSGI middleware).
- Deletion test: deleting the wrap leaves `request.is_secure` false behind the
  edge — HSTS would never emit and the app would log plain-HTTP URLs.
- Adapters: 1 (in-process).

- [ ] **Step 1: Write the failing tests** — `backend/tests/test_proxyfix.py`.

  The ProxyFix decision lives in `wsgi.py`, which imports the whole app (gunicorn
  entrypoint) — importing it in a test would start the Leader/RQ worker for
  `KUBEDASH_ROLE=leader`. Keep the gate in a tiny testable function on `wsgi`:

  ```python
  # wsgi.py — near the top, before `app = create_app(...)`:
  def _apply_proxyfix(app: Flask) -> None:
      """ADR-0026: trust the TLS edge's X-Forwarded-* when (and only when)
      we run behind it. WHY env-gated: the test client and the plain-HTTP
      dev fast path send no forwarded headers; unconditional ProxyFix would
      make a spoofed X-Forwarded-Proto flip request.is_secure (and with it,
      HSTS emission and the Secure-cookie semantics)."""
      from app.core.config import get_settings
      if not get_settings().tls_edge:
          return
      from werkzeug.middleware.proxy_fix import ProxyFix
      app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
  ```

  Test (construct a bare Flask app via `create_app` with the sqlite pattern,
  or — cheaper — a minimal `Flask()` with one route):

  ```python
  import pytest
  from flask import Flask, jsonify, request

  @pytest.fixture()
  def probe_app(monkeypatch):
      import app.core.config as cfg
      monkeypatch.delenv("KUBEDASH_TLS_EDGE", raising=False)
      cfg._settings = None
      app = Flask(__name__)

      @app.get("/probe")
      def probe():
          return jsonify(secure=request.is_secure)

      from wsgi import _apply_proxyfix  # noqa: wsgi import must not start Leader
      _apply_proxyfix(app)
      return app

  def test_proxyfix_applied_when_edge(probe_app, monkeypatch):
      import app.core.config as cfg
      monkeypatch.setenv("KUBEDASH_TLS_EDGE", "true")
      cfg._settings = None
      # Re-apply with the env now set (the fixture applied it with it unset).
      from wsgi import _apply_proxyfix
      # The gate reads Settings at call time, so a fresh call picks it up.
      # (If the implementation memoizes, that is a test bug — fix the impl.)
      app = probe_app
      _apply_proxyfix(app)
      assert app.test_client().get("/probe", headers={"X-Forwarded-Proto": "https"}).get_json()["secure"] is True
      assert app.test_client().get("/probe").get_json()["secure"] is False

  def test_proxyfix_inactive_without_edge(probe_app):
      assert probe_app.test_client().get(
          "/probe", headers={"X-Forwarded-Proto": "https"}
      ).get_json()["secure"] is False
  ```

  (If re-applying ProxyFix on an already-wrapped `wsgi_app` double-wraps, the
  fixture should build the app AFTER the env is set — restructure the fixture
  to take an `edge: bool` arg. The invariant under test is: gate reads
  Settings at call time, and the wrapped app honors X-Forwarded-Proto.)

  > **Watch the wsgi import side effects:** `import wsgi` executes
  > `_start_worker_if_leader()` — it is a no-op unless `KUBEDASH_ROLE=leader`
  > (default `worker`), so it is safe in tests. If it is NOT safe (the RQ import
  > path), extract `_apply_proxyfix` into `app/core/proxyfix.py` instead —
  > that is the fallback, record it in the commit.

- [ ] **Step 2: Run, confirm RED** — `.venv/bin/python -m pytest tests/test_proxyfix.py -q`.
- [ ] **Step 3: Implement** — the `_apply_proxyfix` above + call it in `wsgi.py`
  after `app = create_app(...)`:

  ```python
  _apply_proxyfix(app)
  ```

  (before `_bootstrap_local_admin(app)`; order vs the bootstrap is
  immaterial — record the chosen order in the comment.)

- [ ] **Step 4: Run, confirm GREEN** — focused file + full unit suite.
- [ ] **Step 5: Commit** — `git commit -m "feat(security): ProxyFix gated on KUBEDASH_TLS_EDGE (ADR-0026)"`

### Task 3: TLS certs + nginx edge (dev stack)

**Precondition:** `mkcert` on PATH (verified installed 2026-10-24) and the mkcert
rootCA trusted in the host keychain (verified: `security find-certificate -a -c mkcert`
returns entries in login + System keychain). If either check fails, STOP — the
backstop scenario cannot verify a chain a browser would reject.

**SATISFIES:** `tls-edge-serves-https-and-redirects-http` (the unit-testable half:
nginx config + cert presence; the browser half is Task 5's backstop)

**Files:**
- Create: `dev/setup-tls.sh`
- Create: `dev/nginx/kubedash.conf`
- Modify: `dev/docker-compose.yml` (add `nginx` service)
- Create: `dev/.gitignore`
- Test: shell — `dev/setup-tls.sh verify` (openssl chain + curl)

**Interfaces:**
- Consumes: `mkcert`, `openssl`, the compose stack (postgres/redis/etc. running).
- Produces: `dev/certs/kubedash.local.pem` (+key), `dev/certs/backend.pem` (+key),
  `dev/certs/rootCA.pem` — the paths nginx and wsgi read (see Task 4).
- Seam: `dev/certs/` (generated, gitignored) — the CA is host state, the leaf
  certs are reproducible from `setup-tls.sh`.
- Deletion test: deleting the certs + service reverts the dev stack to today's
  plain-HTTP behavior exactly.
- Adapters: 2 (the mkcert CA for the browser leg, the same CA for the internal leg).

- [ ] **Step 1: Write `dev/setup-tls.sh`** (idempotent; `generate` | `verify` | `hosts`):

  ```bash
  #!/usr/bin/env bash
  # ADR-0026: local TLS for the dev stack. Idempotent: safe to re-run.
  #   generate  leaf certs for kubedash.local (browser leg) + kubedash-backend
  #             (internal leg, nginx -> backend), signed by the mkcert rootCA
  #   verify    openssl chain check + curl check (needs the edge up)
  #   hosts     append 127.0.0.1 kubedash.local to /etc/hosts (needs sudo)
  set -euo pipefail
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  CERTS="$ROOT/dev/certs"

  case "${1:-}" in
    generate)
      mkdir -p "$CERTS"
      cp "$(mkcert -CAROOT)/rootCA.pem" "$CERTS/rootCA.pem"
      [ -f "$CERTS/kubedash.local.pem" ] || mkcert -cert-file "$CERTS/kubedash.local.pem" \
        -key-file "$CERTS/kubedash.local-key.pem" kubedash.local 127.0.0.1 localhost
      # Internal leg: a leaf for the backend. Subject is the backend's
      # internal name; nginx verifies it against rootCA.pem (not the browser
      # trust store), so SAN = kubedash-backend suffices.
      [ -f "$CERTS/backend.pem" ] || mkcert -cert-file "$CERTS/backend.pem" \
        -key-file "$CERTS/backend-key.pem" kubedash-backend
      echo "certs in $CERTS (gitignored)"
      ;;
    verify)
      openssl verify -CAfile "$CERTS/rootCA.pem" "$CERTS/kubedash.local.pem"
      openssl verify -CAfile "$CERTS/rootCA.pem" "$CERTS/backend.pem"
      # The browser-leg proof (needs the edge up + hosts entry):
      curl -sSfI https://kubedash.local:443/healthz | head -3
      ;;
    hosts)
      grep -qE '^\s*127\.0\.0\.1\s+kubedash\.local' /etc/hosts \
        || echo "127.0.0.1 kubedash.local" | sudo tee -a /etc/hosts
      ;;
    *) echo "usage: setup-tls.sh generate|verify|hosts" >&2; exit 2 ;;
  esac
  ```

  **Step 1a: run it** — `bash dev/setup-tls.sh generate` and
  `bash dev/setup-tls.sh hosts`. Confirm: both `openssl verify` lines print
  `OK`, and `curl -vI https://127.0.0.1/ --resolve kubedash.local:443:127.0.0.1`
  would verify (edge not up yet — the full curl runs in Task 5).

- [ ] **Step 2: Write `dev/nginx/kubedash.conf`** — the 4.1 conf, fixed and adapted
  (single upstream, TLS 1.2/1.3 only, deduped XFF, verify ON with the rootCA):

  ```nginx
  # ADR-0026: TLS edge for the dev stack. Terminates browser TLS; proxies to
  # the backend OVER HTTPS (internal leg) so KUBEDASH_COOKIE_SECURE=true is
  # honest on both hops. 4.1's conf used proxy_ssl_verify off — we verify
  # against the mkcert rootCA instead.
  server {
      listen 80;
      listen [::]:80;
      server_name kubedash.local;
      return 301 https://$host:443$request_uri;
  }

  # ONE upstream (ADR-0008): leader election is Postgres-advisory-lock based,
  # any replica serves any request — nginx does no balancing. 4.1's
  # 3-server upstream predates the rebase's election model.
  upstream kubedash_backend {
      server host-gateway:8443;
  }

  server {
      listen 443 ssl;
      listen [::]:443 ssl;
      server_name kubedash.local;

      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_certificate     /etc/nginx/certs/kubedash.local.pem;
      ssl_certificate_key /etc/nginx/certs/kubedash.local-key.pem;

      # Internal leg: verified, not off — the whole point of the internal
      # HTTPS is a chain the edge can check.
      proxy_ssl_verify on;
      proxy_ssl_trusted_certificate /etc/nginx/certs/rootCA.pem;
      proxy_ssl_name kubedash-backend;
      proxy_ssl_server_name on;

      location / {
          proxy_pass          https://kubedash_backend;
          proxy_http_version  1.1;
          proxy_set_header    Host              $host;
          proxy_set_header    X-Real-IP         $remote_addr;
          proxy_set_header    X-Forwarded-For   $proxy_add_x_forwarded_for;
          proxy_set_header    X-Forwarded-Proto https;
          # Exec channel (ADR-0009) needs the upgrade headers — carried over
          # from 4.1's conf.
          proxy_set_header    Upgrade           $http_upgrade;
          proxy_set_header    Connection        "upgrade";
          proxy_set_header    X-Request-ID      $request_id;
          proxy_cache_bypass  $http_upgrade;
          proxy_read_timeout  3600s;
      }
  }
  ```

- [ ] **Step 3: Add the `nginx` service to `dev/docker-compose.yml`**:

  ```yaml
  nginx:
    image: nginx:1.27
    restart: unless-stopped
    ports:
      - "${KUBEDASH_HTTP_PORT:-8080-0}..."  # NO — see below
  ```

  **Exact service (write this verbatim):**

  ```yaml
  nginx:
    image: nginx:1.27
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/kubedash.conf:/etc/nginx/conf.d/kubedash.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - postgres
      - redis
    # The edge healthchecks /healthz with the mkcert CA. --insecure is the
    # HOSTNAME-mismatch escape hatch (the cert is for kubedash.local, the
    # healthcheck dials localhost) — the CHAIN is still verified, which is
    # the half that matters for the healthcheck.
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- --cacert=/etc/nginx/certs/rootCA.pem --insecure https://localhost:443/healthz || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
  ```

  > **Port 80/443 conflict:** if another local service already binds :80 or
  > :443 (check `lsof -i :80 -i :443`), the compose `ports:` must move to
  > `${KUBEDASH_EDGE_HTTP:-80}:80` / `${KUBEDASH_EDGE_HTTPS:-443}:443` and the
  > Taskfile e2e base URL follows. Verify the ports are free BEFORE `up` —
  > the backstop scenario names `:443` explicitly.

- [ ] **Step 4: `dev/.gitignore`** — `certs/` (the CA is host state; the leaves
  are reproducible).
- [ ] **Step 5: Verify** — `docker compose -f dev/docker-compose.yml up -d nginx`,
  then `bash dev/setup-tls.sh verify` (the curl line now works: the edge is up).
  Fails-when: `curl` exits non-zero or the openssl line does not print `OK`.
- [ ] **Step 6: Commit** — `git add dev/` `git commit -m "feat(dev): nginx TLS edge + mkcert certs for the dev stack (ADR-0026)"`

### Task 4: Backend TLS listener

**SATISFIES:** `tls-edge-serves-https-and-redirects-http` (the backend half:
`:8443` answers the edge)

**Files:**
- Modify: `backend/wsgi.py` (TLS listener)
- Modify: `Taskfile.yaml` (backend-stack-run env) — ONLY the cert env, the
  cookie flag flips in Task 5
- Test: runtime — `curl -s --cacert dev/certs/rootCA.pem https://127.0.0.1:8443/healthz`

**Interfaces:**
- Consumes: `dev/certs/backend*.pem` (Task 3), `KUBEDASH_SSL_CERT`/`KUBEDASH_SSL_KEY` env.
- Produces: `:8443` TLS listener (the nginx upstream target).
- Seam: env-gated (`KUBEDASH_SSL_CERT` unset = plain `:8080` exactly as today —
  `multi-up`, `backend-run`, and the test client are untouched).
- Deletion test: deleting the gate reverts `wsgi.py` to a single plain listener.
- Adapters: 1 (env-gated; no port).

- [ ] **Step 1: Implement in `wsgi.py`** (the `__main__` block, replacing the
  bare `app.run`):

  ```python
  if __name__ == "__main__":
      import os

      cert = os.environ.get("KUBEDASH_SSL_CERT")
      ssl_context = (
          (cert, os.environ["KUBEDASH_SSL_KEY"])
          if cert
          else None
      )
      # :8080 plain is ALWAYS up (dev fast path, multi-up, test client);
      # :8443 appears only with the certs — the nginx edge (ADR-0026) is the
      # one consumer. app.run serves one port, so the TLS listener is the
      # `__main__` port and the plain one stays for the gunicorn/container
      # path (backend/Dockerfile binds :8080; the container leg is plain
      # behind the in-cluster ingress, which terminates TLS — ADR-0019).
      port = int(os.environ.get("FLASK_RUN_PORT", "8080"))
      app.run(port=port, ssl_context=ssl_context)
  ```

  > **Decision (recorded):** the `__main__` dev backend serves ONE port. With
  > `KUBEDASH_SSL_CERT` set, that port is 8443-over-TLS and plain :8080 is
  > not served by the dev backend (the nginx edge IS the browser surface).
  > `task dev-up` without the edge keeps plain :8080. If both ports are ever
  > needed simultaneously, that is a gunicorn-arg change, not a wsgi change —
  > out of scope here.

- [ ] **Step 2: Verify** — with the edge stack up (Task 3), start the backend
  via `task dev-stack` (Task 5 wires the env; for this task start manually):

  ```bash
  cd backend && KUBEDASH_SSL_CERT=../dev/certs/backend.pem \
    KUBEDASH_SSL_KEY=../dev/certs/backend-key.pem \
    KUBEDASH_TLS_EDGE=true KUBEDASH_ROLE=leader KUBEDASH_REPLICA_ID=local \
    FLASK_RUN_PORT=8443 .venv/bin/python wsgi.py
  ```

  Then: `curl -s --cacert dev/certs/rootCA.pem https://127.0.0.1:8443/healthz`
  → `{"status": "ok"}`. Fails-when: curl's exit != 0 (cert chain or listener).
  Then end-to-end through the edge: `curl -sI https://kubedash.local/healthz`
  (needs the hosts entry from Task 3) → 200 + the R3 headers present
  (Task 1's layer now visible at the browser surface).

- [ ] **Step 3: Commit** — `git commit -m "feat(dev): backend TLS listener on :8443 (env-gated, ADR-0026)"`

### Task 5: Stack wiring + e2e backstop

**SATISFIES:** `secure-cookies-flow-end-to-end` (backstop), `tls-edge-serves-https-and-redirects-http`
(browser half)

**Files:**
- Modify: `Taskfile.yaml` (new tasks `dev-tls-setup`, `dev-up-ssl`, `e2e-ssl`;
  `dev-stack` becomes edge-aware; `backend-stack-run` env)
- Modify: `frontend/playwright.config.ts` (E2E_TLS_CA)
- Test: `task e2e-ssl` green

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: the `task dev-stack` command now means "the secure dev stack" —
  the R5 deliverable.
- Seam: the Taskfile vars block (all paths/env centralized).
- Deletion test: reverting the Taskfile reverts to today's plain-HTTP dev-stack
  exactly (the carve-out R5 names).
- Adapters: 1.

- [ ] **Step 1: Taskfile changes.**

  New vars (near `COMPOSE`):

  ```yaml
  EDGE_HTTPS: "443"
  TLS_CA: "{{.TASKFILE_DIR}}/dev/certs/rootCA.pem"
  ```

  New tasks:

  ```yaml
  dev-tls-setup:
    desc: "Generate/verify dev TLS certs + hosts entry (ADR-0026, idempotent; hosts step needs sudo)"
    cmds:
      - "bash {{.TASKFILE_DIR}}/dev/setup-tls.sh generate"
      - "bash {{.TASKFILE_DIR}}/dev/setup-tls.sh hosts"

  dev-up-ssl:
    desc: "Start the dev stack INCLUDING the nginx TLS edge (https://kubedash.local:443)"
    cmds:
      - "{{.COMPOSE}} up -d"   # the nginx service is part of the same compose file

  e2e-ssl:
    desc: "Run the Playwright auth-smoke e2e against https://kubedash.local:443 (ADR-0026 backstop)"
    dir: frontend
    env:
      E2E_BASE_URL: "https://kubedash.local:443"
      E2E_TLS_CA: "{{.TLS_CA}}"
    cmds:
      - "corepack pnpm exec playwright test e2e/auth-smoke.spec.ts"
  ```

  `backend-stack-run` env block — flip the two flags (the WHY comment per
  AGENTS.md):

  ```yaml
  # ADR-0026: the dev stack now runs behind the TLS edge — the Secure cookie
  # is honest end-to-end (browser leg HTTPS, internal leg HTTPS via :8443).
  # The plain-HTTP carve-out is `task dev-up` + direct :8080 (fe-dev's proxy
  # target), which keeps KUBEDASH_COOKIE_SECURE=false.
  KUBEDASH_COOKIE_SECURE: "true"
  KUBEDASH_TLS_EDGE: "true"
  KUBEDASH_SSL_CERT: "{{.TASKFILE_DIR}}/dev/certs/backend.pem"
  KUBEDASH_SSL_KEY: "{{.TASKFILE_DIR}}/dev/certs/backend-key.pem"
  FLASK_RUN_PORT: "8443"
  ```

  `dev-stack` cmds — add, as the FIRST step, a precondition:

  ```yaml
  - "test -f {{.TLS_CA}} || (echo 'run task dev-tls-setup first (dev/certs missing)' && exit 1)"
  ```

  (The certs are a *read* precondition — `task dev-stack` fails fast with the
  named fix instead of starting a backend that cannot serve TLS.)

  **R5 carve-out:** `task dev-up` (plain compose, no nginx) + a manual
  `backend-run` keeps today's env (`KUBEDASH_COOKIE_SECURE=false`, no TLS).
  Document it in the `dev-up` desc: `"Start the dev environment (plain-HTTP fast path; add the TLS edge with dev-up-ssl)"`.

- [ ] **Step 2: Playwright CA injection** — `frontend/playwright.config.ts`:

  ```ts
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    ...(process.env.E2E_TLS_CA ? {
      // ADR-0026: verify the mkcert chain instead of ignoring TLS errors —
      // the backstop IS the chain.
      launchOptions: {
        args: [`--ignore-certificate-errors=false`,
               `--trust-store-path=${process.env.E2E_TLS_CA}`],  // verify flag name first
      },
    } : {}),
  },
  ```

  > **Verify the flag before committing:** Chromium's trust mechanism for
  > Playwright is `--ignore-certificate-errors` (the escape hatch we do NOT
  > want) vs the `NODE_EXTRA_CA_CERTS` env (Node-side, not the browser) vs
  > launching with a custom `--user-data-dir` + `security add-trusted-cert`
  > state. The mkcert rootCA is ALREADY in the host keychain (Task 3
  > precondition), so Chromium launched by Playwright inherits it WITHOUT any
  > flag — in which case `E2E_TLS_CA` is only needed for the Node-side
  > (non-browser) clients, and this whole block collapses to the baseURL
  > change. Prove which case applies by running the e2e BEFORE adding flags.
  > Fails-when: `playwright test` fails with a cert error on
  > `https://kubedash.local:443`.

  **Also:** `auth-smoke.spec.ts` step 3 polls `localStorage.getItem('kd_token')`
  (lines 84-88, 120) — ADR-0025 already removed `kd_token` from localStorage,
  so those assertions are STALE (verified: `frontend/src/lib/api.ts` no longer
  touches localStorage). Fix them as part of this task: replace the
  `kd_token` poll with the `kd_session` hint cookie
  (`document.cookie.includes('kd_session')`) — it is the scenario's
  observable — and note it in the commit. This is a prerequisite for a
  green e2e, on any branch.

- [ ] **Step 3: Run the backstop** — `task dev-stack` (new terminal), then
  `task e2e-ssl`. Fails-when: any of the three auth-smoke tests fails, OR the
  `kd_access` cookie lacks the `Secure` attribute (assert it in the spec: add
  `const cookies = await page.context().cookies(); expect(cookies.find(c => c.name === 'kd_access')?.secure).toBe(true)`).
  Then `bash dev/setup-tls.sh verify` (the full curl line).

- [ ] **Step 4: Commit** — `git commit -m "feat(dev): dev-stack runs behind the TLS edge with Secure cookies (ADR-0026)"`

### Task 6: Spec zone close-out

**Files:**
- Modify: `.skillgrid/ASSUMPTIONS.md` (LOCKED index row for ADR-0026)
- Create: `.backlog/decisions/decision-026` (the ADR copy, per config
  `ticketing.decisions_dir`)
- Modify: `.skillgrid/state.yaml` (pointer to this change, phase: executing)

**Steps:**
- [ ] Add the LOCKED row (mirroring ADR-0025's row shape):
  `| ADR-0026 | TLS edge + security header layer (nginx edge with internal HTTPS; ProxyFix gated on KUBEDASH_TLS_EDGE; 4.1 header set restored with two recorded deviations) | yes | artifacts/04-adr-0026-tls-edge-and-security-headers.md |`
- [ ] Copy the ADR to `.backlog/decisions/decision-026`.
- [ ] Update `state.yaml` pointer.
- [ ] **Commit the spec zone FIRST if any of it landed after the code commits**
  (the zone guard blocks mixed commits).

## Verification

- `cd backend && .venv/bin/python -m pytest -m "not integration" -q` — green (350+ baseline).
- `cd backend && .venv/bin/python -m pytest tests/test_security_headers.py tests/test_proxyfix.py -q` — focused.
- `task fe-build` — typecheck + lint + build (the Playwright config change).
- `task fe-check` — air-gap bundle (the CSP change must not have added any source).
- `task dev-stack` + `task e2e-ssl` — the runtime backstop (R1/R2/R5).
- `bash dev/setup-tls.sh verify` — chain proof.
- Manual: browser → `https://kubedash.local:443` → lock icon shows a VERIFIED
  chain (not an exception) → login → DevTools: `kd_access` Secure+HttpOnly,
  HSTS header present, CSP with a fresh nonce per request.

## Self-Review (ran 2026-10-24)

- Spec coverage: R1→Task 3+5, R2→Task 2, R3→Task 1, R4→Task 1, R5→Task 5,
  R6→ADR + Task 6. No gaps.
- Must-haves cover every requirement; the two runtime truths are tagged
  `backstop` with the e2e as the held-out test.
- One-way doors: none (verified — no migration, no API break, no dependency).
- Placeholder scan: the Playwright CA block (Task 5 Step 2) carries an
  explicit "prove which case applies before adding flags" instruction —
  a named decision point, not a TBD; the static-path assertion in Task 1
  names the file to read for the exact value.
- Type consistency: `register_security_headers(app)`, `_apply_proxyfix(app)`,
  `tls_edge` — used identically across Tasks 1-5.
