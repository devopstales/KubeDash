# Swagger UI Air-Gap — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-execution (recommended) or simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2

**Change classification:** `small` — ≤10 files, single concern (offline-serve
the existing Swagger UI + one top-level security scheme). Verification floor L1
(focused tests) + a full backend-suite run at the end (it is the repo's standard
gate per `AGENTS.md`).

**Build shape:** Smallest usable whole — the first task delivers a fully
functional, offline `/api/docs` (the smallest thing an operator could actually
open), and the second task adds the spec's security scheme. Chosen because the
integration risk lives entirely in "does the app-served asset + template
override actually render" — proving that end-to-end first kills the whole
hypothesis before we add anything else.

**Goal:** Make `/api/docs` fully functional in an air gap — serve the Swagger
UI's CSS/JS from the app (no CDN, always) and declare a `BearerAuth` JWT
security scheme on the spec, with the page staying open for browsing.

**Architecture:** Add `swagger-ui-dist` as a backend runtime dependency. A small
module (`app/core/apidocs.py`) serves the package's `swagger-ui.css` /
`swagger-ui-standalone-preset.js` / `swagger-ui-bundle.js` on three Flask routes
under the existing `/api/docs` prefix (read via `importlib.resources`) and
registers the `BearerAuth` security scheme on the smorest spec at init. The
app's own `templates/swagger_ui.html` overrides smorest's packaged template so
the page's asset `src`/`href` point at those app routes instead of the CDN. The
factory's `OPENAPI_SWAGGER_UI_URL` CDN value becomes a local placeholder (the
key stays — smorest only registers the page when it is set). Nothing leaves the
app origin.

**Tech Stack:** Python 3.12, `uv`, `flask-smorest` (0.47, already present),
`swagger-ui-dist` (new runtime dep), `importlib.resources` (stdlib), Flask test
client + `pytest` (already present).

**Spec:** `.skillgrid/specs/2026-10-17-swagger-ui-air-gap/briefing.md`
(requirements R1–R4). Constrained by **ADR-0020** (air-gap, zero outbound calls
at runtime — the driving decision) and **ADR-0006** (single container — assets
ride in the Python image).

## Terms

- **Air-gap (air-gap deployment)** — network-isolated, zero outbound calls at
  runtime; ADR-0020. See `briefing.md` § Terms.
- **Swagger UI asset source** — where `/api/docs` loads its CSS/JS from;
  resolved here to "always app-served from the vendored `swagger-ui-dist`
  package." See `briefing.md` § Terms.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- T1: `GET /api/docs` returns 200 and its HTML contains
  `/api/docs/swagger-ui.css`, `/api/docs/swagger-ui-standalone-preset.js`, and
  `/api/docs/swagger-ui-bundle.js` — and contains **no** `cdn.jsdelivr.net` and
  no other `http(s)://` asset URL *(backstop — assert on the rendered page, not
  a diff read)*
- T2: `GET /api/docs/swagger-ui.css` → 200, `Content-Type` starts with
  `text/css`, non-empty body; `GET /api/docs/swagger-ui-standalone-preset.js`
  and `GET /api/docs/swagger-ui-bundle.js` → 200, `Content-Type` is
  `application/javascript`, non-empty body
- T3: the body served by `GET /api/docs/swagger-ui-bundle.js` is
  **byte-identical** to the file read from the `swagger-ui-dist` package via
  `importlib.resources` — proving the route serves the vendored file, not a
  stale in-repo copy or a transform/encoding bug. (It does **not** by itself
  prove "not a CDN fetch" — that is proven by T1's no-external-URL page assert.
  Two in-process reads of the same package are compared; the CDN claim rests on
  T1.)
- T3b: the `swagger-ui-dist` package's `swagger-ui-bundle.js` is present and
  resolvable via `importlib.resources.files("swagger_ui_dist").joinpath(
  "swagger-ui-bundle.js").is_file()` in the synced venv — proving the runtime
  venv actually ships the data files (this is what T8 relies on at image-build
  time)
- T4: `GET /api/openapi.json` returns 200 and
  `components.securitySchemes.BearerAuth == {"type": "http", "scheme": "bearer",
  "bearerFormat": "JWT"}`
- T5: `GET /api/docs` returns 200 with **no** `Authorization` header (page is
  open/browsable; the scheme is documented, not enforced on the page)
- T6: the two pre-existing doc tests (`test_openapi_json_is_valid_openapi3`,
  `test_openapi_routes_registered_without_deps`) pass unchanged:
  `/api/openapi.json` → `api-docs.openapi_json`, `/api/docs` →
  `api-docs.openapi_swagger_ui`, and the spec is still valid OpenAPI 3
- T7: calling `apidocs.register_security_scheme(api)` **twice on the same
  already-built spec** does **not** raise `DuplicateComponentNameError` (the
  guard is tested directly by double-invocation — NOT by building a second
  app, which rebuilds `api.spec` fresh per `init_app` and would pass trivially)
- T8: `importlib.resources.files("swagger_ui_dist")` resolves the three asset
  files in the **runtime** venv (T3b proves it in the dev venv; the Dockerfile
  `uv sync --frozen --no-dev` stage installs main deps, so the image venv is
  the same set) — no new `COPY` step. *(backstop for the actual image build —
  needs a network/container to build; T3b is the in-venv proxy.)*
- T9: the set of `spec["paths"]` keys after the change **contains** the set
  before (no previously documented operation vanished) — R4's "paths superset"
  is asserted by a golden test, not just by re-running the old tests

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/pyproject.toml` — *modify*: add `swagger-ui-dist` to `dependencies`
- `backend/uv.lock` — *regenerate*: `uv lock` records `swagger-ui-dist`
- `backend/app/core/apidocs.py` — *new*: the asset-serving routes + the
  idempotent `BearerAuth` security-scheme registration
- `backend/app/templates/swagger_ui.html` — *new*: the smorest template override
  pointing asset `src`/`href` at the app routes
- `backend/app/__init__.py` — *modify*: set `OPENAPI_SWAGGER_UI_URL` to a local
  placeholder (not deleted); add `template_folder="templates"`; wire `apidocs`
  (asset routes + security scheme) into the factory
- `backend/tests/api/test_apidocs.py` — *new*: T1–T5, T7, T9 tests (lives in
  `tests/api/` so it uses the **docker-free** `client` fixture from
  `tests/api/conftest.py` — the root `tests/conftest.py` `client` is
  Testcontainers-based and errors without a container runtime)
- `backend/tests/api/apidocs_paths_baseline.json` — *new*: the golden set of
  `spec["paths"]` keys captured before the change, asserted as a subset by T9

**Key links** (critical connections between artifacts that must work together):
- The `templates/swagger_ui.html` override's asset URLs **must** exactly match
  the routes registered by `app/core/apidocs.py` (`/api/docs/swagger-ui.css`,
  `/api/docs/swagger-ui-standalone-preset.js`, `/api/docs/swagger-ui-bundle.js`)
  — a mismatch is a 404 asset and a blank UI (T1/T2 catch it).
- `app/__init__.py` must call the security-scheme registration **after**
  `api.init_app(app)` (so `api.spec` exists) and the asset routes must be
  registered under the **same `/api` prefix** as the smorest `api-docs`
  blueprint so they land at `/api/docs/*` (not shadowed by the SPA catch-all).
- The asset routes must be registered **before** `register_static(app)` (the
  SPA catch-all `@app.get("/<path:path_>")`) so `/api/docs/*` is matched by the
  asset handler, not the SPA route — the SPA route already 404s `.js`/`.css`,
  which is correct, but only if the asset rules are seen first.

**One-way-door decisions** (hard to reverse — flag for explicit user approval):
- None. Adding a dependency, a module, a template, and a top-level spec scheme
  are all additive and trivially revertible (delete the files / drop the
  `dependencies` line). Removing `OPENAPI_SWAGGER_UI_URL` is a one-line delete,
  not a contract break.

## Global Constraints

- Python 3.12; `uv` manages deps and the lockfile (`uv sync --frozen` is the
  Dockerfile's install command, so `uv.lock` must be committed and consistent).
- `ruff` (line-length 100, `select = E,F,I,UP,B,SIM`, target `py312`) +
  `mypy --strict` must pass on the new/changed Python files.
- Conventional Commits (`feat:`, `chore:`…); the pre-commit zone guard blocks
  a commit that mixes blueprint/spec changes with code — spec-zone artifacts
  commit separately from the code change.
- `swagger-ui-dist` is a **runtime** dependency (served in the image), so it
  goes in the main `dependencies` list, **not** the `dev` dependency-group.
- Do **not** add a ReDoc/RapiDoc rule or a `KUBEDASH_SWAGGER_CDN` toggle —
  out of scope per the briefing.
- `OPENAPI_SWAGGER_UI_URL` is **not deleted** — it is set to a local
  placeholder (`/api/docs/`) because smorest 0.47 only registers the `/api/docs`
  route when that key is not None. The CDN value is what is removed; the key
  stays (the app template ignores it). Do not "clean it up" by deleting the
  key — that unregisters the page.

## File Structure

- `backend/pyproject.toml` — add `swagger-ui-dist` to `dependencies`.
- `backend/uv.lock` — regenerated by `uv lock`.
- `backend/app/core/apidocs.py` — new module: three asset view functions that
  read a named file from the `swagger-ui-dist` package via
  `importlib.resources`, a helper that registers them on a blueprint/prefix, and
  `register_security_scheme(api)` that idempotently adds `BearerAuth`. One
  responsibility: make the Swagger UI self-served + documented.
- `backend/app/templates/swagger_ui.html` — new: the smorest template override
  (asset `src`/`href` → app routes, `spec_url` → `openapi.json`).
- `backend/app/__init__.py` — set `OPENAPI_SWAGGER_UI_URL` to a local
  placeholder (not deleted); add `template_folder="templates"`; import + call
  `apidocs` registration in the factory (asset routes + security scheme), with
  the asset routes registered before `register_static(app)`.
- `backend/tests/api/test_apidocs.py` — new: the T1–T5 + T7 + T9 tests
  (in `tests/api/` → docker-free `client` fixture).
- `backend/tests/api/apidocs_paths_baseline.json` — new: golden `spec["paths"]`
  baseline for T9's superset assert.

---

### Task 1: Serve the Swagger UI assets locally (always)

> **Door check (tests the hypothesis):** this task is the thinnest slice that
> proves "the app-served assets + template override render a working `/api/docs`
> with no CDN." If the page does not render offline after this task, stop and
> re-examine the template-override / route-ordering assumptions before adding
> the security scheme. **The load-bearing assumption is #4: smorest 0.47
> registers the `/api/docs` route ONLY when `OPENAPI_SWAGGER_UI_URL` is set
> (`flask_smorest/spec/__init__.py:100-110`), so removing that key unregisters
> the page unless a non-None value is supplied. Step 3 sets a local placeholder
> URL to keep the route registered while the template points assets at the app.**

**Files:**
- Create: `backend/app/core/apidocs.py`
- Create: `backend/app/templates/swagger_ui.html`
- Modify: `backend/app/__init__.py` (set `OPENAPI_SWAGGER_UI_URL` to a local
  placeholder; add `template_folder`; register asset routes)
- Modify: `backend/pyproject.toml` (add `swagger-ui-dist` to `dependencies`)
- Regenerate: `backend/uv.lock` (`uv lock`)
- Test: `backend/tests/api/test_apidocs.py`

**Interfaces:**
- Consumes: `flask_smorest.Api` (the `api` singleton in `app.extensions`),
  Flask `Blueprint`, `importlib.resources.files`, the `client` fixture from
  `backend/tests/api/conftest.py`.
- Produces:
  - `app.core.apidocs.register_asset_routes(app: Flask) -> None` — registers
    `GET /api/docs/swagger-ui.css`, `GET /api/docs/swagger-ui-standalone-preset.js`,
    `GET /api/docs/swagger-ui-bundle.js` (each returns the named file from the
    `swagger-ui-dist` package via `importlib.resources`, with the correct
    `Content-Type`).
  - `app.core.apidocs.SWAGGER_ASSETS: dict[str, tuple[str, str]]` — maps a
    route path suffix → `(package-relative filename, media type)`. The handler
    and the tests both read this map, so a renamed file edits one place.
- Seam: `apidocs.py` — the asset-serving behavior can change (e.g. swap to a
  mounted file) without touching the factory's call site or the template.
- Deletion test: delete `apidocs.py` + the template → the `/api/docs` page falls
  back to the CDN (the blank-air-gap failure returns) and the three asset routes
  404; the complexity (vendored-file locating + content-type mapping)
  reappears in the factory.
- Adapters: the test client exercises the real package (prod path); the
  `client` fixture builds a fresh app per test (test path) — 2 adapters justify
  the module.

**SATISFIES:** `swagger-ui-serves-local-assets`, `vendored-asset-matches-package`
(→ `acceptance.feature`)

- [ ] **Step 1: Add the dependency and regenerate the lockfile**

  In `backend/pyproject.toml`, add to the `dependencies` list (runtime, not
  dev):

  ```toml
  "swagger-ui-dist>=5,<6",
  ```

  Then:

  ```bash
  cd backend && uv lock && uv sync
  ```

  Confirm `swagger-ui-dist` is installed and its files exist at the package
  root:

  ```bash
  cd backend && uv run python -c "import importlib.resources, swagger_ui_dist" 2>/dev/null \
    || cd backend && uv run python -c "
  from importlib.resources import files
  p = files('swagger_ui_dist')
  print([f.name for f in p.iterdir() if str(f.name).startswith('swagger-ui')])
  "
  ```

  Expected: a listing that includes `swagger-ui.css`,
  `swagger-ui-standalone-preset.js`, `swagger-ui-bundle.js`. Record the exact
  package module name printed (it is `swagger_ui_dist` for the `swagger-ui-dist`
  package) — use it verbatim in Step 3. If a file is missing/renamed, adjust the
  `SWAGGER_ASSETS` map in Step 3 to the real names (the test will catch a miss).

- [ ] **Step 2: Write the failing tests**

  Create `backend/tests/api/test_apidocs.py` — in `tests/api/` so it uses the
  **docker-free** `client` fixture from `tests/api/conftest.py` (the root
  `tests/conftest.py` `client` is Testcontainers-based and errors without a
  container runtime, so these T1–T3 tests must not use it):

  ```python
  """Swagger UI air-gap (R1/R2): the page is app-served, never a CDN.

  Lives in tests/api/ to use the docker-free ``client`` fixture (tests/api/conftest.py).
  """
  from __future__ import annotations

  import importlib.resources

  from app.core import apidocs

  _DIST = "swagger_ui_dist"


  def _read_package(filename: str) -> bytes:
      return importlib.resources.files(_DIST).joinpath(filename).read_bytes()


  def test_package_ships_bundle():
      # T3b / T8 proxy: the runtime venv actually resolves the asset file.
      assert importlib.resources.files(_DIST).joinpath("swagger-ui-bundle.js").is_file()


  def test_docs_page_uses_local_asset_routes(client):
      html = client.get("/api/docs").get_data(as_text=True)
      assert "/api/docs/swagger-ui.css" in html
      assert "/api/docs/swagger-ui-standalone-preset.js" in html
      assert "/api/docs/swagger-ui-bundle.js" in html
      # No egress: no CDN and no other external asset URL in the page.
      assert "cdn.jsdelivr.net" not in html
      assert "https://" not in html
      assert "http://" not in html


  def test_asset_routes_serve_real_files(client):
      css = client.get("/api/docs/swagger-ui.css")
      assert css.status_code == 200
      assert css.content_type.split(";")[0].strip() == "text/css"
      assert css.get_data()
      for js in ("swagger-ui-standalone-preset.js", "swagger-ui-bundle.js"):
          resp = client.get(f"/api/docs/{js}")
          assert resp.status_code == 200
          # Werkzeug may append a charset; the media type is the contract.
          assert resp.content_type.split(";")[0].strip() in {
              "application/javascript",
              "text/javascript",
          }
          assert resp.get_data()


  def test_docs_assets_map_to_swagger_assets_not_spa(client):
      # Route-ordering guard: the asset routes win over the SPA catch-all.
      # (If register_asset_routes ran AFTER register_static, these 404.)
      rules = {r.rule for r in client.application.url_map.iter_rules()}
      assert "/api/docs/swagger-ui-bundle.js" in rules
      assert "/api/docs/swagger-ui.css" in rules


  def test_served_bundle_is_byte_identical_to_package(client):
      # Proves identity with the vendored file (catches a transform/encoding
      # bug or a stale in-repo copy). It does NOT by itself prove "not a CDN
      # fetch" — that is test_docs_page_uses_local_asset_routes (no external URL).
      served = client.get("/api/docs/swagger-ui-bundle.js").get_data()
      assert served == _read_package("swagger-ui-bundle.js")
      # Every asset in the map resolves to a real package file.
      for filename, _ in apidocs.SWAGGER_ASSETS.values():
          assert _read_package(filename)
  ```

- [ ] **Step 3: Write minimal implementation**

  Create `backend/app/core/apidocs.py`. The asset handler reads the bytes once
  and returns a plain `flask.Response` — **not** `send_file`. Reason: on a
  zipped wheel `importlib.resources.files(...).joinpath(...)` yields a
  `Traversable` that is not always a filesystem `Path`, and `send_file`
  (and its `download_name`) behave differently per interpreter/build combo.
  Reading bytes and returning `Response(data, mimetype=...)` is uniform
  across dev venv and the runtime image:

  ```python
  """Swagger UI air-gap (ADR-0020): serve the UI assets from the app, never a CDN.

  Reads the vendored `swagger-ui-dist` files via `importlib.resources` so the
  bundle rides in the Python image (ADR-0006 single container) and the page
  makes zero outbound calls at runtime.
  """
  from __future__ import annotations

  import importlib.resources

  from flask import Flask, Blueprint, Response, abort

  # route suffix -> (package-relative filename, media type). The handler and
  # the tests both read this map, so a renamed file edits one place.
  SWAGGER_ASSETS: dict[str, tuple[str, str]] = {
      "swagger-ui.css": ("swagger-ui.css", "text/css"),
      "swagger-ui-standalone-preset.js": ("swagger-ui-standalone-preset.js", "application/javascript"),
      "swagger-ui-bundle.js": ("swagger-ui-bundle.js", "application/javascript"),
  }
  _DIST_PKG = "swagger_ui_dist"


  def _asset_bytes(filename: str) -> bytes:
      return importlib.resources.files(_DIST_PKG).joinpath(filename).read_bytes()


  def register_asset_routes(app: Flask) -> None:
      """Register /api/docs/<asset> routes (same /api prefix as the smorest
      api-docs blueprint). Called BEFORE register_static so the SPA catch-all
      never sees these paths."""
      bp = Blueprint("swagger_assets", __name__, url_prefix="/api/docs")

      @bp.route("/<name>")
      def asset(name: str) -> Response:
          if name not in SWAGGER_ASSETS:
              abort(404)
          filename, media_type = SWAGGER_ASSETS[name]
          return Response(_asset_bytes(filename), mimetype=media_type)

      app.register_blueprint(bp)
  ```

  > **Template precedence (verified, keep it straight):** Flask's
  > `render_template` resolves the **app** `templates/` folder *before* any
  > blueprint's template folder. So `app/templates/swagger_ui.html` wins over
  > smorest's packaged `flask_smorest/spec/templates/swagger_ui.html` — do NOT
  > "fix" this by making the app template a fallback; the app copy must win.
  > T1's rendered-HTML assert is the gate (if the packaged template is used
  > instead, the CDN URL reappears and the test fails).

  Create `backend/app/templates/swagger_ui.html` (the smorest override — same
  shape as the packaged template, asset URLs now app-relative):

  ```html
  <!DOCTYPE html>
  <html>
    <head>
      <title>{{title}}</title>
      <link href="/api/docs/swagger-ui.css" rel="stylesheet" type="text/css"/>
    </head>
    <body>
      <div id="swagger-ui-container"></div>
      <script src="/api/docs/swagger-ui-standalone-preset.js"></script>
      <script src="/api/docs/swagger-ui-bundle.js"></script>
      <script>
        config = {
          url: "{{ spec_url }}",
          dom_id: '#swagger-ui-container'
        }
        var override_config = {{ swagger_ui_config | tojson }};
        for (var attrname in override_config) { config[attrname] = override_config[attrname]; }
        window.onload = function() {
          window.ui = SwaggerUIBundle(config)
        }
      </script>
    </body>
  </html>
  ```

  In `backend/app/__init__.py`:
  - **Do NOT delete** `OPENAPI_SWAGGER_UI_URL` outright — smorest 0.47 only
    registers the `/api/docs` route when this key is **not None**
    (`flask_smorest/spec/__init__.py:100-110`). Replace its CDN value with a
    local placeholder and update the comment so the CDN is gone from the page
    (the template hardcodes app-relative asset URLs, so the placeholder is
    never fetched):

    ```python
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/docs"
    # Local placeholder: keeps the /api/docs route registered (smorest only
    # registers it when this key is set). The app template (app/templates/
    # swagger_ui.html) ignores it and points the CSS/JS at /api/docs/* asset
    # routes, so nothing is fetched from a CDN. Air-gap (ADR-0020).
    app.config["OPENAPI_SWAGGER_UI_URL"] = "/api/docs/"
    ```
  - Ensure the app picks up `templates/`: change the constructor to
    `Flask(__name__, static_folder=None, template_folder="templates")` (add the
    `template_folder` kwarg to the existing `Flask(...)` call at line 20).
    Note the blast radius: this makes the app's `templates/` the app-level
    template dir for the whole app (it currently has none); record it in
    ASSUMPTIONS.md.
  - **Before** `register_static(app)` (and after `api.init_app(app)`), call:

    ```python
    from app.core import apidocs
    apidocs.register_asset_routes(app)
    ```

- [ ] **Step 4: Run tests to verify they pass**

  Run: `cd backend && uv run pytest tests/api/test_apidocs.py -v`
  Expected: all five tests PASS (`test_package_ships_bundle`,
  `test_docs_page_uses_local_asset_routes`, `test_asset_routes_serve_real_files`,
  `test_docs_assets_map_to_swagger_assets_not_spa`,
  `test_served_bundle_is_byte_identical_to_package`).
  Also confirm the existing doc tests still pass (route wiring + valid OpenAPI):

  Run: `cd backend && uv run pytest tests/test_app.py -v`
  Expected: PASS (no regression).

- [ ] **Step 5: Lint, typecheck, and full suite**

  ```bash
  cd backend && uv run ruff check app tests && uv run mypy app/core/apidocs.py
  cd backend && uv run pytest -q
  ```
  Expected: ruff clean, mypy clean, full backend suite green.

- [ ] **Step 6: Commit**

  ```bash
  git add backend/pyproject.toml backend/uv.lock backend/app/core/apidocs.py \
    backend/app/templates/swagger_ui.html backend/app/__init__.py backend/tests/api/test_apidocs.py
  git commit -m "feat: serve Swagger UI assets locally (air-gap, no CDN)"
  ```

---

### Task 2: Declare the `BearerAuth` JWT security scheme (page stays open)

**Files:**
- Modify: `backend/app/core/apidocs.py` (add `register_security_scheme(api)`)
- Modify: `backend/app/__init__.py` (call it after `api.init_app(app)`)
- Test: `backend/tests/api/test_apidocs.py` (add T4/T5/T7/T9 tests)

**Interfaces:**
- Consumes: `flask_smorest.Api` (`api` singleton), `apispec.Components.security_scheme`
  (via `api.spec.components.security_scheme`).
- Produces:
  - `app.core.apidocs.register_security_scheme(api: Api) -> None` — idempotently
    adds `components.securitySchemes.BearerAuth = {type: http, scheme: bearer,
    bearerFormat: JWT}`; no-ops if already present (safe under repeated
    `create_app`).
- Seam: `apidocs.py` — the scheme can be replaced/augmented (e.g. add an
  `OAuth2` alternative) without touching the factory.
- Deletion test: delete it → `/api/openapi.json` loses `components.securitySchemes`
  (T4 fails); the page is unchanged (still open).
- Adapters: production spec + the per-test app (2 adapters).

**SATISFIES:** `spec-declares-bearer-scheme`, `doc-routes-unchanged` (→
`acceptance.feature`)

- [ ] **Step 1: Write the failing tests**

  Add to `backend/tests/api/test_apidocs.py` (T4/T5/T7/T9):

  ```python
  def test_spec_declares_bearer_scheme(client):
      # T4
      spec = client.get("/api/openapi.json").get_json()
      assert spec["components"]["securitySchemes"]["BearerAuth"] == {
          "type": "http",
          "scheme": "bearer",
          "bearerFormat": "JWT",
      }


  def test_docs_page_is_open_without_token(client):
      # T5: the page is browsable with no Authorization header.
      resp = client.get("/api/docs")  # no Authorization header
      assert resp.status_code == 200


  def test_register_security_scheme_is_idempotent():
      # T7 — test the GUARD directly by double-invocation on one built spec.
      # Building a second app does NOT test this (api.spec is rebuilt fresh per
      # init_app), so a second-create_app test would pass trivially.
      from app import create_app
      from app.extensions import api

      application = create_app(
          {"DATABASE_URL": "sqlite://", "REDIS_URL": "redis://localhost:1/0"}
      )
      assert api.spec is not None  # init_app built it
      apidocs.register_security_scheme(api)  # factory already called it once
      apidocs.register_security_scheme(api)  # must be a no-op, not a raise
      assert "BearerAuth" in api.spec.components.security_schemes


  def test_spec_paths_superset_of_baseline(client):
      # T9 / R4: no previously documented operation vanished. Baseline = the
      # paths present before this change (captured once; see Step 3 note).
      from pathlib import Path

      spec = client.get("/api/openapi.json").get_json()
      baseline = set(json.loads((Path(__file__).parent / "apidocs_paths_baseline.json").read_text()))
      assert baseline <= set(spec["paths"])
  ```

  (Add `import json` to the test file's top imports.)

- [ ] **Step 2: Run tests to verify they fail**

  First capture the path baseline **before** this change alters the spec (the
  security scheme is top-level and does not add paths, so the baseline is the
  same set the app already exposes):

  ```bash
  cd backend && uv run python -c "
  import json
  from app import create_app
  from app.extensions import api
  app = create_app({'DATABASE_URL':'sqlite://','REDIS_URL':'redis://localhost:1/0'})
  with app.test_client() as c:
      paths = list(c.get('/api/openapi.json').get_json()['paths'])
  open('tests/api/apidocs_paths_baseline.json','w').write(json.dumps(paths, indent=2, sort_keys=True))
  print(len(paths), 'paths recorded')
  "
  ```

  Run: `cd backend && uv run pytest tests/api/test_apidocs.py -v -k "bearer or open_without or idempotent or superset"`
  Expected: `test_spec_declares_bearer_scheme` FAILS (no `securitySchemes` yet).
  `test_docs_page_is_open_without_token` PASSES (the page is open — the placeholder
  URL from Task 1 keeps the route registered and the `_authhook` skips doc paths).
  `test_register_security_scheme_is_idempotent` and
  `test_spec_paths_superset_of_baseline` may pass or fail on `register_security_scheme`
  not existing yet (RED is expected — the function is added in Step 3).

- [ ] **Step 3: Write minimal implementation**

  In `backend/app/core/apidocs.py`, add (the guard checks for the scheme's
  presence, so a second call on the same spec is a no-op — it never reaches
  `security_scheme()` a second time, so no `DuplicateComponentNameError`):

  ```python
  from flask_smorest import Api

  _BEARER_SCHEME = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
  _BEARER_ID = "BearerAuth"


  def register_security_scheme(api: Api) -> None:
      """Idempotently add the BearerAuth JWT scheme to the spec (called after
      api.init_app, so api.spec exists). A no-op if the scheme is already
      present on this spec — tested by double-invocation in
      test_register_security_scheme_is_idempotent."""
      spec = api.spec
      if spec is None:
          return
      if _BEARER_ID in spec.components.security_schemes:
          return
      spec.components.security_scheme(_BEARER_ID, _BEARER_SCHEME)
  ```

  In `backend/app/__init__.py`, immediately **after** `api.init_app(app)` and
  before `register_apis(app, api)` (so the scheme exists before routes are
  documented), add:

  ```python
  apidocs.register_security_scheme(api)
  ```

  (`apidocs` is already imported in Task 1.)

- [ ] **Step 4: Run tests to verify they pass**

  Run: `cd backend && uv run pytest tests/api/test_apidocs.py -v`
  Expected: all tests PASS (Task 1's five + Task 2's four).

- [ ] **Step 5: Lint, typecheck, and full suite**

  ```bash
  cd backend && uv run ruff check app tests && uv run mypy app/core/apidocs.py
  cd backend && uv run pytest -q
  ```
  Expected: green.

- [ ] **Step 6: Commit**

  ```bash
  git add backend/app/core/apidocs.py backend/app/__init__.py \
    backend/tests/api/test_apidocs.py backend/tests/api/apidocs_paths_baseline.json
  git commit -m "feat: declare BearerAuth JWT security scheme on the OpenAPI spec"
  ```

---

## Self-Review (run after writing, before handoff)

**Critic pass (general subagent, 2026-10-17):** 16 findings. Resolutions
folded into the blueprint:
- **#1/#3 (CRIT/HIGH) — T7 guard trivially untested.** FIXED: `test_register_security_scheme_is_idempotent`
  now double-invokes `register_security_scheme(api)` on one built spec (not a
  second `create_app`, which rebuilds `api.spec` fresh and would pass
  trivially). The guard checks presence, so a second call never reaches
  `security_scheme()` a second time.
- **#2 (CRIT) — wrong `client` fixture.** FIXED: the new tests live in
  `tests/api/test_apidocs.py` to use the docker-free `client` from
  `tests/api/conftest.py`; the root `tests/conftest.py` `client` is
  Testcontainers-based.
- **#4 (HIGH) — removing `OPENAPI_SWAGGER_UI_URL` unregisters the page.** FIXED:
  smorest 0.47 registers `/api/docs` only when that key is not None
  (verified in `flask_smorest/spec/__init__.py:100-110`); the plan now keeps a
  local placeholder URL (`/api/docs/`) instead of deleting the key, and the
  door check names this as the load-bearing assumption.
- **#5 (HIGH) — T8 asserted as fact with no test.** FIXED: T3b
  (`test_package_ships_bundle`, `importlib.resources...is_file()`) proves the
  venv resolves the file; T8 is the image-build backstop.
- **#6 (HIGH) — template-override rationale inverted.** FIXED: the correct
  precedence (app `templates/` wins over smorest's blueprint `./templates`) is
  stated in Step 3 as a constraint, not the reversed "fallback" claim.
- **#7 (MED) — `send_file` on a Traversable / double read / `download_name`.**
  FIXED: `_asset_bytes` reads once and returns `flask.Response(data,
  mimetype=...)`; no `send_file`, no `download_name`.
- **#8 (MED) — no route-ordering test.** FIXED: `test_docs_assets_map_to_swagger_assets_not_spa`
  asserts the asset paths are in the url_map (would fail if registered after the
  SPA catch-all).
- **#9 (MED) — T6 "paths superset" untested.** FIXED: T9 +
  `test_spec_paths_superset_of_baseline` (golden `apidocs_paths_baseline.json`,
  captured in Task 2 Step 2).
- **#10 (MED) — no-op `https://` assert.** FIXED: deleted; the test now asserts
  `assert "https://" not in html and "http://" not in html` (two explicit lines).
- **#11 (MED) — byte-identical claim overstated.** FIXED: T3's wording lowered
  to "proves identity with the vendored file, not a CDN fetch"; the CDN claim
  rests on T1.
- **#12 (MED) — exact `content_type` flaky.** FIXED: JS asserts
  `content_type.split(";")[0].strip() in {"application/javascript",
  "text/javascript"}`.
- **#13 (LOW) — `SWAGGER_ASSETS` map key == filename.** KEPT (harmless); the
  "single source of truth" comment now says "handler and tests both read this
  map" rather than over-claiming a rename benefit.
- **#14 (LOW) — `template_folder` blast radius.** FIXED: recorded in Task 1
  Step 3 (affects the whole app's template resolution) and flagged for
  ASSUMPTIONS.md.
- **#15 (LOW) — chart/env verification unrecorded.** FIXED: see the note below.
- **#16 (LOW) — `strict_slashes=False` no-op.** FIXED: removed from the route
  (default behavior is unchanged).

**Verified (facts, not vibes):**
- No `OPENAPI_SWAGGER_UI_URL` reference exists in `charts/` or the
  `Dockerfile` (grep-verified) — the env var is factory-internal, so removing its
  CDN value requires no chart change.
- smorest 0.47 `_register_swagger_ui_rule` registers the route only when
  `OPENAPI_SWAGGER_UI_URL` is not None (`spec/__init__.py:100-110`).
- Flask `render_template` resolves the app `templates/` before blueprint
  template folders (verified against the installed Flask).
- The `swagger_ui_dist` package module name and the three file names are
  confirmed present at the package root after `uv sync` (Task 1 Step 1's file
  listing is the gate).

- **Spec coverage:** R1 → Task 1 (page + asset routes). R2 → Task 1
  (dependency + byte-identical + `is_file()` + T8 image note). R3 → Task 2
  (scheme + open page). R4 → Task 1 Step 4 + Task 2 Step 4 (existing doc tests
  stay green, spec paths superset via T9). No requirement is uncovered.
- **Must-haves coverage:** T1–T9 each map to a test in Task 1 or Task 2
  (T3b/T8 are the image/venv backstops; T9 is the paths-superset golden test).
- **One-way-door completeness:** none (recorded above); no `> ⚠ one-way:` tags
  needed.
- **Placeholder scan:** the previous no-op `"https://"` assert is deleted; all
  steps now carry concrete values. The path baseline JSON is captured by a
  concrete command in Task 2 Step 2 (not a TBD).
- **Type consistency:** `SWAGGER_ASSETS` is a `dict[str, tuple[str, str]]` used
  identically by the handler (`name not in SWAGGER_ASSETS`, unpack to
  `(filename, media_type)`) and the test (`for filename, _ in
  apidocs.SWAGGER_ASSETS.values()`). `register_security_scheme(api: Api) ->
  None` / `register_asset_routes(app: Flask) -> None` signatures match their
  call sites in the factory.

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Routing (SPA catch-all shadowing) | Applicable — `/api/docs/*` could be swallowed by the SPA `@app.get("/<path:path_>")` | Register asset routes BEFORE `register_static`; the asset rules match first; the SPA route already 404s `.js`/`.css` as a backstop | `test_docs_page_uses_local_asset_routes` + `test_asset_routes_serve_real_files` (a 404 asset fails these) + `test_docs_assets_map_to_swagger_assets_not_spa` (pins the asset paths in the url_map) |
| Shell / subprocess | N/A — no shell or subprocess calls are added (asset reads use `importlib.resources`, not `open` on a path or a `COPY` step) | — | — |
| Executable-file classification | N/A — no new binaries/executables; the venv's `swagger-ui-dist` data files are served, not executed | — | — |
| Version-control automation / PR automation | N/A — no git hooks or PR automation touched by this change | — | — |
| Process integration | N/A — no new process/worker; the asset serving is in-process in the existing Gunicorn workers | — | — |
| `_shared/{planning,craft,verification,knowledge}/` | N/A — no skillgrid shared files edited | — | — |

## Execution Handoff

Two tasks, both small and sequential (Task 2 depends on Task 1's
`apidocs` module + factory wiring). **3+ tasks of work is borderline** — this is
2 focused tasks, so **slicing is optional**: execute directly, or slice into two
tickets if the team prefers per-ticket review.

**Update `state.yaml`:** set `pipeline.current_change:
2026-10-17-swagger-ui-air-gap` and `pipeline.current_phase: blueprint`.

Then choose an execution approach:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task,
review between tasks. Use `skillgrid:subagent-execution`.

**2. Inline Execution** — execute both tasks in this session with checkpoints.
Use `skillgrid:simple-execution`.

**Review at the end:** the lightweight two-axis pass
(`skillgrid:requesting-code-review`) is sufficient at this tier — the change is
`small`, single-concern, no trust-boundary or migration risk.
