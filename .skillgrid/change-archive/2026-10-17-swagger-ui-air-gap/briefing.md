# Swagger UI Air-Gap — Design Briefing (requirements & intent)

> **STATUS:** `draft` (2026-10-17)

> **Role:** this is the *what* — the validated design/spec: problem, intent,
> requirements, success criteria. The companion `blueprint.md` is the *how*
> (implementation plan). Do not rename.

## Problem / Intent

The KubeDash API exposes a working Swagger UI at `/api/docs` and an OpenAPI 3
spec at `/api/openapi.json` (both already registered and tested). But the UI
loads its three assets — `swagger-ui.css`, `swagger-ui-standalone-preset.js`,
and `swagger-ui-bundle.js` — from a **hardcoded public CDN**
(`cdn.jsdelivr.net/npm/swagger-ui-dist@5/...`, set as `OPENAPI_SWAGGER_UI_URL`
in `backend/app/__init__.py:62`). In a network-isolated deployment — the core
reason KubeDash exists (ADR-0020: **zero outbound calls at runtime**) — that
`<script src>` is a runtime egress the page silently depends on; with no
internet the UI shell renders blank. This change makes the Swagger UI serve
its assets **from the app itself (always)** and adds a **bearer-JWT security
scheme** to the spec so the UI documents the auth affordance, while the page
stays open for browsing.

## Purpose & Success Criteria

- **Purpose:** a KubeDash operator in an air-gapped cluster can open
  `/api/docs` and see the full, functional Swagger UI — no internet required —
  and the spec declares a `Bearer` (JWT) security scheme so the auth contract
  is visible in the docs.
- **Success criteria:**
  - `GET /api/docs` returns 200 and its HTML references **only** app-served
    asset paths (no `cdn.jsdelivr.net`, no other external host) for the CSS and
    both JS bundles.
  - `GET /api/docs/swagger-ui.css`, `.../swagger-ui-standalone-preset.js`, and
    `.../swagger-ui-bundle.js` each return 200 with the correct
    `Content-Type` and a non-empty body (the real vendored files).
  - `GET /api/openapi.json` returns 200 with a valid OpenAPI 3 document
    containing `components.securitySchemes.BearerAuth`
    (`{type: http, scheme: bearer, bearerFormat: JWT}`).
  - `GET /api/docs` remains **open** (no `Authorization` header required) — the
    page is browsable; the security scheme is documented, not enforced on the
    page.
  - The existing route-wiring guard
    (`test_openapi_routes_registered_without_deps`) still passes:
    `/api/openapi.json` → `api-docs.openapi_json`, `/api/docs` →
    `api-docs.openapi_swagger_ui`.
- **Out of scope:**
  - **No auth wiring on the page.** We add the `BearerAuth` scheme to the spec
    now, but the Swagger UI is not yet given a pre-filled/autofilling JWT
    "Authorize" affordance (no `requestInterceptor` that reads the SPA's
    stored token). That is deferred; the scheme's presence is what enables it
    later. (User decision 2026-10-17: "auth for the future.")
  - **No new config flag / no CDN toggle.** The asset source is *always* local
    (user decision 2026-10-17: "always air-gap"). `OPENAPI_SWAGGER_UI_URL` is
    removed, not made conditional.
  - **No ReDoc / RapiDoc** — only the Swagger UI page is in scope.
  - **No change to which API routes are documented** — the existing
    `@blp.doc(...)` surface is untouched; we only change where its *assets*
    come from and add the top-level security scheme.
  - **No Helm chart change** unless the chart references the removed
    `OPENAPI_SWAGGER_UI_URL` env var (verified in the blueprint; if absent,
    "None").

## Context

- **Fits existing patterns: yes.** Flask-Smorest already registers the doc
  blueprint (`api-docs`) with `/api/openapi.json` and `/api/docs`. The page is
  rendered from smorest's packaged `swagger_ui.html` template
  (`flask_smorest/spec/templates/swagger_ui.html`), which interpolates
  `{{swagger_ui_url}}` (the CDN base) in front of `swagger-ui.css`,
  `swagger-ui-standalone-preset.js`, and `swagger-ui-bundle.js`, and
  `{{ spec_url }}` (the `openapi.json` URL) into the `SwaggerUIBundle` config.
  This change overrides that one template and adds three asset routes under the
  same `/api/docs` prefix.
- **In-force decisions constraining this change:**
  - **ADR-0020 (air-gap, zero outbound calls at runtime)** — the driving
    decision. The CDN `<script src>` is exactly the kind of runtime egress it
    forbids. This change removes it.
  - **ADR-0006 (single container: Gunicorn serves API + static SPA)** — the
    Swagger UI is served by the same Gunicorn app as the API and SPA, so the
    vendored assets ride in the Python image (the user-chosen "serve from a
    Python package" strategy), not a separate static dir.
- **Conventions** (per the base-structure briefing): Python 3.12 + `uv` +
  `ruff` + `mypy --strict`; Conventional Commits. `swagger-ui-dist` is a
  **runtime** dependency (served in the image), so it is added to the main
  `dependencies` group in `backend/pyproject.toml` (uv sync picks it up).

## Approaches Considered

- **Chosen: always-local assets via a Python package + a template override.**
  Add `swagger-ui-dist` as a backend dependency; serve its files from
  `importlib.resources` on three app routes under `/api/docs/`; override
  smorest's `swagger_ui.html` with an app template whose `src`/`href` point at
  those app routes. One image, no CDN, no toggle, works fully offline.
- **Rejected: CDN vs. local config flag.** A `KUBEDASH_SWAGGER_CDN` toggle
  (local only when off) is more moving parts for a benefit an air-gapped
  product does not need; the user chose *always* air-gap, so the CDN is removed
  outright (single-switch principle, ADR-0020).
- **Rejected: copy the bundle into a separate static dir at Dockerfile build
  time.** Works, but it couples the assets to a Dockerfile `COPY` step and a
  second static location distinct from the SPA's `KUBEDASH_STATIC_DIR`; the
  user chose serving from the Python package instead (self-contained in the
  venv, version pinned by the lockfile).
- **Chosen: security scheme added now, page auth deferred.** Register a
  `BearerAuth` security scheme on the spec so the docs declare JWT auth; do not
  yet wire an Authorize affordance (the user wants the scheme "now but not auth
  for the future").

## Requirements

1. **R1 — Always-local Swagger UI assets:** the Swagger UI page loads its CSS
   and both JS bundles from the app, never from a CDN or any external host.
   - **Current:** `backend/app/__init__.py:62` sets
     `OPENAPI_SWAGGER_UI_URL` to
     `https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`;
     smorest's packaged `swagger_ui.html` emits `{{swagger_ui_url}}...` for the
     three assets, so the page fetches them from jsdelivr at runtime.
   - **Target:** `OPENAPI_SWAGGER_UI_URL` is removed; an app `templates/`
     directory provides a `swagger_ui.html` override whose asset references are
     app-relative routes (`/api/docs/swagger-ui.css`,
     `/api/docs/swagger-ui-standalone-preset.js`,
     `/api/docs/swagger-ui-bundle.js`); three Flask routes under the same
     doc prefix serve those files from the vendored `swagger-ui-dist` package.
   - **Acceptance:** `GET /api/docs` 200 and its HTML contains
     `/api/docs/swagger-ui.css`, `/api/docs/swagger-ui-standalone-preset.js`,
     and `/api/docs/swagger-ui-bundle.js`, and contains **no** `cdn.jsdelivr.net`
     and no other `http(s)://` asset URL; the three asset GETs return 200 with
     a non-empty body and `text/css` / `application/javascript` (or
     `text/javascript`) `Content-Type`.
   - **Acceptance scenario:** `happy path swagger-ui-serves-local-assets` →
     `acceptance.feature`

2. **R2 — Vendored package ships in the image:** the `swagger-ui-dist` package
   is a declared runtime dependency and is present in the production image.
   - **Current:** `swagger-ui-dist` is not in `backend/pyproject.toml` and is
     not in the venv; the Dockerfile runtime stage copies only `backend/app` +
     `wsgi.py` + the built SPA.
   - **Target:** `swagger-ui-dist` is added to the main `dependencies` list in
     `backend/pyproject.toml`; `uv lock` records it; `uv sync` installs it into
     the venv (the Dockerfile's `uv sync --frozen` stage installs it too, since
     it is a main dependency). The asset routes read the files from
     `importlib.resources` of the package, so no `COPY` step is added.
   - **Acceptance:** `backend/pyproject.toml` lists `swagger-ui-dist`;
     `uv.lock` contains it; a test asserts the served `swagger-ui-bundle.js`
     body is byte-identical to the file read from the package via
     `importlib.resources` (proving the route serves the vendored file, not a
     CDN fetch or a stale copy).
   - **Acceptance scenario:** `happy path vendored-asset-matches-package` →
     `acceptance.feature`

3. **R3 — Bearer JWT security scheme in the spec (no page auth):** the OpenAPI
   spec declares a `BearerAuth` security scheme; the `/api/docs` page stays
   open (browsable without a token).
   - **Current:** `/api/openapi.json` has no `components.securitySchemes`; the
     `_authhook` already scopes JWT enforcement to `/api/v1/*` and explicitly
     skips the doc paths, so the page is already open.
   - **Target:** at app init the spec registers a `BearerAuth` security scheme
     (`{type: http, scheme: bearer, bearerFormat: JWT}`); the page requires no
     `Authorization` header. No `requestInterceptor`/prefill is added (page
     auth deferred — see Out of scope).
   - **Acceptance:** `GET /api/openapi.json` 200 and
     `components.securitySchemes.BearerAuth == {type: http, scheme: bearer,
     bearerFormat: JWT}`; `GET /api/docs` returns 200 **without** an
     `Authorization` header.
   - **Acceptance scenario:** `happy path spec-declares-bearer-scheme` →
     `acceptance.feature`

4. **R4 — Doc surface and route wiring preserved:** the existing OpenAPI spec
   and doc routes remain valid and unchanged in shape; only the asset source
   and the new top-level security scheme differ.
   - **Current:** `test_openapi_json_is_valid_openapi3` and
     `test_openapi_routes_registered_without_deps` pass and lock
     `/api/openapi.json` → `api-docs.openapi_json`, `/api/docs` →
     `api-docs.openapi_swagger_ui`, plus the valid-OpenAPI-3 assertion.
   - **Target:** both tests keep passing; the spec is still valid OpenAPI 3 and
     still lists the same documented operations (the change is additive at the
     top level and does not remove any route or operation).
   - **Acceptance:** the full backend test suite passes; the two existing doc
     tests are unchanged and green; the set of spec `paths` is a superset of
     (i.e. contains) what it was before the change.
   - **Acceptance scenario:** `happy path doc-routes-unchanged` →
     `acceptance.feature`

## Implementation Decisions

- **Modules to build/modify:**
  - `backend/pyproject.toml` (add `swagger-ui-dist` to `dependencies`) —
    *modify*; `backend/uv.lock` regenerated via `uv lock`.
  - `backend/app/__init__.py` (remove the `OPENAPI_SWAGGER_UI_URL` config line;
    ensure the app's `templates` folder resolves; register the `BearerAuth`
    security scheme on the spec at init) — *modify*.
  - `backend/app/templates/swagger_ui.html` (new) — the smorest template
    override that points asset `src`/`href` at app routes.
  - A small module for the asset routes + spec security registration
    (e.g. `backend/app/core/apidocs.py`) — *new*; wired into the factory.
  - `backend/tests/test_apidocs.py` (new) — R1/R2/R3 tests.
  - `backend/tests/test_app.py` — *verify only* (no change; the two existing
    doc tests must stay green).
- **Interfaces:**
  - Asset routes (under the same `/api` doc prefix as the smorest `api-docs`
    blueprint, so they land at `/api/docs/...`):
    - `GET /api/docs/swagger-ui.css` → `text/css`
    - `GET /api/docs/swagger-ui-standalone-preset.js` → `application/javascript`
    - `GET /api/docs/swagger-ui-bundle.js` → `application/javascript`
    Each returns the bytes of the named file from the `swagger-ui-dist`
    package via `importlib.resources`.
  - Spec registration: `api.spec.components.security_scheme("BearerAuth",
    {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"})` called during
    `create_app` after `api.init_app(app)` (so `api.spec` is built).
- **Data flow:** browser → `GET /api/docs` (Flask renders the app's
  `swagger_ui.html`, `spec_url` = `/api/openapi.json`) → browser issues three
  asset GETs to `/api/docs/*` → the asset handler reads the vendored file from
  the package and returns it → browser builds the UI and fetches
  `/api/openapi.json` for the spec. No request leaves the app origin.
- **Error handling:** a missing package file is a build/dependency defect, not
  a runtime branch — the handler returns the file's bytes or lets Flask 404
  (there is no "optional" asset). The security-scheme registration is guarded
  so a second `create_app` (conftest builds one app per test) does not re-add
  the scheme and raise `DuplicateComponentNameError` (register idempotently).
- **Dependencies (runtime):** `swagger-ui-dist` (main dependency; served in the
  image). No new dev-only deps.

## Testing Decisions

- **What makes a good test here:** verify the *output* — the rendered page's
  asset references and the served asset bytes — not the internals of how the
  files are located. The "matches the package" test proves the route serves the
  real vendored file (catches a CDN fallback or a stale in-repo copy).
- **Modules to test:** `backend/app/core/apidocs.py` (asset routes + security
  registration) via the Flask test client; the factory's spec via the
  `client` fixture.
- **Prior art:** `backend/tests/test_app.py` (the two existing doc tests) and
  `backend/tests/api/conftest.py` (the `client` fixture that builds the app).
- **Edge cases:** (a) page HTML has no external asset URL; (b) each asset route
  200 + correct `Content-Type` + non-empty; (c) served `swagger-ui-bundle.js`
  is byte-identical to the package file; (d) `BearerAuth` scheme present in
  spec with the exact dict; (e) `/api/docs` 200 with **no** `Authorization`
  header; (f) a second `create_app` does not raise on the duplicate security
  scheme; (g) the two pre-existing doc tests remain green.

## Impact on Global Docs

- `.skillgrid/artifacts/00-prd.md`: **None** (a self-serve API-docs capability;
  no new user-facing product feature or metric).
- `.skillgrid/ASSUMPTIONS.md`: record the decision that Swagger UI assets are
  **always served locally** (no CDN, no toggle) as the air-gap posture, and that
  a `BearerAuth` security scheme is declared on the spec with page-level auth
  deferred. (Add a VERIFIED fact: the vendored-asset serving mechanism.)
- `.skillgrid/ARCHITECTURE.md`: **None** (no new component/data store/integration;
  the Swagger UI is the existing doc surface, now offline).

## Clarity Report

The design was developed in a single Plan-mode session with the user on
2026-10-17 (three answer-select rounds locked: always-air-gap / no toggle,
serve-from-Python-package, and security-scheme-now-but-page-auth-deferred).

| Dimension           | Score | Min  | Status | Notes                              |
|---------------------|-------|------|--------|------------------------------------|
| Goal Clarity        | 0.95  | 0.75 | pass   | "make /api/docs air-gap ready" — user-confirmed |
| Boundary Clarity    | 0.92  | 0.70 | pass   | always-local, no toggle, no page-auth, no ReDoc — explicit in Out-of-scope |
| Constraint Clarity  | 0.90  | 0.65 | pass   | ADR-0020 (driving) + ADR-0006 (single container) in force |
| Acceptance Criteria | 0.90  | 0.70 | pass   | every requirement carries a concrete pass/fail check + scenario |
| **Clarity**         | 0.05  | ≤0.20| pass   | residual: exact `Content-Type` string the JS routes return (see Open Questions) |

**Interview log:**

| Round | Question summary         | Decision locked                    |
|-------|-------------------------|------------------------------------|
| 1     | CDN vs local asset source at runtime? | **Always local** (always air-gap); remove `OPENAPI_SWAGGER_UI_URL`, no toggle |
| 2     | Which asset strategy fits the air-gap single-container build? | **Serve from a Python package** (`swagger-ui-dist` dep + `importlib.resources`) |
| 3     | Add a JWT Authorize security scheme now? | **Add the `BearerAuth` scheme now; defer page-level auth wiring** |

## Open Questions & Assumptions

- **Assumption:** `swagger-ui-dist` (current major, pinned by `uv.lock`) ships
  `swagger-ui.css`, `swagger-ui-standalone-preset.js`, and
  `swagger-ui-bundle.js` at its package root. Verified at execution time by the
  "matches the package" test reading the exact file names via
  `importlib.resources`; if a minor version renames a file, the asset routes
  (not the spec) are the only thing to update.
- **Assumption:** the app's `templates/` folder is found by Flask's template
  resolver so `render_template("swagger_ui.html")` picks the app's override
  over smorest's packaged one. Flask resolves a `templates/` folder relative to
  the app root path; the blueprint's packaged `./templates` is a fallback.
  Verified by R1's "no CDN in page HTML" assertion (if the override is not
  picked, the CDN URL reappears and the test fails).
- **Question:** the exact `Content-Type` string the JS asset routes should set
  — `application/javascript` (the modern canonical type, preferred by
  Content-Security-Policy) vs `text/javascript`. The blueprint will use
  `application/javascript` and the test will assert on that exact value.

## Decisions (ADR)

No new ADR clears the bar — this change **implements** in-force decisions
(ADR-0020 air-gap, ADR-0006 single container) rather than making a new
hard-to-reverse + surprising + real-trade-off choice. The "always-local, no
toggle" posture is recorded in `.skillgrid/ASSUMPTIONS.md` (a VERIFIED fact),
not a new ADR. In-force ADRs constraining it: **ADR-0020** (zero outbound calls
at runtime — the CDN is the egress removed) and **ADR-0006** (single container —
the assets ride in the Python image).

## Terms

- **Air-gap (air-gap deployment)** — a network-isolated deployment with zero
  outbound calls at runtime (ADR-0020). Not in the terms files; defined by the
  ADR.
- **Swagger UI asset source** — where `/api/docs` loads its CSS/JS from
  (CDN vs app-served). Introduced by this spec; resolved to "always app-served
  from the vendored `swagger-ui-dist` package."
