# QA Report — Swagger UI Air-Gap

**Effective tier:** T2 (briefing/blueprint header) → floor L2+L3 (full suite + build).
Classification: `small` (≤10 files, single concern). `quality:` not configured —
using defaults (coverage_min 80, p0 100%, p1 95%); mutation + Trivy not configured
(disabled → N/A). **Status: PROPOSED** (no ASSUMED flag → no decision-debt WARNING).

## Test Plan

| Scenario (SATISFIES) | Truth | Covering test (ran + passed) | Layer | Cadence | Rank |
|---|---|---|---|---|---|
| `swagger-ui-serves-local-assets` | T1 | `test_docs_page_uses_local_asset_routes` | unit (Flask client) | pr | P0 |
| (asset serving) | T2 | `test_asset_routes_serve_real_files` | unit (Flask client) | pr | P0 |
| `vendored-asset-matches-package` | T3 | `test_served_bundle_is_byte_identical_to_package` | unit (byte equality) | pr | P1 |
| (venv ships files) | T3b/T8 | `test_package_ships_bundle` | unit (importlib.resources) | pr | P1 |
| `spec-declares-bearer-scheme` | T4 | `test_spec_declares_bearer_scheme` | unit (Flask client) | pr | P0 |
| (page open) | T5 | `test_docs_page_is_open_without_token` | unit (Flask client) | pr | P1 |
| (route wiring preserved) | T6 | `test_app.py::test_openapi_routes_registered_without_deps` + `test_openapi_json_is_valid_openapi3` (pre-existing, re-run green) | unit (runtime-free) | pr | P1 |
| `spec-declares-bearer-scheme` (guard) | T7 | `test_register_security_scheme_is_idempotent` | unit (double-invocation) | pr | P1 |
| `doc-routes-unchanged` | T9 | `test_spec_paths_superset_of_baseline` | unit (golden baseline) | pr | P1 |

- **Out of scope:** the actual Docker image build (T8 backstop — needs a
  container runtime/network, absent on this host); T3b is the in-venv proxy.
  No ReDoc/RapiDoc (not in scope). No page-level auth wiring (deferred by design).
- **Layer note:** all behaviors are pure request/response on the Flask app —
  the unit layer (Flask test client) is the highest layer that fits; no
  integration/e2e layer is warranted (no DB, no external I/O in these paths).

## Goal-Backward Verification

| Truth | Evidence (named, ran) | Verdict |
|---|---|---|
| T1 page loads local assets, no CDN | `test_docs_page_uses_local_asset_routes` + runtime probe `T1 page-no-CDN: True` | VERIFIED |
| T2 asset routes serve non-empty files, correct content-type | `test_asset_routes_serve_real_files` + probe `T2 assets-200-nonempty: True` (css 144KB, preset 312KB, bundle 1MB) | VERIFIED |
| T3 served bundle byte-identical to package file | `test_served_bundle_is_byte_identical_to_package` | VERIFIED |
| T3b/T8 venv resolves the asset file | `test_package_ships_bundle` | VERIFIED |
| T4 BearerAuth scheme present, exact dict | `test_spec_declares_bearer_scheme` + probe `T4 bearer-scheme: True` | VERIFIED |
| T5 page open without Authorization | `test_docs_page_is_open_without_token` + probe `T5 page-open: True` | VERIFIED |
| T6 pre-existing doc tests unchanged + green | `tests/test_app.py` (route wiring + valid OpenAPI 3) re-run | VERIFIED |
| T7 idempotent guard (no DuplicateComponentNameError) | `test_register_security_scheme_is_idempotent` (double-invocation) | VERIFIED |
| T9 paths superset of baseline | `test_spec_paths_superset_of_baseline` (31 paths, golden subset) | VERIFIED |

## TDD Evidence

| Unit | RED (failing first) | GREEN commit |
|---|---|---|
| Task 1 (asset serving) | `ImportError: cannot import name 'apidocs' from 'app.core'` (module absent) | `73cd7daf` |
| Task 2 (BearerAuth scheme) | `test_spec_declares_bearer_scheme` FAIL (no `securitySchemes`) + idempotent test error (fn absent) | `3d2a9a0a` |

Both RED→GREEN cycles are recorded in the implementer reports; commit hashes
resolve in git history; test files exist on disk.

## Code-Quality Gates

| Gate | Result | Threshold | Verdict |
|---|---|---|---|
| Focused suite | 9/9 passed | — | PASS |
| Full backend suite | 132 passed, 17 pre-existing env-block errors (psycopg2/kind/docker — no container runtime; none reference this change's files) | — | PASS (no regression) |
| ruff (changed files) | 0 | 0 | PASS |
| mypy --strict (changed files) | 0 | 0 | PASS |
| Whole-project coverage | not configured | 80 (default) | N/A (no coverage command set) |
| Mutation | not configured | 80 (default) | N/A |
| Trivy | not configured | — | N/A |
| P0 pass rate | 100% (3 P0 tests green) | 100% | PASS |
| P1 pass rate | 100% | 95% | PASS |

## Assertion Quality

- `test_docs_page_uses_local_asset_routes`: asserts on rendered HTML content +
  absence of external URLs — not a tautology, exercises the real page render.
- `test_served_bundle_is_byte_identical_to_package`: byte equality against an
  independent `importlib.resources` read — catches a transform/encoding bug.
- `test_register_security_scheme_is_idempotent`: double-invocation on one built
  spec — exercises the real guard (not the trivially-passing second-app path).
- No tautology, no ghost loop, no assertion-without-code-call. CRITICAL count: 0.

## Findings

- **CRITICAL:** 0
- **WARNING:** 0
- **SUGGESTION:** 1 — the Docker image build (T8 backstop) is not exercised on
  this host (no container runtime). It is a named re-run path: build the image
  where Docker is present and confirm `/api/docs` renders offline. Low risk —
  T3b proves the dev venv ships the files, and the Dockerfile's
  `uv sync --frozen --no-dev` installs the same main-dep set.

## Floor

Weakest dimension: **PASS** (every audit PASS or N/A; the single SUGGESTION is a
named re-run path, not a non-answer that caps the verdict — the verification
scope is COMPLETE for everything runnable on this host). No FAIL-valued
dimension. The mean (also green) is not used; the floor is the verdict.

## Gate Decision

**PASS**

All truths VERIFIED by named tests; all scenarios covered by a test that ran and
passed; 0 CRITICAL findings; no MISSING_RED/STALE; all code-quality gates PASS
or N/A; P0/P1 at threshold. The one SUGGESTION (image-build backstop) is a named
re-run path, not a gate blocker.

## Human Override

None.

---

# Retro Half (written by reflect, 2026-10-18)

## Final-State Facts

- **Shipped to:** `rebase` branch (KEPT — no merge into `main`, per the Integration
  Rule adopted this session). `main` was not touched.
- **Commits (this change, on `rebase`):**
  - `fcc2dc4f` spec — briefing + blueprint
  - `73cd7daf` Task 1 — serve Swagger UI assets locally (air-gap, no CDN)
  - `3d2a9a0a` Task 2 — declare BearerAuth JWT security scheme
  - `07ab0db3` QA report (PASS)
  - `10324d64` state phase → qa
  - `18c919c5` docs — blueprint package-name correction (`swagger-ui-dist` → `swagger-ui-bundle`)
  - `cee356fd` final-fix — fail at boot on missing vendored asset; tighten route test
  - `f5ef351a` docs — record "Swagger UI always-local" as VERIFIED in ASSUMPTIONS.md
- **Final test state (re-run at close, not the QA snapshot):** `tests/api/test_apidocs.py`
  **9/9 passed** (1.83s). Full backend suite carries 17 pre-existing env-block
  errors (`psycopg2`/Testcontainers, no container runtime) — none reference this
  change's files.
- **QA-half snapshot vs final state:** the QA half (written at `07ab0db3`) records
  Task 1 + Task 2 only. Two later commits landed after it: `cee356fd` (boot-time
  `RuntimeError` on a missing/vendored-asset drift, plus a tightened
  url_map→endpoint test) and `f5ef351a` (ASSUMPTIONS.md VERIFIED note). Per
  Final-State Authority these are the current state; the QA half's "9 tests"
  count is unchanged (still 9) but the route test was strengthened and the boot
  guard added.
- **Move evidence (from ship):** `.skillgrid/specs/2026-10-17-swagger-ui-air-gap/`
  → `.skillgrid/archive/2026-10-17-swagger-ui-air-gap/`; `diff -r` readback
  **empty**. Source path gone.
- **Carried forward (NOT shipped):** `backend/Dockerfile` (uv image from
  `docker.io/astral/uv` + `pnpm@10` pin) is intentionally uncommitted for a
  separate `build(deploy)` commit (user instruction, 2026-10-18).

## Sourced Learnings

- **Decision:** vendored assets ride in the Python image via the `swagger-ui-bundle`
  PyPI package + `importlib.resources`, with `OPENAPI_SWAGGER_UI_URL` left as a local
  placeholder (`/api/docs/`) rather than deleted. Tradeoff: the key looks vestigial
  but smorest 0.47 registers `/api/docs` only when it is non-None — deleting it
  unregisters the page. Source: `backend/app/__init__.py` (placeholder),
  `flask_smorest/spec/__init__.py:100-110` (verified in blueprint), `73cd7daf`.
- **Decision:** boot-time `RuntimeError` when a `SWAGGER_ASSETS` file is missing,
  over a lazy per-request 500. Tradeoff: a pin/`_DIST_SUBDIR` drift now fails app
  boot (immediate, loud) instead of failing the first `/api/docs` request. Source:
  `cee356fd`, `backend/app/core/apidocs.py`.
- **Lesson:** the package is `swagger-ui-bundle` (module `swagger_ui_bundle`,
  files under `vendor/swagger-ui-<ver>/`), **not** `swagger-ui-dist` — that is the
  npm name and 404s on PyPI. Root cause: the blueprint was written against the npm
  name before the PyPI name was verified. A future dep add should confirm the
  distribution name on the registry before naming it in the plan. Source:
  `18c919c5` (blueprint correction note), `backend/pyproject.toml:29-32`.
- **Pattern:** serve vendored package files as `flask.Response(bytes, mimetype=...)`
  (not `send_file`) so a zipped-wheel `Traversable` is handled uniformly across the
  dev venv and the runtime image; keep the route→(filename, media-type) map as a
  single module constant read by both the handler and the tests. Source:
  `backend/app/core/apidocs.py`, `73cd7daf` skillgrid-context.
- **Surprise:** pnpm 12 (pulled by `npm install -g pnpm` on `node:20`) silently
  ignores `pnpm-workspace.yaml`'s `allowBuilds`, so the build fails with
  `ERR_PNPM_IGNORED_BUILDS`; pinning `pnpm@10` restores the honored `allowBuilds`.
  Source: session docker-build attempts (2026-10-18), `backend/Dockerfile` (uncommitted).
- **Surprise:** `ghcr.io/astral-sh/uv:latest` is not pullable in this environment's
  registry (`denied: denied`); `docker.io/astral/uv` is the Docker Hub equivalent.
  Source: session docker-build attempts, `backend/Dockerfile` (uncommitted).

## Acceptance Verdict

**accepted-with-open-items**

Goal (briefing.md): make `/api/docs` fully functional in an air gap — app-served
assets, no CDN, BearerAuth documented, page open. All truths T1–T9 verified by named
tests (QA half); final tree re-run 9/9 green. Open items below do not unmet the goal
but are named for the next change.

## Open Items (→ next change)

- **Docker image build commit** — `backend/Dockerfile` (uv-from-Docker-Hub + `pnpm@10`
  pin) is verified to build (image `kubedash-swagger-check` built successfully,
  2026-10-18) but is uncommitted, held for a separate `build(deploy)` commit.
  Path: commit it; re-run `docker build -f backend/Dockerfile .` in CI.
- **`psycopg2` test-env gap** — 17 full-suite errors (`ModuleNotFoundError: psycopg2`)
  pre-exist this change; the test DB URL uses `postgresql+psycopg2` but the driver is
  not in `pyproject.toml`/`uv.lock`. Path: add the driver to the dev dependency group
  or point the test DB at `sqlite`/`postgresql+psycopg` in conftest.
- **Merge to `main`** — the work branch is kept (Integration Rule); merging 64
  commits (this change + 60 others) into `main` is a separate explicit act.

## Prior-Change Follow-Through

- This change addressed the base-structure change's open item "Swagger UI loads
  from a public CDN at runtime" (TASK-015 / TICKET-13) — the CDN is gone, assets are
  app-served.
- Base-structure's other open items (ADR-0001..0013 file authoring, ADR decision
  copies, mnemonic code index) remain open — not addressed here, unchanged.

## Lineage

- **Observation IDs read (lineage endpoint):**
  - ship: `skillgrid/2026-10-17-swagger-ui-air-gap/ship` (observation id 1, session
    `79af7226-0dab-4a47-bb18-01d2871a006a`)
  - integration-rule decision: observation id 2, same session
  - blueprint / tasks / briefing: in-repo (not separately mem_saved in this project's
    mnemonic — `mnemonic.enabled` is true but only ship + the integration rule were
    captured; the in-repo `briefing.md`/`blueprint.md`/`report.md` are the record).
- **Review gate:** waived (small tier, no `review.md`). The one pre-merge code review
  that did run (the critic pass embedded in `blueprint.md` § Self-Review, 16 findings)
  was folded into the blueprint before implementation; the `cee356fd` boot-time guard
  is a post-QA hardening, not a review catch. No `review.md` independence grade exists.
- **Gate results (close):** Ship ✅ (move + empty `diff -r`) · QA ✅ PASS · Verdict
  (advisory) accepted-with-open-items.

## Environment Retro

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| Automated checks | CI already builds the image (`.github/workflows/ci.yaml` `image` job), yet the session spent ~4 local `docker build` iterations discovering the pnpm/`ghcr.io`-uv issues. Local iteration was the slow loop; the deterministic check already exists in CI. | No new check — lean on the existing CI `image` job; record it as the canonical Dockerfile verifier so a future session runs CI (or a single cached local build) instead of guessing. | session docker-build attempts (4 builds), `ci.yaml:48-58` |
| Coding standards (mechanical) | pnpm version is load-bearing: `npm install -g pnpm` pulls 12.x which ignores `pnpm-workspace.yaml` `allowBuilds` → `ERR_PNPM_IGNORED_BUILDS`; `pnpm@10` works. This is a fixed pin, not a judgement call. | A one-line comment in `backend/Dockerfile` (with the uncommitted deploy commit) pinning `pnpm@10` with the reason; optionally a `devDependencies`/`packageManager` field in `frontend/package.json` so the pin is version-controlled, not shell-local. | session: pnpm 12 vs 10 build diff (2026-10-18) |
| Information access | The PyPI-vs-npm package name (`swagger-ui-bundle` vs `swagger-ui-dist`) was wrong in the blueprint until verified against the registry mid-task; the correction is now in ASSUMPTIONS.md but a future dep-add plan will repeat the guess. | Add a one-line reminder to the `writing-blueprints` skill's dependency step: "confirm the distribution name on the registry (PyPI/npm) before naming it in the plan." (process file, not steering no-op) | `18c919c5` blueprint correction, `pyproject.toml:29-32` |
| Tool economy | `mnemonic mem_save` required a live `session_id`; the first call failed on a foreign-key constraint, forcing a `mem_session_start` round-trip. | `mnemonic-memory.md` rule: always `mem_session_start` (or read the active session) before the first `mem_save` of a phase. | session: `mem_save` FK failure (observation id 2) |
| Navigation | (clean) — the change's files were located quickly; no navigation trap. | — | — |
| Steering-file no-ops | (clean) — the new `## Integration Rule` in AGENTS.md is a real behaviour change (ship keeps the branch), not a no-op. | — | AGENTS.md § Integration Rule (this session) |

**Proposed follow-ups (proposed, not implemented):**
1. *(coding standards)* Add the pnpm-pin comment / `packageManager` field with the Dockerfile deploy commit — small, deterministic.
2. *(process)* Add the "confirm registry name before naming a dep in the blueprint" reminder to the `writing-blueprints` skill — prevents the next PyPI/npm name guess.

