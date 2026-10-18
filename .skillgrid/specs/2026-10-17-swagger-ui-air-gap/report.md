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
