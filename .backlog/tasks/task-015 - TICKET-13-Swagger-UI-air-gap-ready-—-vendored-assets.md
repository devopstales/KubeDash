---
id: TASK-015
title: 'TICKET-13: Swagger UI air-gap ready — vendored assets'
status: Done
assignee: []
created_date: '2026-10-17 19:48'
updated_date: '2026-10-18 08:09'
labels:
  - api
  - air-gap
  - docs
dependencies: []
references:
  - backend/app/__init__.py
  - .skillgrid/artifacts/04-adr-0020-air-gap-deployment.md
priority: medium
type: feature
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Swagger UI at /api/docs is wired but loads its assets from a public CDN (backend/app/__init__.py sets OPENAPI_SWAGGER_UI_URL to cdn.jsdelivr.net/.../swagger-ui-bundle.js). In an air-gapped environment (ADR-0020: zero outbound calls at runtime) that <script src> is a runtime egress dependency the UI silently relies on, and it breaks when the site has no internet. Make the Swagger UI assets local and served by the app, driven by a config flag, so the UI renders identically with or without internet.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Swagger UI assets are vendored into the image (PyPI swagger-ui-bundle) and served locally by the app on /api/docs/*, no runtime fetch from a CDN or any external host
- [x] #2 Assets are always app-served (no KUBEDASH_SWAGGER_CDN toggle — blueprint decision, supersedes the earlier 'CDN vs local flag' wording; OPENAPI_SWAGGER_UI_URL is a local placeholder that keeps the route registered)
- [x] #3 GET /api/docs renders the Swagger UI and loads its bundle from the app (no external script src in the page)
- [x] #4 GET /api/openapi.json still returns valid OpenAPI 3 and declares the BearerAuth JWT security scheme
- [x] #5 Tests assert the /api/docs response references the locally-served bundle, the served bundle is byte-identical to the vendored package, and no cdn.jsdelivr.net reference remains
- [x] #6 Dockerfile (backend/Dockerfile) picks up the vendored assets via uv sync --frozen (no new COPY); image build verification deferred — registry auth for ghcr.io/astral-sh/uv unavailable in this environment
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Executed 2026-10-17/18 (subagent-driven). Final state: 9/9 apidocs tests green; full suite 132 passed (17 pre-existing env-block errors, no regression); ruff + mypy --strict clean. QA gate PASS (report.md). Final whole-branch review GO + fix commit cee356fd (boot-time RuntimeError on missing vendored asset; direct endpoint assert in route test) + scoped re-review CLEAN. Commits: 73cd7daf (task1) 3d2a9a0a (task2) 18c919c5 (blueprint pkg correction) 07ab0db3 (QA PASS) 10324d64 (state->qa) cee356fd (final fix) f5ef351a (ASSUMPTIONS VERIFIED). Package is PyPI swagger-ui-bundle (not swagger-ui-dist, which is npm-only).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Made /api/docs fully functional in an air gap: Swagger UI assets are always served locally from the vendored swagger-ui-bundle PyPI package (importlib.resources on /api/docs/* routes, no CDN), and the OpenAPI spec declares a BearerAuth JWT security scheme (page stays open). Verified with 9 focused tests (byte-identical bundle, no-CDN page, open page, idempotent scheme guard, paths-superset golden baseline), the full backend suite, ruff + mypy --strict, a goal-backward runtime probe, and a two-stage review (QA PASS + final review GO, fix commit re-reviewed CLEAN).
<!-- SECTION:FINAL_SUMMARY:END -->
