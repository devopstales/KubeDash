---
id: TASK-063
title: 'Fix: /api/docs renders empty - swagger inline script blocked by ADR-0026 CSP'
status: Done
assignee: []
created_date: '2026-11-04 10:57'
updated_date: '2026-11-04 11:14'
labels: []
dependencies: []
ordinal: 59000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR-0026 (shipped 2026-10-24-tls-security-headers) restored the per-request nonce CSP on every response (script-src 'self' 'nonce-...', no unsafe-inline). app/templates/swagger_ui.html — the only inline script the app serves (the swagger config script) — was never wired to the nonce, so browsers block it: /api/docs renders an empty #swagger-ui-container (window.ui undefined). Reported by the user 2026-11-04 as a CSP console violation; a JSON.parse "line 1 column 1" in the same paste is from tooling that parsed an HTML document as JSON (all app JSON.parse are guarded).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The /api/docs inline script carries a nonce attribute equal to the nonce in the response CSP header (regression test in tests/api/test_apidocs.py)
- [x] #2 In a real browser the Swagger UI renders the spec at /api/docs with no CSP console violation
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add nonce="{{ g.csp_nonce }}" to the inline script in backend/app/templates/swagger_ui.html (the per-request nonce from ADR-0026's before_request hook, same request context as the after_request header). 2. Regression test in tests/api/test_apidocs.py: the inline script's nonce attribute must equal the nonce in the response CSP header. 3. Verify in a real browser (Playwright against :8080): no CSP console violation, window.ui defined, spec operations render. 4. Backend unit floor (uv run pytest -m 'not integration').
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Verification: tests/api/test_apidocs.py::test_docs_page_inline_script_carrys_response_nonce green (18/18 apidocs+security headers; full backend floor 551 passed, was 550). Real browser (Playwright vs :8080): before fix - CSP console violation, window.ui undefined, #swagger-ui-container 0 children; after fix - 0 console events, window.ui object, 66 operation sections rendered (KubeDash API v1 OAS3 /api/openapi.json). g.csp_nonce absent renders an empty nonce attr (no 500) - verified with render_template_string. Live dev stack needed a gunicorn HUP (master 3172) to refresh the worker template cache; fix is template-only, no config change.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added nonce="{{ g.csp_nonce }}" to the inline swagger config script in backend/app/templates/swagger_ui.html - the per-request ADR-0026 nonce (before_request) now matches the after_request CSP header in the same request context. Regression test asserts the script nonce equals the response CSP nonce. Verified in a real browser: /api/docs renders the full spec (66 operations) with a clean console.
<!-- SECTION:FINAL_SUMMARY:END -->
