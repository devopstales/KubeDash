---
id: TASK-054
title: >-
  Build 4.1 LimitRange views at /other-resource/limit-range (list + data,
  namespaced)
status: Done
assignee:
  - '@implementer'
created_date: '2026-10-29 12:04'
updated_date: '2026-10-29 15:49'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-limitrange-views/
  - '4.1:src/kubedash/templates/other-resources/limit-range.html.j2'
  - '4.1:src/kubedash/templates/other-resources/limit-range-data.html.j2'
priority: medium
type: feature
ordinal: 50000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'Limit Range -> /other-resource/limit-range' (_nav.tsx:115) currently renders a stub (views/Stub/routes.ts). 4.1 HAS both templates for Limit Range: other-resources/limit-range.html.j2 (list) + limit-range-data.html.j2 (data with the Container Limits table). Port the 4.1 shape to 5.0 with the ratified deltas: ?name=&namespace= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains list_limit_ranges (CoreV1Api.list_namespaced_limit_range OR list_limit_range_for_all_namespaces, to_dict, namespace param) + get_limit_range (read_namespaced_limit_range, 404 -> [], other ApiException -> _unreachable) mirroring list_secrets/get_secret; resources.py adds _KINDS['limitranges'] = ('list_limit_ranges', 'limitranges', '') and _GETTERS['limitranges'] = 'get_limit_range'. Frontend: LimitRangeItem in types.ts (metadata, spec.limits[].type/max/min/default/defaultRequest, hard); views/OtherResource/LimitRange.tsx (KubeDataTable, name links to the data page with ?name=&namespace=); views/OtherResource/LimitRangeData.tsx (single ?name=&namespace= fetch, CTable + Container Limits table + hard-limits table, NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/limit-range + /data; remove the stub route; _nav.tsx leaf unchanged. Spec (briefing/blueprint/acceptance/adr) authored at /Users/paladm/.opencode/plan/limitrange-spec/ - copy it to .skillgrid/specs/2026-10-28-limitrange-views/ and commit it in a separate spec-zone commit BEFORE any code commit (zone guard). Full spec: .skillgrid/specs/2026-10-28-limitrange-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/limitranges?namespace=<ns> returns the LimitRange list, SAR-gated on list limitranges (core), 403 RBAC_DENIED on deny
- [x] #2 GET .../limitranges?name=<name>&namespace=<ns> returns the single LimitRange via _GETTERS; 404 -> empty items
- [x] #3 frontend LimitRange.tsx renders the list with the 4.1-port columns; name links to the data page with ?name=&namespace=
- [x] #4 frontend LimitRangeData.tsx renders detail at /other-resource/limit-range/data?name=&namespace= via a single fetch; CTable + Container Limits table; NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #5 /other-resource/limit-range removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #6 Backend tests: new tests/services/test_k8s_client_limitranges.py (list in-ns/all-ns, get hit/404/5xx) + test_resources.py extensions (200, namespace threading, get-by-name hit/miss, SAR deny w/ core group, binding 404, singular kind rejected)
- [x] #7 Frontend tests: limit_ranges.test.tsx + limit_range_data.test.tsx (mirror network_policies/priority_class_data tests); Stub.test.tsx updated for the removed route
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Commit spec to .skillgrid/specs/2026-10-28-limitrange-views/ (spec-zone commit). 2. T1 backend: k8s_client list_limit_ranges/get_limit_range + _KINDS/_GETTERS rows + service tests + API tests (TDD). 3. T2 list view LimitRange.tsx + LimitRangeItem type + limit_ranges.test.tsx (TDD). 4. T3 data view LimitRangeData.tsx + limit_range_data.test.tsx (TDD). 5. T4 routing: App.tsx routes, remove stub route, Stub.test.tsx, e2e ui-smoke move. 6. Full verification floor (backend unit suite, vitest, fe-build, fe-check, git diff --stat). 7. state.yaml in_flight entry + finalize TASK-054.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All 4 tasks executed (commits: spec d8ba964d, backend aadef0d5, list view 38e16aaf, data view fdb8ca33, routing 2a6e478b). Verification floor: backend unit suite running; vitest 16/16 targeted (limit_ranges 5, limit_range_data 6, Stub 5); fe-build green (tsc+eslint+vite); fe-check green; git diff --stat clean (_nav.tsx absent).
<!-- SECTION:NOTES:END -->

## Comments

<!-- COMMENTS:BEGIN -->
author: orchestrator
created: 2026-10-29 15:49
---
REVIEW FIX 2026-10-29 (batch review, REVIEW-PASS-WITH-FIXES): F1 fixed in 251e0c7b - LimitRangeData Created cell now uses formatTimestamp (was raw ISO; briefing R4 + all four sibling data views require it; dropped the dead 'N/A' fallback since formatTimestamp returns the em-dash certainty sentinel for absent values; no-raw-ISO-T test assertion added, RED->GREEN). F2 fixed in 98613f68 - VPA data bounds(): present-but-empty minAllowed/maxAllowed object now renders the em dash, N/A is reserved for absent bounds (RED->GREEN, absent case still N/A). Parked as follow-ups: F3 (two KubeDataTable Name-column conventions coexist in the batch - unify), F4 (PDB unhealthy_pod_eviction_policy typed as string, k8s >=1.29 is []string - spec/code normalization follow-up), F5 rides parked W008/W009 (e2e SMOKE_STUB_ROUTES still lists 4 of the 6 kinds + stale priorityclass entry).
---
<!-- COMMENTS:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Built 4.1-parity LimitRange views at /other-resource/limit-range (list + data, namespaced, core group). 4 code commits on rebase: backend limitranges kind (aadef0d5: k8s_client list/get + _KINDS/_GETTERS, SAR-gated on core group with namespace threading), list view (38e16aaf: LimitRange.tsx + LimitRangeItem type, 4.1 Name/Namespace/Created columns, selected-namespace fetch, data links), data view (fdb8ca33: LimitRangeData.tsx, single ?name=&namespace= fetch, metadata CTable + Container Limits table iterated by spec.limits[] type + JSON hljs block, NOT_FOUND as pinned state), routing (2a6e478b: App.tsx routes, stub route removed, e2e ui-smoke moved to REAL_ROUTES; stale priorityclass stub entry left for TASK-046 follow-up per blueprint). Spec committed first in spec-zone commit d8ba964d. Verified: backend unit suite 532 passed (not integration); targeted API tests 96 passed in test_resources.py (7 new); service tests 6 passed in test_k8s_client_limitranges.py; vitest 16/16 targeted (limit_ranges 5, limit_range_data 6, Stub 5); full vitest failures are exactly the pre-change baseline (users 7, groups 4, admin_permissions 1, node 1); task fe-build green (tsc --noEmit incl. test files + eslint + vite build); task fe-check green (air-gap); git diff --stat vs d8ba964d touches only the 13 blueprint files (frontend/src/_nav.tsx absent). TDD per task: RED (missing module/methods) before each implementation, GREEN after. Deviations from blueprint: (1) test fixture uses snake_case default_request/max_limit_request_ratio keys to match the real kubernetes to_dict serialization (blueprint's own service FakeK8s also shows camelCase in one place — the API returns to_dict snake_case); (2) data test 'data-limits-table' asserts the Pod row's None cells via tr lookup instead of table:last-of-type (that selector matched the JSON pre block).
<!-- SECTION:FINAL_SUMMARY:END -->
