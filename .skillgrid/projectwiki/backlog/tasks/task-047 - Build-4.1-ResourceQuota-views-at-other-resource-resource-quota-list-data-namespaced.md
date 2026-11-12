---
id: TASK-047
title: >-
  Build 4.1 ResourceQuota views at /other-resource/resource-quota (list + data,
  namespaced)
status: Done
assignee: []
created_date: '2026-10-28 12:35'
updated_date: '2026-10-29 15:49'
labels:
  - feature
dependencies: []
references:
  - '4.1:src/kubedash/templates/other-resources/resource-quota.html.j2'
  - '4.1:src/kubedash/templates/other-resources/resource-quota-data.html.j2'
  - '4.1:src/kubedash/lib/k8s/other.py (k8sQuotaListGet'
  - line 203)
  - 'kubedash_4:backend/app/api/resources.py'
  - .skillgrid/specs/2026-10-28-resourcequota-views/
priority: medium
ordinal: 43000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'Resource Quota -> /other-resource/resource-quota' (_nav.tsx:114) currently renders a stub (views/Stub/routes.ts:26). 4.1 HAS real templates for this kind (unlike RuntimeClass): other-resources/resource-quota.html.j2 (list: Name/Namespace/Request/Limit) + resource-quota-data.html.j2 (data: Name/Created/Namespace/Creation/Selectors/Scopes/Annotations/Labels/Status table) + k8sQuotaListGet (lib/k8s/other.py:203, CoreV1Api, NAMESPACED — session ns_select). Port the shape to 5.0 with the ratified deltas: ?name= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains list_resource_quotas (CoreV1Api list_namespaced_resource_quota OR list_resource_quota_for_all_namespaces, to_dict, namespace param) + get_resource_quotas (read_namespaced_resource_quota, 404 -> [], other ApiException -> _unreachable) mirroring list_secrets/get_secret; resources.py adds _KINDS['resourcequotas'] = ('list_resource_quotas', 'resourcequotas', '') and _GETTERS['resourcequotas'] = 'get_resource_quotas'. Frontend: ResourceQuotaItem in types.ts (metadata, spec.scopes, spec.scope_selector, status.hard, status.used); views/OtherResource/ResourceQuota.tsx (KubeDataTable columns Name/Namespace/Requests/Limits/Created — Request & Limit cells show requests.cpu, requests.memory, limits.cpu, limits.memory as used/hard, missing keys render as em dash; name links to the data page with ?name=&namespace=); views/OtherResource/ResourceQuotaData.tsx (single ?name=&namespace= fetch, CTable Name/Created/Namespace/Scope/Labels/Annotations/Status table, NOT_FOUND as a state 'No ResourceQuota '<name>' found', full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/resource-quota + /other-resource/resource-quota/data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-resourcequota-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns> returns the quota list for that namespace, SAR-gated on list resourcequotas (core, group ''), 403 RBAC_DENIED on deny; without a namespace param the list spans all namespaces
- [x] #2 GET /api/v1/clusters/<id>/resources/resourcequotas?name=<name>&namespace=<ns> returns the single ResourceQuota via _GETTERS; 404 -> empty items
- [x] #3 frontend ResourceQuota.tsx renders the list with Name/Namespace/Requests/Limits/Created columns; Request and Limit cells show requests.cpu, requests.memory, limits.cpu, limits.memory as used/hard (missing -> em dash); card title exactly 'Resource Quota List'; name links to the data page
- [x] #4 frontend ResourceQuotaData.tsx renders detail at /other-resource/resource-quota/data?name=&namespace= via a single fetch; CTable Name/Created/Namespace/Scope/Labels/Annotations + Status table (Resource/Used/Hard Limit); NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #5 /other-resource/resource-quota removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #6 Backend tests: tests/services/test_k8s_client_resourcequotas.py (namespaced list, all-ns list, get hit/404/5xx) + test_resources.py extensions (200, namespace scoping, get-by-name, SAR deny, binding 404, singular kind rejected)
- [x] #7 Frontend tests: resource_quotas.test.tsx + resource_quota_data.test.tsx (mirror network_policies / priority_class_data patterns); Stub.test.tsx updated
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
## Implementation plan — /other-resource/resource-quota (4.1 port, TASK-047)

Spec zone complete: .skillgrid/specs/2026-10-28-resourcequota-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: resourcequotas kind (core, namespaced, SAR-gated)
- k8s_client.py: list_resource_quotas(namespace: str|None) (list_namespaced_resource_quota OR list_resource_quota_for_all_namespaces, to_dict, _unreachable on ApiException) + get_resource_quota(namespace, name) (read_namespaced_resource_quota, 404 -> [], else _unreachable). No __init__ change (self._v1 exists).
- resources.py: _KINDS["resourcequotas"] = ("list_resource_quotas", "resourcequotas", "") + _GETTERS["resourcequotas"] = "get_resource_quota" — both rows land in the same commit as the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_resourcequotas.py (6 tests, object.__new__ + SimpleNamespace, mirror secrets) + test_resources.py (FakeK8s methods + 6 tests: 200-in-ns, all-namespaces w/o param, get-by-name hit/miss, SAR denied w/ asked-assertion, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): resourcequotas kind (core, namespaced, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: ResourceQuotaItem (metadata, spec.scopes/scope_selector, status.hard/used).
- views/OtherResource/ResourceQuota.tsx: KubeDataTable; namespace = useClusterStore.selectedNamespace ?? 'default' (NetworkPolicy pattern); card title EXACTLY 'Resource Quota List'; columns Name(link)/Namespace/Requests/Limits/Created; cell = '<key>: <used> / <hard>' with '—' for missing keys (certainty rule, 4.1 would KeyError); name link is the SOLE producer of ?name=&namespace= (row's OWN namespace); fetch /api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns>; pinned states (No cluster selected. / Loading resource quotas... / No resource quotas found).
- Test: resource_quotas.test.tsx (clone network_policies.test.tsx pattern; fetch URL exact, cell contents, missing-key dashes, empty/error/no-cluster states).
- Commit: feat(frontend): resource quota list view (4.1 port, namespaced)

### T3 — Frontend: data view (independent of T2 after T1)
- views/OtherResource/ResourceQuotaData.tsx: clone PriorityClassData.tsx; single ?name=&namespace= fetch (query enabled on cluster+name+namespace); CTable Name/Created/Namespace/Scope/Labels/Annotations; Status table Resource/Used/Hard Limit over 4.1's four dims in 4.1's order (limits.cpu, limits.memory, requests.cpu, requests.memory) with '—' for missing; full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No ResourceQuota '<name>' found' (not error); missing name = 'Error: resource quota name not provided'.
- Test: resource_quota_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion, status table rows, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): resource quota data view (4.1 tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block).
- Stub/routes.ts: drop line 26; Stub.test.tsx: drop the Resource Quota expectation. _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire resource-quota routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) data view must treat items:[] as not-found state, not error; (3) pinned copy is verbatim (e2e smoke contract: 'Resource Quota List'); (4) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 done (commit 783cff0a): service methods + _KINDS/_GETTERS rows + 12 tests green (6 service + 6 API); 3 kind-fixture E's are the known ScopeMismatch baseline. Kind-tier suite hangs at process exit (teardown dial) as warned — summary is the evidence.

T2 done (commit 14d8af2b): ResourceQuotaItem + list view + 6 tests green; fe-build (tsc+lint+build) green. Fake needed the datatables.net-react slotRenderer contract (2-arg fn gets (data,row); Name uses data={null} whole-row like NetworkPolicy since the link needs the row's own namespace).

T3 done (commit 3acac8dc): data view + 4 tests green; fe-build green. Deviation: JSON-block assertion polls container.textContent (highlighter splits tokens) — the proven priorityclass pattern, not pre.textContent per blueprint letter.

Verification summary (2026-10-28): (AC1/AC2/AC6) backend targeted: uv run pytest tests/services/test_k8s_client_resourcequotas.py tests/api/test_resources.py -q → 74 passed + 3 known kind-fixture baseline errors (ScopeMismatch, pre-existing). (AC6) full unit: uv run pytest -m 'not integration' -q → 483 passed, 10 deselected, 0 failed (baseline was 471). (AC3/AC4/AC7) frontend targeted: pnpm vitest run resource_quotas + resource_quota_data + Stub → 15/15 passed. (AC5) full vitest: only baseline failures remain (users/groups/admin_permissions + node.node-detail-renders); fe-build (tsc --noEmit incl. test files + eslint + vite) green; fe-check air-gap green; git diff --stat vs cab0e37a: _nav.tsx absent, no file outside the blueprint File Structure (the other diff entries are unrelated sibling spec/backlog files, never staged).
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
4.1 ResourceQuota views shipped as a real, SAR-gated, read-only list + data pair under /other-resource/resource-quota. 4 commits on rebase, each independently revertable: T1 backend resourcequotas kind (core, namespaced, _KINDS+_GETTERS, 783cff0a); T2 list view ResourceQuota.tsx + ResourceQuotaItem (14d8af2b); T3 data view ResourceQuotaData.tsx (4.1 tables + JSON block) (d3d4067d); T4 App.tsx routes + stub removal (0b3b97bf). Verification floor: backend unit 483 passed / 0 failed; frontend targeted 15/15; full vitest at baseline; fe-build + fe-check green; _nav.tsx untouched. Deviations from blueprint (recorded, all in-favor): (a) KubeDataTable fake mirrors datatables.net-react's real slotRenderer contract (2-arg slot fn gets (data, row); Name column uses data={null} whole-row like NetworkPolicy, since the link needs the row's own namespace) — a blueprint clone of the network_policies fake would render an empty Name cell; (b) data-view JSON-block assertions poll container.textContent because the hljs highlighter splits tokens across spans (the proven priority_class_data pattern). Handoff: QA gate + code review are the orchestrator's; the change follows the secrets/networkpolicies namespaced-kind precedent end to end.
<!-- SECTION:FINAL_SUMMARY:END -->
