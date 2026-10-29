---
id: TASK-048
title: >-
  Build 4.1 PodDisruptionBudget views at /other-resource/pod-disruption-budget
  (list + data, namespaced)
status: Done
assignee: []
created_date: '2026-10-28 13:27'
updated_date: '2026-10-29 15:49'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/other-resources/pod-disruption-budget.html.j2'
  - >-
    4.1:src/kubedash/templates/other-resources/pod-disruption-budget-data.html.j2
  - '4.1:src/kubedash/lib/k8s/other.py (k8sPodDisruptionBudgetListGet, line 153)'
  - 'kubedash_4:backend/app/api/resources.py'
  - .skillgrid/specs/2026-10-28-pdb-views/
priority: medium
ordinal: 44000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'Pod Disruption Budget -> /other-resource/pod-disruption-budget' (_nav.tsx:113) currently renders a stub (views/Stub/routes.ts:25). 4.1 HAS real templates for this kind: other-resources/pod-disruption-budget.html.j2 (list: Name/Namespace/Min Available/Max Unavailable/Allowed Disruptions) + pod-disruption-budget-data.html.j2 (data: Name/Created/Namespace/Creation/Annotations/Labels/Selector/Eviction Policy/Status/Conditions table) + k8sPodDisruptionBudgetListGet (lib/k8s/other.py:153, PolicyV1Api, NAMESPACED policy/v1 - session ns_select). Port the shape to 5.0 with the ratified deltas: ?name= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains self._policy = PolicyV1Api(api_client) + list_pod_disruption_budgets (list_namespaced_pod_disruption_budget OR list_pod_disruption_budget_for_all_namespaces, to_dict, namespace param) + get_pod_disruption_budget (read_namespaced_pod_disruption_budget, 404 -> [], other ApiException -> _unreachable) mirroring list_secrets/get_secret; resources.py adds _KINDS['poddisruptionbudgets'] = ('list_pod_disruption_budgets', 'poddisruptionbudgets', 'policy') and _GETTERS['poddisruptionbudgets'] = 'get_pod_disruption_budget'. Frontend: PodDisruptionBudgetItem in types.ts (metadata, spec.min_available/max_unavailable/selector.match_labels/unhealthy_pod_eviction_policy, status.disruptions_allowed/current_healthy/desired/conditions); views/OtherResource/PodDisruptionBudget.tsx (KubeDataTable columns Name/Namespace/Min Available/Max Unavailable/Allowed Disruptions - exactly one of min/max is set, the absent one and a missing status render em dash; name links to the data page with ?name=&namespace=); views/OtherResource/PodDisruptionBudgetData.tsx (single ?name=&namespace= fetch, CTable Name/Created/Namespace/Selector/Eviction Policy/Labels/Annotations + Status table Key/Value + Conditions table Type/Status/Reason/Message, NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/pod-disruption-budget + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-pdb-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/poddisruptionbudgets?namespace=<ns> returns the PDB list, SAR-gated on list poddisruptionbudgets (policy), 403 RBAC_DENIED on deny
- [x] #2 GET .../poddisruptionbudgets?name=<name>&namespace=<ns> returns the single PDB via _GETTERS; 404 -> empty items
- [x] #3 frontend PodDisruptionBudget.tsx renders the list with Name/Namespace/Min Available/Max Unavailable/Allowed Disruptions columns; card title exactly "Pod Disruption Budget List"; name links to the data page
- [x] #4 frontend PodDisruptionBudgetData.tsx renders detail at /other-resource/pod-disruption-budget/data?name=&namespace= via a single fetch; CTable + Status + Conditions tables; NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #5 /other-resource/pod-disruption-budget removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #6 Backend tests: new tests/services/test_k8s_client_poddisruptionbudgets.py (list in-ns/all-ns, get hit/404/5xx) + test_resources.py extensions (200, all-namespaces, get-by-name hit/miss, SAR deny w/ group policy, binding 404, singular kind rejected)
- [x] #7 Frontend tests: pod_disruption_budgets.test.tsx + pod_disruption_budget_data.test.tsx (mirror network_policies/priority_class_data tests); Stub.test.tsx viewPaths updated for the removed route
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
## Implementation plan — /other-resource/pod-disruption-budget (4.1 port, TASK-048)

Spec zone complete: .skillgrid/specs/2026-10-28-pdb-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: poddisruptionbudgets kind (policy, namespaced, SAR-gated)
- k8s_client.py: __init__ gains self._policy = PolicyV1Api(api_client) (next to self._node); list_pod_disruption_budgets(namespace: str|None) (list_namespaced_pod_disruption_budget OR list_pod_disruption_budget_for_all_namespaces, to_dict, _unreachable on ApiException) + get_pod_disruption_budget(namespace, name) (read_namespaced_pod_disruption_budget, 404 -> [], else _unreachable). Mirror list_secrets/get_secret.
- resources.py: _KINDS["poddisruptionbudgets"] = ("list_pod_disruption_budgets", "poddisruptionbudgets", "policy") + _GETTERS["poddisruptionbudgets"] = "get_pod_disruption_budget" — both rows land with the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_poddisruptionbudgets.py (6 tests, object.__new__ + SimpleNamespace) + test_resources.py (FakeK8s methods + 6 tests: 200-in-ns, all-namespaces w/o param, get-by-name hit/miss, SAR denied w/ ("list","poddisruptionbudgets","team-a",None,"policy") in asked, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): poddisruptionbudgets kind (policy, namespaced, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: PodDisruptionBudgetItem (metadata, spec.min_available/max_unavailable/selector.match_labels/unhealthy_pod_eviction_policy, status.disruptions_allowed/current_healthy/desired/conditions).
- views/OtherResource/PodDisruptionBudget.tsx: KubeDataTable; namespace = useClusterStore.selectedNamespace ?? 'default' (NetworkPolicy pattern); card title EXACTLY 'Pod Disruption Budget List'; columns Name(link)/Namespace/Min Available/Max Unavailable/Allowed Disruptions; exactly one of min/max is set -> the absent one is '—'; status.disruptions_allowed '—' when status absent (fresh PDB, 4.1 would UndefinedError); name link is the SOLE producer of ?name=&namespace= (row's OWN namespace); fetch /api/v1/clusters/<id>/resources/poddisruptionbudgets?namespace=<ns>; pinned states.
- Test: pod_disruption_budgets.test.tsx (clone network_policies.test.tsx pattern; fetch URL exact, min/max cell contents, missing-status dash, empty/error/no-cluster states).
- Commit: feat(frontend): pod disruption budget list view (4.1 port, namespaced)

### T3 — Frontend: data view (independent of T2 after T1)
- views/OtherResource/PodDisruptionBudgetData.tsx: clone PriorityClassData.tsx; single ?name=&namespace= fetch (query enabled on cluster+name+namespace); CTable Name/Created/Namespace/Selector(match_labels key:value)/Eviction Policy/Labels/Annotations; Status table Key/Value (Allowed disruptions/Current healthy/Desired from to_dict status.desired, no client-side floor math) with '—' for missing; Conditions table Type/Status/Reason/Message (No conditions when empty); full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No PodDisruptionBudget '<name>' found' (not error); missing name = 'Error: pod disruption budget name not provided'.
- Test: pod_disruption_budget_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion, status+conditions rows, selector/eviction-policy rows, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): pod disruption budget data view (4.1 tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block, after line 381) + two imports (after line 48).
- Stub/routes.ts: drop line 25; Stub.test.tsx: add '/other-resource/pod-disruption-budget' to the viewPaths set in expectedStubs() (the test derives expected stubs from nav minus viewPaths — without it the removed route is RED). _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire pod-disruption-budget routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) data view must treat items:[] as not-found state, not error (NOT_FOUND-throw pattern); (3) the k8s API enforces exactly one of min_available/max_unavailable — the absent one is '—'; (4) a fresh PDB has NO status (controller fills it) — 4.1's Jinja 3.1.6 UndefinedErrors (verified against the 4.1 venv), 5.0 renders '—'; (5) Spec 'Desired' uses to_dict status.desired (the controller-computed value), no client-side ceil(maxUnavailable) math; (6) card title is verbatim (e2e-smoke contract); (7) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 done (5f1f9244): backend kind green — service tests 6/6 RED->GREEN; test_resources.py unit tier 77 passed, 6 deselected (kind tier = 3 baseline errors).

T2 done (7a1ab3a5): list view green — 6/6 RED->GREEN.

T3 done (305a44c6): data view green — 5/5 RED->GREEN.

T4 done (7b3e35be): routes wired, stub removed, Stub.test.tsx updated. state.yaml updated (1a510cb4).
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
Implemented the 4.1 PodDisruptionBudget view pair (list + data, namespaced, policy/v1) as a real, SAR-gated, read-only pair under Other Resources. 4 commits on rebase: backend poddisruptionbudgets kind (5f1f9244), list view (7a1ab3a5), data view (305a44c6), routes + stub removal (7b3e35be). Verification: backend unit suite 495 passed (483 baseline + 12 new); frontend targeted vitest 16/16 (list 6 + data 5 + Stub 5); task fe-build green; task fe-check green; _nav.tsx untouched. Awaits QA gate + code review (orchestrator).
<!-- SECTION:FINAL_SUMMARY:END -->
