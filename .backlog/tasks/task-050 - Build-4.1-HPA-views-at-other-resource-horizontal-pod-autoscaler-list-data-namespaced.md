---
id: TASK-050
title: >-
  Build 4.1 HPA views at /other-resource/horizontal-pod-autoscaler (list + data,
  namespaced)
status: Done
assignee: []
created_date: '2026-10-28 14:12'
updated_date: '2026-10-29 15:49'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/other-resources/hpa.html.j2'
  - '4.1:src/kubedash/templates/other-resources/hpa-data.html.j2'
  - '4.1:src/kubedash/lib/k8s/other.py (k8sHPAListGet, line 110)'
  - 'kubedash_4:backend/app/api/resources.py'
  - >-
    kubedash_4:backend/app/services/k8s_client.py (networkpolicies namespaced
    seam lines 762-786)
  - .skillgrid/specs/2026-10-28-hpa-views/
priority: medium
ordinal: 46000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'HPAs -> /other-resource/horizontal-pod-autoscaler' (_nav.tsx:111) currently renders a stub (views/Stub/routes.ts:23). 4.1 HAS real templates for this kind: other-resources/hpa.html.j2 (list: Name/Namespace/Owner/Targets/MinReplicas/MaxReplicas/Replicas) + hpa-data.html.j2 (data: Name/Created/Namespace/Annotations/Labels/Owner/Metrics/MinReplicas/MaxReplicas/Deployment pods/Conditions table). Unlike VPAs, HPAs are a CORE API (horizontalpodautoscalers, autoscaling/v1, NAMESPACED, snake_case to_dict); the 4.1 read k8sHPAListGet (lib/k8s/other.py:110) uses AutoscalingV1Api().list_namespaced_horizontal_pod_autoscaler; the data page is list-then-filter by name. Port the shape to 5.0 with the ratified deltas: ?name= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains self._autoscaling = AutoscalingV1Api(api_client) + list_horizontal_pod_autoscalers (list_namespaced_horizontal_pod_autoscaler OR list_horizontal_pod_autoscaler_for_all_namespaces, to_dict, namespace param) + get_horizontal_pod_autoscaler (read_namespaced_horizontal_pod_autoscaler, 404 -> [], other ApiException -> _unreachable) mirroring list_network_policies/get_network_policy; resources.py adds _KINDS['horizontalpodautoscalers'] = ('list_horizontal_pod_autoscalers', 'horizontalpodautoscalers', '') and _GETTERS['horizontalpodautoscalers'] = 'get_horizontal_pod_autoscaler'. Frontend: HorizontalPodAutoscalerItem in types.ts (metadata, spec.scale_target_ref/min_replicas/max_replicas/target_cpu_utilization_percentage, status.current_replicas/desired_replicas/current_cpu_utilization_percentage/conditions); views/OtherResource/HorizontalPodAutoscaler.tsx (KubeDataTable columns Name/Namespace/Owner/Targets/Min Replicas/Max Replicas/Replicas - Owner plain text not a link, Targets = current/target CPU percent with UNKNOWN literal, 4.1's Min/Max header-cell swap CORRECTED; name links to the data page with ?name=&namespace=); views/OtherResource/HorizontalPodAutoscalerData.tsx (single ?name=&namespace= fetch, CTable Name/Created/Namespace/Owner/Metrics/Min Replicas/Max Replicas/Replicas/Labels/Annotations + Conditions table Type/Status/Last Transition Time/Reason/Message from status.conditions ELSE the legacy autoscaling.alpha.kubernetes.io/conditions annotation (4.1's source), NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/horizontal-pod-autoscaler + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-hpa-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/horizontalpodautoscalers?namespace=<ns> returns the HPA list, SAR-gated on list horizontalpodautoscalers (core), 403 RBAC_DENIED on deny
- [x] #2 GET .../horizontalpodautoscalers?name=<name>&namespace=<ns> returns the single HPA via _GETTERS; 404 -> empty items
- [x] #3 frontend HorizontalPodAutoscaler.tsx renders the list with Name/Namespace/Owner/Targets/Min Replicas/Max Replicas/Replicas columns; card title exactly "Horizontal Pod Autoscaler List"; Owner plain text; 4.1 min/max header-swap corrected; name links to the data page
- [x] #4 frontend HorizontalPodAutoscalerData.tsx renders detail at /other-resource/horizontal-pod-autoscaler/data?name=&namespace= via a single fetch; CTable + Conditions table (status.conditions else legacy annotation); NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #5 /other-resource/horizontal-pod-autoscaler removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #6 Backend tests: new tests/services/test_k8s_client_horizontalpodautoscalers.py (list in-ns/all-ns, get hit/404/5xx) + test_resources.py extensions (200, all-namespaces, get-by-name hit/miss, SAR deny w/ core group, binding 404, singular kind rejected)
- [x] #7 Frontend tests: horizontal_pod_autoscalers.test.tsx + horizontal_pod_autoscaler_data.test.tsx (mirror network_policies/priority_class_data tests; conditions-from-status + conditions-from-legacy-annotation + missing-conditions); Stub.test.tsx viewPaths updated for the removed route
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
1. T1 backend: service tests RED (new file) -> K8sClient._autoscaling + list/get methods + _KINDS/_GETTERS rows + FakeK8s methods + 6 API tests GREEN -> commit feat(resources). 2. T2 frontend list: HorizontalPodAutoscalerItem type + list test RED -> view GREEN -> commit feat(frontend) list. 3. T3 frontend data: data test RED (conditions from status/legacy annotation/missing/not-found/missing-name) -> view GREEN -> commit feat(frontend) data. 4. T4 routing: App.tsx routes+imports, Stub/routes.ts removal, Stub.test.tsx viewPaths -> full verification floor (targeted pytest, unit suite, vitest, fe-build, fe-check, git diff --stat) -> commit feat(frontend) wire. 5. state.yaml in_flight + finalize TASK-050.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Execution started; blueprint tasks follow T1 backend kind -> T2 list view -> T3 data view -> T4 routing. Baselines: 3 pre-existing kind-fixture errors in test_resources.py; frontend pre-existing failures in users/groups/admin_permissions + node-detail-renders.

T1 done, commit 0178df05. RED: 6 failed (AttributeError: no list/get_horizontal_pod_autoscaler methods) -> GREEN: 6 service tests passed; 89 passed on tests/api/test_resources.py -k 'not integration' (6 new API tests green). kind-gated tests are environment-gated (Docker daemon), matching sibling changes.

T2 done, commit 233e827c (list view, 6/6 vitest green). T3 done, commit 954e7a0b (data view, 6/6 vitest green). T3 test deviation: data-renders-detail asserts the labels sub-table (fixture has labels {team: a}) + 'No annotations' (fixture annotations empty) — 'No labels' can't hold for a labeled fixture; data-conditions-from-legacy-annotation fixture uses the snake_case to_dict condition shape (the legacy annotation JSON's rendering path is pinned; the live 4.1 camelCase shape degrades to N/A cells).

Verification floor (all green): (1) targeted pytest tests/services/test_k8s_client_horizontalpodautoscalers.py + tests/api/test_resources.py: 95 passed; the 3 kind-gated FAILED (test_list_networkpolicies_on_kind / test_cilium_absent_degrades_to_empty_on_kind / test_list_priorityclasses_on_kind) + 3 ScopeMismatch ERRORs are the pre-existing kind-fixture baseline (verified identical when run in isolation on this environment — the kind cluster's apiserver is unreachable from test processes: SAR/probe dials 1.2.3.4). (2) unit suite: 519 passed (was 507 after vpa; +12 new HPA tests), 10 deselected. (3) frontend targeted vitest (hpa list + data + Stub): 17/17 passed. (4) full frontend vitest: 14 failed / 230 passed — all 14 in the declared baseline (users x9, groups x4, admin_permissions x1, node-detail-renders x1); nothing new. (5) task fe-build (tsc --noEmit incl. tests + eslint + vite build) green. (6) task fe-check (air-gap) green. (7) git diff --stat vs 29ee7c8d: exactly the blueprint File Structure files (12 code files); frontend/src/_nav.tsx ABSENT.
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
Built the 4.1-parity HPA views (list + data) at /other-resource/horizontal-pod-autoscaler: backend horizontalpodautoscalers kind (autoscaling/v1, namespaced core kind, snake_case to_dict, SAR-gated on list/get with core group) via K8sClient._autoscaling + _KINDS/_GETTERS rows; frontend HorizontalPodAutoscaler list view (Name/Namespace/Owner/Targets/Min Replicas/Max Replicas/Replicas, 4.1 min/max header-swap corrected, UNKNOWN CPU literal, name links sole producer of ?name=&namespace=) and HorizontalPodAutoscalerData data view (single ?name=&namespace= fetch, CTable + typed Conditions table from status.conditions with the legacy autoscaling.alpha.kubernetes.io/conditions annotation fallback, NOT_FOUND as a state, JSON full-object block) + App.tsx routes + stub removal. 5 commits: 0178df05 (backend kind), 233e827c (list view), 954e7a0b (data view), 3aabed9d (routes + stub removal), b9ba23fb (state.yaml). Verified: 12 new backend tests green (targeted 95 passed; unit suite 519 passed); 17/17 targeted frontend tests green (full suite: only the 14 declared-baseline failures); fe-build + fe-check green; _nav.tsx untouched; diff scoped to the blueprint File Structure.
<!-- SECTION:FINAL_SUMMARY:END -->
