---
id: TASK-049
title: >-
  Build 4.1 VPA views at /other-resource/vertical-pod-autoscaler (list + data,
  namespaced CRD)
status: Done
assignee: []
created_date: '2026-10-28 13:45'
updated_date: '2026-10-29 15:49'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/other-resources/vpa.html.j2'
  - '4.1:src/kubedash/templates/other-resources/vpa-data.html.j2'
  - >-
    4.1:src/kubedash/lib/k8s/other.py (k8sVPAListGet line 50,
    get_vpa_crd_version line 17)
  - 'kubedash_4:backend/app/api/resources.py'
  - >-
    kubedash_4:backend/app/services/k8s_client.py (Cilium CRD seam lines
    667-734)
  - .skillgrid/specs/2026-10-28-vpa-views/
priority: medium
ordinal: 45000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'VPAs -> /other-resource/vertical-pod-autoscaler' (_nav.tsx:112) currently renders a stub (views/Stub/routes.ts:24). 4.1 HAS real templates for this kind: other-resources/vpa.html.j2 (list: Name/Namespace/Target Kind/Target Name/Update Mode/Min Memory/Max Memory/Creation Timestamp) + vpa-data.html.j2 (data: Name/Created/Namespace/Annotations/Labels/Target (Owner)/Update Mode/Container Policies/Conditions). Unlike the core kinds, VPAs are a CRD (verticalpodautoscalers.autoscaling.k8s.io, autoscaling.k8s.io group, NAMESPACED); the 4.1 read k8sVPAListGet (lib/k8s/other.py:50) resolves the CRD served+storage version at runtime (get_vpa_crd_version line 17) then CustomObjectsApi().list_namespaced_custom_object; the data page is list-then-filter by name. Port the shape to 5.0 via the CILIUM full-custom-object seam (get_crd_served authority, CRD-absent -> [] as a first-class empty state, full object spec+status intact, camelCase) with the ratified deltas: ?name= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains list_vertical_pod_autoscalers (get_crd_served None -> [], else list_namespaced/list_cluster_custom_object, _crd_body, to_dict) + get_vertical_pod_autoscaler (get_namespaced_custom_object, 404/absent -> [], other ApiException -> _unreachable) mirroring list_cilium_network_policies/get_cilium_network_policy; resources.py adds _KINDS['verticalpodautoscalers'] = ('list_vertical_pod_autoscalers', 'verticalpodautoscalers', 'autoscaling.k8s.io') and _GETTERS['verticalpodautoscalers'] = 'get_vertical_pod_autoscaler'. Frontend: VerticalPodAutoscalerItem in types.ts (camelCase custom object: metadata, spec.targetRef/updatePolicy/resourcePolicy.containerPolicies, status.conditions); views/OtherResource/VerticalPodAutoscaler.tsx (KubeDataTable columns Name/Namespace/Target Kind/Target Name/Update Mode/Min Memory/Max Memory/Created - Target Name plain text not a link, Min/Max Memory the LAST container's minAllowed/maxAllowed.memory via 4.1 {% set %} overwrite, N/A literals; name links to the data page with ?name=&namespace=); views/OtherResource/VerticalPodAutoscalerData.tsx (single ?name=&namespace= fetch, CTable Name/Created/Namespace/Target (Owner)/Update Mode/Labels/Annotations + Container Policies table Container Name/Controlled Values/Mode/Min Allowed/Max Allowed/Controlled Resources + Conditions table Type/Status/Last Transition Time/Reason/Message from status.conditions NOT 4.1's dead top-level conditions, NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/vertical-pod-autoscaler + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-vpa-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/verticalpodautoscalers?namespace=<ns> returns the VPA list as full custom objects (spec+status intact, camelCase), SAR-gated on list verticalpodautoscalers (autoscaling.k8s.io), 403 RBAC_DENIED on deny
- [x] #2 GET .../verticalpodautoscalers?name=<name>&namespace=<ns> returns the single full VPA via _GETTERS; 404/CRD-absent -> empty items
- [x] #3 CRD absent (operator not installed) -> items == [] 200 (a state, not an error) - the get_crd_served None -> [] contract
- [x] #4 frontend VerticalPodAutoscaler.tsx renders the list with Name/Namespace/Target Kind/Target Name/Update Mode/Min Memory/Max Memory/Created columns; card title exactly "Vertical Pod Autoscaler List"; Target Name plain text; name links to the data page
- [x] #5 frontend VerticalPodAutoscalerData.tsx renders detail at /other-resource/vertical-pod-autoscaler/data?name=&namespace= via a single fetch; CTable + Container Policies + Conditions (status.conditions) tables; NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #6 /other-resource/vertical-pod-autoscaler removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #7 Backend tests: new tests/services/test_k8s_client_verticalpodautoscalers.py (list in-ns/all-ns, CRD-absent empty, get hit/404/5xx) + test_resources.py extensions (200 full-object, all-namespaces, get-by-name hit/miss, SAR deny w/ group autoscaling.k8s.io, binding 404, singular kind rejected)
- [x] #8 Frontend tests: vertical_pod_autoscalers.test.tsx + vertical_pod_autoscaler_data.test.tsx (mirror network_policies/priority_class_data tests); Stub.test.tsx viewPaths updated for the removed route
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
## Implementation plan — /other-resource/vertical-pod-autoscaler (4.1 CRD port, TASK-049)

Spec zone complete: .skillgrid/specs/2026-10-28-vpa-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

KEY: VPA is a CRD (verticalpodautoscalers.autoscaling.k8s.io, namespaced). This is the CILIUM full-custom-object seam, NOT the list_secrets core pattern: get_crd_served authority, CRD-absent -> [] (first-class empty), full object (spec+status intact), camelCase wire form.

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: verticalpodautoscalers kind (CRD, full object, SAR-gated)
- k8s_client.py (next to the Cilium methods ~line 715): _VPA_GROUP="autoscaling.k8s.io" + _VPA_PLURAL="verticalpodautoscalers" module constants; list_vertical_pod_autoscalers(namespace) (get_crd_served None -> []; else list_namespaced/list_cluster_custom_object branch, _crd_body, to_dict, _unreachable on ApiException) + get_vertical_pod_autoscaler(namespace, name) (get_crd_served None -> []; get_namespaced_custom_object, 404 -> [], else _unreachable). NO new __init__ attribute (self._custom()/self._api_client exist).
- resources.py: _KINDS["verticalpodautoscalers"] = ("list_vertical_pod_autoscalers", "verticalpodautoscalers", "autoscaling.k8s.io") + _GETTERS["verticalpodautoscalers"] = "get_vertical_pod_autoscaler" — both rows land with the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_verticalpodautoscalers.py (6 tests: list in-ns full-object, all-namespaces, CRD-absent empty w/ list-call-never-made, get 404->[], get hit full object, get 5xx->unreachable; stub get_crd_served + _custom via object.__new__) + test_resources.py (FakeK8s methods + 6 tests: 200 full-object-in-ns, all-namespaces w/o param, get-by-name hit/miss, SAR denied w/ ("list","verticalpodautoscalers","team-a",None,"autoscaling.k8s.io") in asked, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): verticalpodautoscalers kind (CRD, full object, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: VerticalPodAutoscalerItem — CAMEL CASE custom object (metadata.creationTimestamp, spec.targetRef.kind/name, spec.updatePolicy.updateMode, spec.resourcePolicy.containerPolicies[{containerName,controlledValues,mode,minAllowed,maxAllowed,controlledResources}], status.conditions[], [key:string]:unknown index).
- views/OtherResource/VerticalPodAutoscaler.tsx: KubeDataTable; namespace = useClusterStore.selectedNamespace ?? 'default' (NetworkPolicy pattern); card title EXACTLY 'Vertical Pod Autoscaler List'; columns Name(link)/Namespace/Target Kind/Target Name/Update Mode/Min Memory/Max Memory/Created; Target Name PLAIN TEXT (4.1's /workload link dropped - no 5.0 destination); Min/Max Memory = LAST container's minAllowed/maxAllowed.memory (4.1 {% set %} overwrite), N/A when none; Update Mode N/A when updatePolicy absent; name link is the SOLE producer of ?name=&namespace= (row's OWN namespace); fetch /api/v1/clusters/<id>/resources/verticalpodautoscalers?namespace=<ns>; pinned states (No cluster selected. / Loading vertical pod autoscalers... / No vertical pod autoscalers found — also the CRD-absent state).
- Test: vertical_pod_autoscalers.test.tsx (clone network_policies.test.tsx; fetch URL exact, target+memory cells, last-container memory semantics, missing updatePolicy N/A, empty state, Target Name not a link).
- Commit: feat(frontend): vertical pod autoscaler list view (4.1 CRD port, namespaced)

### T3 — Frontend: data view (independent of T2 after T1)
- views/OtherResource/VerticalPodAutoscalerData.tsx: clone PriorityClassData.tsx; single ?name=&namespace= fetch (query enabled on cluster+name+namespace); CTable Name/Created/Namespace/Target (Owner, plain text)/Update Mode/Labels/Annotations; Container Policies table (Container Name/Controlled Values/Mode/Min Allowed/Max Allowed/Controlled Resources; Min/Max Allowed 'resource: value' lines, N/A when absent; No container policies when absent); Conditions table (Type/Status/Last Transition Time/Reason/Message) from status.conditions (4.1's top-level conditions was DEAD - never populated); full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No VerticalPodAutoscaler '<name>' found' (not error; also CRD-absent); missing name = 'Error: vertical pod autoscaler name not provided'.
- Test: vertical_pod_autoscaler_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion, container-policies rows, conditions-from-status row, missing-policy No container policies/No conditions, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): vertical pod autoscaler data view (4.1 CRD tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block, after line 381) + two imports (after line 48).
- Stub/routes.ts: drop line 24; Stub.test.tsx: add '/other-resource/vertical-pod-autoscaler' to the viewPaths set in expectedStubs(). _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire vertical-pod-autoscaler routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) MUST call get_crd_served first and return [] when None — forgetting it is a 500 (ClusterUnreachableError) on any cluster without the VPA operator; (3) full custom object camelCase (not snake_case) — type + cell readers use camelCase keys; (4) data view treats items:[] as not-found state (miss OR CRD-absent), not error; (5) conditions read from status.conditions not 4.1's dead top-level conditions; (6) card title verbatim (e2e-smoke contract); (7) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Execution start (skillgrid implementer, session ses): working on branch `rebase` from HEAD 1a510cb4. Plan of record = blueprint.md (T1 backend kind → T2 list view → T3 data view → T4 routing). TDD per task with [scenario] docstring tags; one conventional commit per task; baseline: 3 kind-fixture errors in test_resources.py, frontend pre-existing failures in users/groups/admin_permissions + node-detail-renders. Concurrent work stream on same branch (hpa/pvc/storageclass/snapshotclass specs) — never stage sibling spec/backlog files.

T1 c0616fa4 (backend kind): RED = 6 service tests AttributeError (no methods); GREEN = 6/6 service, 83/83 api unit, 4 kind-tier passing + 2 pre-existing ScopeMismatch errors (3rd baseline error intermittently hidden by the known testcontainers teardown race). T2 638acda3 (list view): RED = module-not-found; GREEN 6/6. T3 ecd6e98a (data view): RED = module-not-found; GREEN 6/6. T4 6bb35dd9 (routes + stub removal): RED = Stub.test.tsx every-stub-entry-has-a-page (17 vs 18 expected); GREEN 17/17 across Stub + both VPA files. state.yaml 29ee7c8d. Verification floor: backend unit 507 passed (baseline, no new); frontend full vitest = 13 pre-existing baseline failures only (users/groups/admin_permissions/node-detail), 219 passed; fe-build + fe-check green; git diff --stat vs 1a510cb4 shows only File-Structure files, _nav.tsx absent. Deviations: blueprint FakeK8s snippet extended with vpa_ns_calls recording (Cilium precedent) so the 200/all-namespaces tests pin the forwarded namespace.
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
## VPA views (list + data) — 4.1 CRD port to 5.0

`/other-resource/vertical-pod-autoscaler` (+ `/data`) now resolve to real, SAR-gated, read-only views. VPAs are a namespaced CRD (verticalpodautoscalers.autoscaling.k8s.io) read through the Cilium full-custom-object seam: `get_crd_served` is the version+scope authority, CRD-absent degrades to `[]` as a first-class empty state, items keep spec+status intact in the camelCase wire form.

**Commits (branch `rebase`):** c0616fa4 backend kind (k8s_client methods + _KINDS/_GETTERS rows, 6 service + 6 API tests), 638acda3 list view (KubeDataTable, exact title 'Vertical Pod Autoscaler List', 4.1 last-container memory semantics, Target Name plain text, sole producer of ?name=&namespace=), ecd6e98a data view (single fetch, metadata CTable + Container Policies + Conditions from status.conditions + JSON block w/ json hljs grammar, not-found as state), 6bb35dd9 routes + stub removal, 29ee7c8d state.yaml.

**Verification:** backend unit 507 passed; new tests 6 service + 6 API green (3 pre-existing kind-fixture ScopeMismatch errors are baseline); frontend targeted 17/17; full vitest only pre-existing baseline failures; fe-build (tsc+eslint+vite) + fe-check (air-gap) green; _nav.tsx byte-identical.
<!-- SECTION:FINAL_SUMMARY:END -->
