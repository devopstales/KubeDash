---
id: TASK-052
title: >-
  Build 4.1 StorageClass views at /storage/storage-class (list + data,
  cluster-scoped)
status: Done
assignee: []
created_date: '2026-10-28 14:43'
updated_date: '2026-11-04 16:16'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/storage/storage-class.html.j2'
  - '4.1:src/kubedash/templates/storage/storage-class-data.html.j2'
  - '4.1:src/kubedash/lib/k8s/storage.py (k8sStorageClassListGet, line 15)'
  - 'kubedash_4:backend/app/api/resources.py'
  - >-
    kubedash_4:backend/app/services/k8s_client.py (list_nodes/get_priority_class
    cluster-scoped seam lines 261-276, 819-830)
  - .skillgrid/specs/2026-10-28-storageclass-views/
priority: medium
ordinal: 48000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'StorageClass -> /storage/storage-class' (_nav.tsx:103) currently renders a stub (views/Stub/routes.ts:21). 4.1 HAS real templates for this kind: storage/storage-class.html.j2 (list: Name/Default/Reclaim Policy/Volume Binding Mode) + storage-class-data.html.j2 (data: Name/Created/Annotations/Labels/Reclaim Policy/Binding Mode/Provisioner/Parameters card). Unlike SnapshotClass, StorageClass is a CORE API (storageclasses, storage/v1, CLUSTER-SCOPED, snake_case to_dict); the 4.1 read k8sStorageClassListGet (lib/k8s/storage.py:15) uses StorageV1Api().list_storage_class; the data page is list-then-filter by name. Port the shape to 5.0 with the ratified deltas: ?name= query-param navigation (cluster-scoped, NO ?namespace=), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains self._storage = StorageV1Api(api_client) + list_storage_classes (list_storage_class, to_dict, namespace accepted-and-ignored) + get_storage_class (read_storage_class, 404 -> [], other ApiException -> _unreachable; namespace accepted-and-ignored per the get_priority_class cluster-scoped pattern) mirroring list_nodes/get_priority_class; resources.py adds _KINDS['storageclasses'] = ('list_storage_classes', 'storageclasses', '') and _GETTERS['storageclasses'] = 'get_storage_class'. Frontend: StorageClassItem in types.ts (metadata, provisioner, reclaim_policy, volume_binding_mode, allow_volume_expansion, parameters); views/Storage/StorageClass.tsx (KubeDataTable columns Name/Default/Reclaim Policy/Volume Binding Mode - cluster-scoped no namespace, Default = storageclass.kubernetes.io/is-default-class annotation value, em dash for absent; name links to the data page with ?name= only); views/Storage/StorageClassData.tsx (single ?name= fetch, CTable Name/Created/Reclaim Policy/Volume Binding Mode/Provisioner/Labels/Annotations + Parameters table Key/Value, NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /storage/storage-class + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-storageclass-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/storageclasses returns the StorageClass list in to_dict snake_case form, SAR-gated on list storageclasses (core), 403 RBAC_DENIED on deny
- [x] #2 GET .../storageclasses?name=<name> returns the single StorageClass via _GETTERS; 404 -> empty items
- [x] #3 Cluster-scoped: ?namespace= is accepted and ignored (list_storage_class / read_storage_class)
- [x] #4 frontend StorageClass.tsx renders the list with Name/Default/Reclaim Policy/Volume Binding Mode columns (cluster-scoped, no namespace); card title exactly "Storage Classes List"; Default = is-default-class annotation; name links to the data page with ?name= only
- [x] #5 frontend StorageClassData.tsx renders detail at /storage/storage-class/data?name= via a single fetch; CTable + Parameters table; NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #6 /storage/storage-class removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #7 Backend tests: new tests/services/test_k8s_client_storageclasses.py (list ignores-namespace, get hit/404/5xx/ignores-namespace) + test_resources.py extensions (200, ignores-namespace, get-by-name hit/miss, SAR deny w/ core group + namespace None, binding 404, singular kind rejected)
- [x] #8 Frontend tests: storage_classes.test.tsx + storage_class_data.test.tsx (mirror priority_classes/priority_class_data tests; cluster-scoped no namespace); Stub.test.tsx viewPaths updated for the removed route
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
## Implementation plan — /storage/storage-class (4.1 port, TASK-052)

Spec zone complete: .skillgrid/specs/2026-10-28-storageclass-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

KEY: StorageClass is a CORE API (storageclasses, storage/v1, cluster-scoped, snake_case to_dict). This is the list_nodes/get_priority_class cluster-scoped core-kind pattern (NOT the CRD seam). New self._storage = StorageV1Api attribute.

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: storageclasses kind (storage, cluster-scoped, SAR-gated)
- k8s_client.py: __init__ gains self._storage = StorageV1Api(api_client) (next to self._scheduling ~line 226); list_storage_classes(_namespace) (list_storage_class, to_dict, _unreachable on ApiException; namespace accepted-and-ignored) + get_storage_class(_namespace, name) (read_storage_class, 404 -> [], else _unreachable; namespace accepted-and-ignored per the get_priority_class cluster-scoped pattern). Mirror list_nodes/get_priority_class.
- resources.py: _KINDS["storageclasses"] = ("list_storage_classes", "storageclasses", "") + _GETTERS["storageclasses"] = "get_storage_class" — both rows land with the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_storageclasses.py (6 tests, object.__new__ + SimpleNamespace) + test_resources.py (FakeK8s methods + 6 tests: 200, ignores-namespace w/ None received, get-by-name hit/miss, SAR denied w/ ("list","storageclasses",None,None,"") in asked, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): storageclasses kind (storage, cluster-scoped, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: StorageClassItem (snake_case to_dict: metadata, provisioner, reclaim_policy, volume_binding_mode, allow_volume_expansion, parameters, [key:string]:unknown index).
- views/Storage/StorageClass.tsx: KubeDataTable; cluster-scoped (NO namespace read); card title EXACTLY 'Storage Classes List'; columns Name(link)/Default/Reclaim Policy/Volume Binding Mode; Default = storageclass.kubernetes.io/is-default-class annotation value (— when absent); Reclaim Policy/Volume Binding Mode — when absent; name link is the SOLE producer of ?name= (cluster-scoped, NO namespace); fetch /api/v1/clusters/<id>/resources/storageclasses (NO namespace param); pinned states (No cluster selected. / Loading storage classes... / No storage classes found).
- Test: storage_classes.test.tsx (clone priority_classes.test.tsx — cluster-scoped no namespace; fetch URL exact w/o namespace, default/policy/binding cells, missing-fields dashes, empty state, no-cluster state, link has ?name= only).
- Commit: feat(frontend): storage class list view (4.1 port, cluster-scoped)

### T3 — Frontend: data view (independent of T2 after T1)
- views/Storage/StorageClassData.tsx: clone PriorityClassData.tsx; single ?name= fetch (query enabled on cluster+name, NO namespace); CTable Name/Created/Reclaim Policy/Volume Binding Mode/Provisioner/Labels/Annotations; Parameters table (Key/Value, one row per parameters entry, No parameters when absent); full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No StorageClass '<name>' found' (not error); missing name = 'Error: storage class name not provided'.
- Test: storage_class_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion w/o namespace, parameters rows, missing-parameters No parameters, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): storage class data view (4.1 tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block, after line 381) + two imports (after line 48).
- Stub/routes.ts: drop line 21; Stub.test.tsx: add '/storage/storage-class' to the viewPaths set in expectedStubs(). _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire storage-class routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) data view treats items:[] as not-found state, not error (NOT_FOUND-throw pattern); (3) cluster-scoped — namespace accepted-and-ignored, list_storage_class/read_storage_class (NOT namespaced); (4) snake_case to_dict (generated core-API model) — type + cell readers use snake_case keys; (5) Default column = is-default-class annotation (— when absent); (6) data 'Volume Binding Mode' label keeps the list header verbatim (4.1 data used the shorter 'Binding Mode'); (7) card title verbatim (e2e-smoke contract); (8) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.

RE-BASELINE (2026-11-04, executed on rebase): the plan above predates the ADR-0040 session-object-navigation contract (superseded 2026-10-29, QA PASS 2026-11-04). Execute per the shipped contract: (1) list route /storage/storage-class carries ObjectRoute kind=storageclass; name cells are buttons calling openObject(KIND, name, undefined, LIST_ROUTE, navigate) (cluster-scoped: no namespace); (2) the data view is a separate component receiving name as a PROP from ObjectRoute (not useSearchParams) with a single ?name= fetch; (3) App.tsx: NO /data route and NO OldDataRedirect (the /data URL never shipped — the kind was a stub); (4) clone the RuntimeClass pair (cluster-scoped sibling) for list/data shapes; (5) T4 adds ui-smoke REAL_ROUTES entry + dev/scripts/demo-data.sh StorageClass fixture (parameters, reclaim policy, volume binding mode, is-default-class annotation).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 committed 868a1062: backend storageclasses kind (K8sClient.list_storage_classes/get_storage_class via StorageV1Api; _KINDS/_GETTERS rows; service tests 5 + API tests 6; full suite 564 passed == baseline+11)

T2 committed f79ef048: list view StorageClass.tsx (cluster-scoped, openObject button, 'Storage Classes List' title) + StorageClassItem type + 6 tests (RED: module-not-found; GREEN 6/6 + tsc clean)

T3 committed <hash>: data view StorageClassData.tsx ({name} prop, single ?name= fetch, CTable + Parameters CTable + JSON block, not-found state) + 5 tests (RED: module-not-found; GREEN 5/5 + tsc clean)

T3 hash: e9fc4e08

Hashes re-issued (T1 amended to fold in the 6th service test required by AC #7, 'get ignores-namespace'; rebase, disjoint files, no functional change): T1=1d5bb5ba T2=ab951e9d T3=76aaa5ed T4=08e37b50. T4: App.tsx ObjectRoute block (one route, no /data — kind was a stub, no R7), stub row dropped, Stub.test viewPaths + ui-smoke REAL_ROUTES moved, demo-data.sh demo-gp2 fixture (rancher.local-path, no is-default-class) + echo line. Floors: fe-build tsc+eslint+build PASS; fe-check air-gap PASS; fe-sync synced; vitest full 12 failed|307 passed (== baseline 12|296 + 11 new); backend full (pending final run, targeted 108/108 + 564 earlier); git diff --stat 14 files only, _nav.tsx untouched
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Built 4.1 StorageClass views at /storage/storage-class (cluster-scoped core kind, SAR-gated). 4 commits (T1 backend kind, T2 list view, T3 data view, T4 routing+stub removal): 1d5bb5ba feat(resources): storageclasses kind (core, cluster-scoped, SAR-gated); ab951e9d feat(frontend): storage class list view (4.1-parity, ADR-0040 nav); 76aaa5ed feat(frontend): storage class data view (parameters table + JSON block); 08e37b50 feat(frontend): wire storage-class routes, remove stub. Executed per the shipped ADR-0040 session-object-navigation contract (re-baseline): ObjectRoute single route (no /data, no R7 — kind was a stub), openObject button list cells, data view takes {name} prop, single ?name= backend fetch. Verified: 8/8 ACs + 5/5 DoD. Backend 565 passed/10 deselected (== baseline 553 + 12 new: 6 service incl. get-ignores-namespace, 6 API). Frontend full vitest 307 passed / 12 failed (== baseline 296/12 + 11 new; the 12 are pre-existing users/groups/admin_permissions). fe-build (tsc+eslint+build) + fe-check (air-gap) + fe-sync PASS. git diff --stat = 14 files only (blueprint File Structure + re-baseline ui-smoke.spec.ts + demo-data.sh); _nav.tsx untouched.
<!-- SECTION:FINAL_SUMMARY:END -->
