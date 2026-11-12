---
id: TASK-051
title: >-
  Build 4.1 SnapshotClass views at /storage/snapshot-class (list + data,
  cluster-scoped CRD)
status: Done
assignee: []
created_date: '2026-10-28 14:31'
updated_date: '2026-11-04 17:35'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/storage/snapshot-class.html.j2'
  - '4.1:src/kubedash/templates/storage/snapshot-class-data.html.j2'
  - '4.1:src/kubedash/lib/k8s/storage.py (k8sSnapshotClassListGet, line 46)'
  - 'kubedash_4:backend/app/api/resources.py'
  - >-
    kubedash_4:backend/app/services/k8s_client.py (Cilium + get_crd
    cluster-scoped seam lines 563-734)
  - .skillgrid/specs/2026-10-28-snapshotclass-views/
priority: medium
ordinal: 47000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'SnapshotClass -> /storage/snapshot-class' (_nav.tsx:104) currently renders a stub (views/Stub/routes.ts:22). 4.1 HAS real templates for this kind: storage/snapshot-class.html.j2 (list: Name/Default/Deletion Policy/Driver) + snapshot-class-data.html.j2 (data: Name/Created/Annotations/Labels/Deletion Policy/Driver/Parameters table). Unlike the core kinds, SnapshotClass is a CRD (volumesnapshotclasses.snapshot.storage.k8s.io, snapshot.storage.k8s.io group, CLUSTER-SCOPED); the 4.1 read k8sSnapshotClassListGet (lib/k8s/storage.py:46) uses CustomObjectsApi().list_cluster_custom_object("snapshot.storage.k8s.io", "v1", "volumesnapshotclasses") with a HARDCODED v1 (no runtime version resolution, unlike VPA) and swallows ALL ApiException -> []; the data page is list-then-filter by name. Port the shape to 5.0 via the CILIUM full-custom-object seam (get_crd_served version authority - an improvement over 4.1's hardcoded v1, CRD-absent -> [] as a first-class empty state, full object driver/deletionPolicy/parameters/metadata intact, camelCase) with the ratified deltas: ?name= query-param navigation (cluster-scoped, NO ?namespace=), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains list_volume_snapshot_classes (get_crd_served None -> [], else list_cluster_custom_object, _crd_body, to_dict, namespace accepted-and-ignored) + get_volume_snapshot_class (get_crd_served None -> [], get_cluster_custom_object, 404/absent -> [], other ApiException -> _unreachable; namespace accepted-and-ignored per the get_crd cluster-scoped pattern) mirroring list_cilium_clusterwide_network_policies/get_cilium_network_policy; resources.py adds _KINDS['volumesnapshotclasses'] = ('list_volume_snapshot_classes', 'volumesnapshotclasses', 'snapshot.storage.k8s.io') and _GETTERS['volumesnapshotclasses'] = 'get_volume_snapshot_class'. Frontend: VolumeSnapshotClassItem in types.ts (camelCase custom object: metadata, driver, deletionPolicy, parameters); views/Storage/SnapshotClass.tsx (KubeDataTable columns Name/Default/Deletion Policy/Driver - cluster-scoped no namespace, Default = snapshot.storage.kubernetes.io/is-default-class annotation value, em dash for absent; name links to the data page with ?name= only); views/Storage/SnapshotClassData.tsx (single ?name= fetch, CTable Name/Created/Deletion Policy/Driver/Labels/Annotations + Parameters table Key/Value, NOT_FOUND as a state, full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /storage/snapshot-class + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-snapshotclass-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/volumesnapshotclasses returns the SnapshotClass list as full custom objects (driver+deletionPolicy+parameters intact, camelCase), SAR-gated on list volumesnapshotclasses (snapshot.storage.k8s.io), 403 RBAC_DENIED on deny
- [x] #2 GET .../volumesnapshotclasses?name=<name> returns the single full SnapshotClass via _GETTERS; 404/CRD-absent -> empty items
- [x] #3 CRD absent (snapshot operator not installed) -> items == [] 200 (a state, not an error) - the get_crd_served None -> [] contract
- [x] #4 Cluster-scoped: ?namespace= is accepted and ignored (list_cluster_custom_object / get_cluster_custom_object)
- [x] #5 frontend SnapshotClass.tsx renders the list with Name/Default/Deletion Policy/Driver columns (cluster-scoped, no namespace); card title exactly "Snapshot Classes List"; Default = is-default-class annotation; name links to the data page with ?name= only
- [x] #6 frontend SnapshotClassData.tsx renders detail at /storage/snapshot-class/data?name= via a single fetch; CTable + Parameters table; NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [x] #7 /storage/snapshot-class removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #8 Backend tests: new tests/services/test_k8s_client_volume_snapshot_classes.py (list ignores-namespace full-object, CRD-absent empty, get hit/404/5xx/ignores-namespace) + test_resources.py extensions (200 full-object, ignores-namespace, get-by-name hit/miss, SAR deny w/ group snapshot.storage.k8s.io + namespace None, binding 404, singular kind rejected)
- [x] #9 Frontend tests: snapshot_classes.test.tsx + snapshot_class_data.test.tsx (mirror priority_classes/priority_class_data tests; cluster-scoped no namespace); Stub.test.tsx viewPaths updated for the removed route
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
## Implementation plan — /storage/snapshot-class (4.1 CRD port, TASK-051)

Spec zone complete: .skillgrid/specs/2026-10-28-snapshotclass-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

KEY: SnapshotClass is a CLUSTER-SCOPED CRD (volumesnapshotclasses.snapshot.storage.k8s.io). This is the CILIUM full-custom-object seam + RUNTIMECLASS cluster-scoped pattern: get_crd_served version authority (improvement over 4.1's hardcoded v1), CRD-absent -> [] (first-class empty), full object (driver/deletionPolicy/parameters/metadata intact), camelCase, namespace accepted-and-ignored. Getter uses get_cluster_custom_object (the get_crd cluster-scoped pattern).

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: volumesnapshotclasses kind (CRD, cluster-scoped, full object, SAR-gated)
- k8s_client.py (next to the Cilium methods ~line 715): _SNAPSHOT_CLASS_GROUP="snapshot.storage.k8s.io" + _SNAPSHOT_CLASS_PLURAL="volumesnapshotclasses" module constants; list_volume_snapshot_classes(_namespace) (get_crd_served None -> []; else list_cluster_custom_object, _crd_body, to_dict, _unreachable; namespace ignored) + get_volume_snapshot_class(_namespace, name) (get_crd_served None -> []; get_cluster_custom_object, 404 -> [], else _unreachable; namespace ignored). NO new __init__ attribute (self._custom()/self._api_client exist).
- resources.py: _KINDS["volumesnapshotclasses"] = ("list_volume_snapshot_classes", "volumesnapshotclasses", "snapshot.storage.k8s.io") + _GETTERS["volumesnapshotclasses"] = "get_volume_snapshot_class" — both rows land with the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_volume_snapshot_classes.py (6 tests: list ignores-namespace full-object, CRD-absent empty w/ list-call-never-made, get 404->[], get hit full object, get ignores-namespace, get 5xx->unreachable; stub get_crd_served + _custom via object.__new__) + test_resources.py (FakeK8s methods + 6 tests: 200 full-object, ignores-namespace w/ None received, get-by-name hit/miss, SAR denied w/ ("list","volumesnapshotclasses",None,None,"snapshot.storage.k8s.io") in asked, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): volumesnapshotclasses kind (CRD, cluster-scoped, full object, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: VolumeSnapshotClassItem — CAMEL CASE custom object (metadata.creationTimestamp/annotations/labels, driver, deletionPolicy, parameters, [key:string]:unknown index).
- views/Storage/SnapshotClass.tsx: KubeDataTable; cluster-scoped (NO namespace read); card title EXACTLY 'Snapshot Classes List'; columns Name(link)/Default/Deletion Policy/Driver; Default = snapshot.storage.kubernetes.io/is-default-class annotation value (— when absent); Deletion Policy/Driver — when absent; name link is the SOLE producer of ?name= (cluster-scoped, NO namespace); fetch /api/v1/clusters/<id>/resources/volumesnapshotclasses (NO namespace param); pinned states (No cluster selected. / Loading snapshot classes... / No snapshot classes found — also the CRD-absent state).
- Test: snapshot_classes.test.tsx (clone priority_classes.test.tsx — cluster-scoped no namespace; fetch URL exact w/o namespace, default/policy/driver cells, missing-fields dashes, empty state, no-cluster state, link has ?name= only).
- Commit: feat(frontend): snapshot class list view (4.1 CRD port, cluster-scoped)

### T3 — Frontend: data view (independent of T2 after T1)
- views/Storage/SnapshotClassData.tsx: clone PriorityClassData.tsx; single ?name= fetch (query enabled on cluster+name, NO namespace); CTable Name/Created/Deletion Policy/Driver/Labels/Annotations; Parameters table (Key/Value, one row per parameters entry, No parameters when absent); full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No VolumeSnapshotClass '<name>' found' (not error; also CRD-absent); missing name = 'Error: snapshot class name not provided'.
- Test: snapshot_class_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion w/o namespace, parameters rows, missing-parameters No parameters, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): snapshot class data view (4.1 CRD tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block, after line 381) + two imports (after line 48).
- Stub/routes.ts: drop line 22; Stub.test.tsx: add '/storage/snapshot-class' to the viewPaths set in expectedStubs(). _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire snapshot-class routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) MUST call get_crd_served first and return [] when None — forgetting it is a 500 on any cluster without the snapshot operator; (3) full custom object camelCase (not snake_case) — type + cell readers use camelCase keys; (4) cluster-scoped — namespace accepted-and-ignored, get_cluster_custom_object (NOT namespaced); (5) data view treats items:[] as not-found state (miss OR CRD-absent), not error; (6) Default column = is-default-class annotation (— when absent); (7) card title verbatim (e2e-smoke contract); (8) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.

RE-BASELINE (2026-11-04, executed on rebase): the plan above predates the ADR-0040 session-object-navigation contract (superseded 2026-10-29, QA PASS 2026-11-04). Execute per the shipped contract: (1) list route /storage/snapshot-class carries ObjectRoute kind=snapshotclass; name cells are buttons calling openObject(KIND, name, undefined, LIST_ROUTE, navigate) (cluster-scoped CRD: no namespace); (2) the data view is a separate component receiving name as a PROP from ObjectRoute (not useSearchParams) with a single ?name= fetch; (3) App.tsx: NO /data route and NO OldDataRedirect (the /data URL never shipped — the kind was a stub); (4) clone the RuntimeClass pair (cluster-scoped sibling) for list/data shapes, keeping the full-custom-object camelCase readers; (5) T4 adds ui-smoke REAL_ROUTES entry + dev/scripts/demo-data.sh fixtures (volumesnapshotclasses.snapshot.storage.k8s.io CRD + one SnapshotClass, minimal x-kubernetes-preserve-unknown-fields schema).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 DONE (commit 7279d411): backend volumesnapshotclasses kind. RED=6 service tests AttributeError; GREEN=6 passed. resources.py _KINDS+_GETTERS rows. Full suite 589 passed,10 deselected (baseline 577+12). Delta: get_crd_served returns (version,scope) not (group,version) — unpacked version,_scope and passed _SNAPSHOT_CLASS_GROUP explicitly (code wins over the plan's '(group,version)=served').

T2 DONE (commit 3f739884): SnapshotClass list view + VolumeSnapshotClassItem type (camelCase, next to CiliumPolicyItem) + 6 list tests (RED=import failure, GREEN=6 passed, tsc clean). Columns Name/Default/Deletion Policy/Driver/Created; card title 'Snapshot Classes List' verbatim.

T3 DONE (commit c413d085): SnapshotClassData view (single ?name= fetch, name prop from ObjectRoute, CTable + Parameters + JSON block) + 5 data tests (RED=import failure, GREEN=5 passed, tsc clean).

T4 DONE (commit 2365cff8): App.tsx ObjectRoute wiring (kind=snapshotclass, first build — no /data route, no R7 redirect, cluster-scoped), stub route dropped, Stub.test.tsx viewPaths + ui-smoke REAL_ROUTES moved, demo-data.sh CRD+csi-default fixture. FLOOR: fe-build (tsc+eslint+build) PASS; fe-check (air-gap) PASS; fe-sync synced; vitest 331 passed / 12 failed (12 pre-existing in groups/users/admin_permissions — none in changed files; baseline 320+11 new passes); pytest 589 passed, 10 deselected (baseline 577+12 new); git diff --stat = exactly the file-list files, _nav.tsx untouched. Warnings verified pre-existing (testcontainers.postgres + PyJWT InsecureKeyLengthWarning). Ruff: new code clean (12 pre-existing E501 in test_resources.py, none new).

Closeout (320e2b4b): live dev-cluster verification found the snapshot CRDs never went Ready/Established — the apiextensions group protects the `api-approved` annotation, which the fixture lacked, so the dev list rendered empty. The fixture now applies the annotated CRDs in a dedicated first pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Built 4.1 SnapshotClass list+data views at /storage/snapshot-class (cluster-scoped CRD volumesnapshotclasses.snapshot.storage.k8s.io), per the ADR-0040 re-baselined contract. 4 commits: 7279d411 (backend kind: get_crd_served-authoritative full-custom-object seam, cluster-scoped, CRD-absent->[], SAR-gated), 3f739884 (list view, card title 'Snapshot Classes List' verbatim, Name/Default/Deletion Policy/Driver/Created, openObject nav), c413d085 (data view, single ?name= fetch, CTable+Parameters+JSON block, not-found state), 2365cff8 (ObjectRoute wiring, stub removal, ui-smoke REAL_ROUTES, demo-data CRD+csi-default fixture). Verified: TDD RED->GREEN per task; backend pytest 589 passed/10 deselected (baseline 577+12 new); frontend vitest 331 passed/12 failed (12 pre-existing in groups/users/admin_permissions, none in changed files; baseline 320+11 new); fe-build (tsc+eslint+build) PASS; fe-check air-gap PASS; fe-sync synced; ruff new code clean; git diff --stat = exactly the 14 file-list files, _nav.tsx untouched. Deltas noted: get_crd_served returns (version,scope) not (group,version).
<!-- SECTION:FINAL_SUMMARY:END -->
