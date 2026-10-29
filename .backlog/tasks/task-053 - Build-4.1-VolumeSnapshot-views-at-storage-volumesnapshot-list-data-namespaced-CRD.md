---
id: TASK-053
title: >-
  Build 4.1 VolumeSnapshot views at /storage/volumesnapshot (list + data,
  namespaced CRD)
status: In Progress
assignee: []
created_date: '2026-10-28 15:09'
updated_date: '2026-10-28 15:10'
labels: []
dependencies: []
references:
  - '4.1:src/kubedash/templates/storage/volumesnapshot.html.j2'
  - >-
    4.1:src/kubedash/lib/k8s/storage.py (k8sPersistentVolumeSnapshotListGet,
    line 162)
  - >-
    4.1:src/kubedash/blueprint/storage.py (line 232 — list route only, no data
    route)
  - 'kubedash_4:backend/app/api/resources.py'
  - >-
    kubedash_4:backend/app/services/k8s_client.py (Cilium/VPA CRD-seam lines
    667-734)
  - .skillgrid/specs/2026-10-28-volumesnapshot-views/
priority: medium
ordinal: 49000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf VolumeSnapshot -> /storage/volumesnapshot (_nav.tsx:102) currently renders a stub (views/Stub/routes.ts:23). 4.1 has a real LIST template but NO data template: storage/volumesnapshot.html.j2 (list: Usable/Name/SnapshotClass/VolumeClaim/RestorSize — Usable is the status.readyToUse success/danger badge; the name link is COMMENTED OUT — a dead link, 4.1 has no /volumesnapshot/data route). The 4.1 read k8sPersistentVolumeSnapshotListGet (lib/k8s/storage.py:162) uses CustomObjectsApi().list_cluster_custom_object(snapshot.storage.k8s.io, v1, volumesnapshots) — hardcoded v1 AND hardcoded all-namespaces (ignored session ns_select); deep-indexes spec.source.persistentVolumeClaimName / spec.volumeSnapshotClassName (KeyError 500 on a SourceMode-less snapshot). VolumeSnapshot is a NAMESPACE-AWARE CRD (snapshot.storage.k8s.io, volumesnapshots) — the namespaced member of the CRD-seam family (like VPA, unlike cluster-scoped SnapshotClass). Port the 4.1 LIST shape to 5.0 with the ratified deltas + ADD a 5.0 data page (4.1 had none). Backend: k8s_client.py gains list_volume_snapshots(namespace) (get_crd_served version authority — NOT 4.1 hardcoded v1; CRD-absent 404 -> []; namespace None -> list_cluster_custom_object all-namespaces branch, else list_namespaced_custom_object; _unreachable on other ApiException) + get_volume_snapshot(namespace, name) (get_custom_object, 404/CRD-absent -> [], else _unreachable) — NO new __init__ attribute (self._custom already exists); resources.py adds _KINDS[volumesnapshots] = (list_volume_snapshots, volumesnapshots, snapshot.storage.k8s.io) and _GETTERS[volumesnapshots] = get_volume_snapshot. Frontend: VolumeSnapshotItem in types.ts (camelCase full custom object: metadata, spec.volumeSnapshotClassName, spec.source.persistentVolumeClaimName, status.readyToUse/restoreSize/boundVolumeSnapshotContentName); views/Storage/VolumeSnapshot.tsx (KubeDataTable columns Name/Usable/SnapshotClass/VolumeClaim/Restore Size — namespaced via selectedNamespace, ALWAYS sends ?namespace= (a fix for 4.1 all-namespaces list); Usable = readyToUse success/danger badge; deep-index fields em-dash when absent (the 4.1 KeyError-500 fix); name links to the data page with ?name=&namespace=); views/Storage/VolumeSnapshotData.tsx (NEW in 5.0 — 4.1 had no data page; single ?name=&namespace= fetch, CTable Name/Created/Source/SnapshotClass/Ready To Use/Restore Size/Bound Content/Labels/Annotations, NOT_FOUND as a state (also the CRD-absent state), full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /storage/volumesnapshot + /data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-volumesnapshot-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GET /api/v1/clusters/<id>/resources/volumesnapshots?namespace=<ns> returns the full custom-object list (camelCase, spec/status intact) via list_namespaced_custom_object with the CRD served version (get_crd_served, NOT hardcoded v1), SAR-gated on list volumesnapshots (snapshot.storage.k8s.io), 403 RBAC_DENIED on deny
- [ ] #2 No ?namespace= -> list_cluster_custom_object (all-namespaces branch); CRD absent (404) -> 200 with empty items (first-class empty state, not an error)
- [ ] #3 GET .../volumesnapshots?name=<name>&namespace=<ns> returns the single full object via _GETTERS; 404 and CRD-absent -> empty items
- [ ] #4 frontend VolumeSnapshot.tsx renders the list with Name/Usable/SnapshotClass/VolumeClaim/Restore Size columns; card title exactly "Volume Snapshot List"; ALWAYS sends ?namespace= (header-selected, a fix for 4.1 all-namespaces); Usable = readyToUse badge; deep-index fields em-dash when absent; name links to the data page with ?name=&namespace=
- [ ] #5 frontend VolumeSnapshotData.tsx (NEW in 5.0 — 4.1 had no data page) renders detail at /storage/volumesnapshot/data?name=&namespace= via a single fetch; CTable + deep-index fields; NOT_FOUND is a first-class state (also CRD-absent); full-object JSON block (json hljs grammar)
- [ ] #6 /storage/volumesnapshot removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [ ] #7 Backend tests: new tests/services/test_k8s_client_volumesnapshots.py (served-version-namespaced, all-namespaces-branch, crd-absent-empty, 5xx-unreachable, get hit/404/crd-absent) + test_resources.py extensions (namespaced 200, all-namespaces, crd-absent, SAR deny w/ group + namespace, binding 404, singular kind rejected, get-by-name hit/miss)
- [ ] #8 Frontend tests: volume_snapshots.test.tsx + volume_snapshot_data.test.tsx (mirror network_policies + snapshot_class_data tests); Stub.test.tsx viewPaths updated for the removed route
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
## Implementation plan — /storage/volumesnapshot (4.1 port + NEW data page, TASK-053)

Spec zone complete: .skillgrid/specs/2026-10-28-volumesnapshot-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

KEY: VolumeSnapshot is a NAMESPACE-AWARE CRD (snapshot.storage.k8s.io, volumesnapshots) — the namespaced member of the CRD-seam family (like VPA, unlike cluster-scoped SnapshotClass). This is the FIRST spec where 4.1 had NO data page (the list's name link is a dead commented-out link) — 5.0 ADDS the data page. 4.1's read is list_cluster_custom_object (all-namespaces, hardcoded v1, deep-index KeyError 500s). NO new __init__ attribute (self._custom already exists).

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: volumesnapshots kind (storage CRD, namespaced, SAR-gated)
- k8s_client.py: list_volume_snapshots(namespace) (get_crd_served("snapshot.storage.k8s.io","volumesnapshots") version authority — NOT 4.1's hardcoded v1; CRD-absent 404 -> [] (snapshot operator is optional); namespace None -> list_cluster_custom_object all-namespaces branch, else list_namespaced_custom_object(namespace=...); _unreachable on other ApiException) + get_volume_snapshot(namespace, name) (get_custom_object, 404/CRD-absent -> [], else _unreachable). Mirror the VPA namespaced CRD methods (the closest precedent); no new __init__ attribute.
- resources.py: _KINDS["volumesnapshots"] = ("list_volume_snapshots", "volumesnapshots", "snapshot.storage.k8s.io") + _GETTERS["volumesnapshots"] = "get_volume_snapshot" — both rows land with the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_volumesnapshots.py (7 tests, object.__new__ + SimpleNamespace) + test_resources.py (FakeK8s methods + 7 tests: namespaced 200, all-namespaces w/ None received, crd-absent empty, SAR denied w/ ("list","volumesnapshots","team-a",None,"snapshot.storage.k8s.io") in asked, binding 404, singular kind rejected, get-by-name hit/miss).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): volumesnapshots kind (storage CRD, namespaced, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: VolumeSnapshotItem (camelCase full custom object: metadata, spec.volumeSnapshotClassName, spec.source.persistentVolumeClaimName, status.readyToUse/restoreSize/boundVolumeSnapshotContentName, [key:string]:unknown index).
- views/Storage/VolumeSnapshot.tsx: KubeDataTable; namespaced via useClusterStore.selectedNamespace (NetworkPolicy pattern — ALWAYS sends ?namespace=, a fix for 4.1's all-namespaces list); card title EXACTLY 'Volume Snapshot List'; columns Name(link)/Usable/SnapshotClass/VolumeClaim/Restore Size; Usable = status.readyToUse success/danger badge (— when absent); SnapshotClass/VolumeClaim/Restore Size = deep-indexed values with — when absent (the 4.1 KeyError-500 fix); name link is the SOLE producer of ?name=&namespace=; fetch /api/v1/clusters/<id>/resources/volumesnapshots?namespace=<ns>; pinned states (No cluster selected. / Loading volume snapshots... / No volume snapshots found — also the CRD-absent state, same copy).
- Test: volume_snapshots.test.tsx (clone network_policies.test.tsx — namespaced; fetch URL exact w/ namespace, usable badge success/danger, missing-deep-fields dashes, empty state, no-cluster state, link has ?name=&namespace=).
- Commit: feat(frontend): volume snapshot list view (4.1 port, namespaced CRD)

### T3 — Frontend: data view (independent of T2 after T1)
- views/Storage/VolumeSnapshotData.tsx: clone SnapshotClassData.tsx; the data page is NEW in 5.0 (4.1 had none — dead commented-out link); single ?name=&namespace= fetch (query enabled on cluster+name, namespace read from the link — never constructed); CTable Name/Created/Source/SnapshotClass/Ready To Use/Restore Size/Bound Content/Labels/Annotations; deep-index fields — when absent; full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No VolumeSnapshot <name> found' (also the CRD-absent state); missing name = 'Error: volume snapshot name not provided'.
- Test: volume_snapshot_data.test.tsx (clone snapshot_class_data.test.tsx; single-fetch assertion w/ ?name=&namespace=, deep-index — fields, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): volume snapshot data view (new in 5.0, 4.1 fields + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror snapshot-class block) + two imports.
- Stub/routes.ts: drop the /storage/volumesnapshot entry (line 23); Stub.test.tsx: add '/storage/volumesnapshot' to the viewPaths set in expectedStubs(). _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire volume-snapshot routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) CRD version via get_crd_served (NOT 4.1's hardcoded v1) — CRD 404 -> [] WITHOUT calling list/get custom-object (Cilium absence contract); (3) namespaced — namespace None -> list_cluster_custom_object, else list_namespaced_custom_object; get uses get_custom_object(namespace=...); (4) camelCase (raw custom object) — type + cell readers use camelCase keys; (5) deep-index — (the 4.1 KeyError-500 fix); (6) data page is NEW in 5.0 — 4.1 had no data page (dead commented-out link); (7) list ALWAYS sends ?namespace= (header-selected, a fix for 4.1 all-namespaces list); (8) card title verbatim (e2e-smoke contract); (9) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.
<!-- SECTION:PLAN:END -->
