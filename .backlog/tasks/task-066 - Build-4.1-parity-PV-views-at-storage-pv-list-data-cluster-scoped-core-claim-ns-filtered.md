---
id: TASK-066
title: >-
  Build 4.1 parity PV views at /storage/pv (list + data, cluster-scoped core,
  claim-ns filtered)
status: Done
assignee: []
created_date: '2026-11-05 07:36'
updated_date: '2026-11-05 08:58'
labels:
  - feature
dependencies: []
priority: medium
ordinal: 62000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Port 4.1's Persistent Volume pages (storage/pv.html.j2 + pv-data.html.j2) to 5.0: backend persistentvolumes kind (cluster-scoped, list filtered to the selected namespace via claim_ref with free PVs always visible — 4.1 bugs fixed: hostPath continue-skip, unbound-PV crash), list view (Status badge/Name/StorageClass/VolumeClaim/Capacity, ADR-0040 object refs), data view (4.1 row set + JSON block), ObjectRoute wiring + stub removal. Companion: the 2026-11-05 user-decision trimAnnotations override for the five existing storage data views. Spec: .skillgrid/specs/2026-11-05-pv-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 T1: K8sClient.list_persistent_volumes(namespace) — cluster list, to_dict, claim-ns filter (free PVs always, bound only for ns), None -> all; ApiException -> 502. K8sClient.get_persistent_volume — 0/1-item, 404 -> []. _KINDS/_GETTERS rows. Service + API tests RED->GREEN
- [x] #2 T2: the five storage data views (StorageClassData, SnapshotClassData, VolumeSnapshotData, PvcData, ConfigMapData) drop kubectl.kubernetes.io/last-applied-configuration + autoscaling.alpha.kubernetes.io/conditions from the annotations table (4.1 trimAnnotations; the 2026-11-04 HPA shape). JSON block untouched. adr.md override notes in the five specs
- [x] #3 T3: Pv.tsx list view — card title exactly 'Persistent Volume List', 4.1 columns, Terminating badge override, cross-kind object refs (storageclass, pvc with claim ns), — for absent values; PersistentVolumeItem type; view tests RED->GREEN
- [x] #4 T4: PvData.tsx — single ?name= fetch, 4.1 row set (conditional Deleted/Local Path/CSI rows, Volume Attributes table), trimmed annotations, not-found state, JSON block; view tests RED->GREEN
- [x] #5 T5: App.tsx ObjectRoute /storage/pv (cluster-scoped, no R7 redirect), stub removed from Stub/routes.ts, Stub.test viewPaths + ui-smoke REAL_ROUTES moved
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
- [x] #6 uv run pytest -m 'not integration' green (new tests RED->GREEN)
- [x] #7 targeted vitest green (pvs, pv_data, five trimmed views, Stub)
- [x] #8 task fe-build + fe-check + fe-sync green
- [x] #9 task e2e green (ui-smoke /storage/pv as REAL route)
- [x] #10 live dev cluster: PV list renders real PVs, data view renders full rows, no last-applied blob in storage annotation tables
- [x] #11 ruff/mypy flat vs HEAD (no new lint debt)
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Execute .skillgrid/specs/2026-11-05-pv-views/blueprint.md end-to-end under the ADR-0040 contract, 6 commits, each independently revertable. T1 backend: k8s_client list_persistent_volumes (cluster list, to_dict, claim-ns filter: free PVs always, bound only for the selected ns, None -> all) + get_persistent_volume (0/1-item, 404 -> []) + resources.py _KINDS/_GETTERS rows (core) + service tests (test_k8s_pvs.py) + API tests (RED first). Commit: feat(resources). T2 companion fix: the five storage data views (StorageClassData, SnapshotClassData, VolumeSnapshotData, PvcData, ConfigMapData) trim kubectl.kubernetes.io/last-applied-configuration + autoscaling.alpha.kubernetes.io/conditions from the annotations table (4.1 trimAnnotations, the HPA 46929a10 shape); JSON block untouched. Commit: fix(fe). T3: lib/types.ts PersistentVolumeItem + Pv.tsx list view (card title exactly 'Persistent Volume List', 4.1 columns, Terminating badge override, cross-kind object refs, — for absent values) + pvs.test.tsx (RED->GREEN). Commit: feat(frontend) list. T4: PvData.tsx (single ?name= fetch, 4.1 row set with conditional Deleted/Local Path/CSI rows + Volume Attributes table, trimmed annotations, not-found state, JSON block) + pv_data.test.tsx (RED->GREEN). Commit: feat(frontend) data. T5: App.tsx ObjectRoute /storage/pv (cluster-scoped, no R7 redirect) + stub removal (Stub/routes.ts, Stub.test viewPaths, ui-smoke REAL_ROUTES). Commit: feat(frontend) wire. Floor: pytest, targeted vitest, fe-build + fe-check + fe-sync, e2e, ruff/mypy flat, live dev-cluster verification.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Verification floor (2026-11-05, all on rebase): backend uv run pytest -m 'not integration' 640 passed (incl. new test_k8s_pvs.py 8 service + 6 API, RED->GREEN); targeted vitest 41/41 (pvs 8, pv_data 5, five trimmed data views 23, Stub); full vitest: 12 pre-existing failures in groups/users/admin_permissions (datatables.net window.alert in jsdom; files last touched 9113ce16/ddeb51ef, pre-dating this change); task fe-build + fe-check (air gap) + fe-sync green; task e2e 19/19 (ui-smoke /storage/pv as REAL route, auth-smoke); ruff/mypy flat vs baseline (105/81 both sides - no new lint debt). Live dev cluster (kind kubedash-test, cluster id 7): /storage/pv list under ns=kubedash-demo renders pvc-3fe50822 (Bound, standard, demo-pvc, 100Mi; hidden under ns=default per claim-ns filter); data view renders the full 4.1 row set + trimmed annotations table + JSON block; URL stays clean /storage/pv (ADR-0040, identity in the session ref). Commits: 6c8c6946 spec, fa6b1e27 T1, ab9b2e18 T3, f7c8223d T2, f3759ab7 docs, 6de151f5 T4, 9c733235 T5.

2026-11-05 (user: 'Persistent Volume usage data is missing'): the PV list gained a Usage column — 5.0 addition (4.1's PV view had no usage). Reuses the PVC list's observed tier verbatim: second parallel /metrics/pvcs fetch (shared pvc-usage query key) joined by claim name (the claim-ns filter makes the join sound); free PVs + ADR-0003 degrades render '—'. 4 new tests (join/unavailable/denied/fetch-fail), free-pv dash count 2->3, column assertion +Usage: pvs 12/12. Floor re-run: fe-build + fe-check + fe-sync green, e2e 19/19, live: column renders with honest '—' on kind 1.35 (hostPath PVs emit no pvcRef stats — same as the PVC list; metrics_available true, items []).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
4.1-parity PV views built at /storage/pv: backend persistentvolumes kind (core, cluster-scoped, claim-ns filtered, SAR-gated), Pv list (4.1 columns, Terminating override, cross-kind refs) + PvData (4.1 rows, conditional rows, JSON block), ADR-0040 object-ref navigation, stub removed. Companion T2: the five storage data views now trim machine-managed annotations (2026-11-05 user decision, overrides the 2026-10-28 verbatim deviation; HPA 46929a10 precedent) with adr.md override notes in the five specs. Verified: backend 640/640, targeted vitest 41/41, fe-build/fe-check/fe-sync, e2e 19/19, live cluster list+data+trim checks.
<!-- SECTION:FINAL_SUMMARY:END -->
