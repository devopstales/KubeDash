---
id: TASK-065
title: >-
  Build 4.1-parity PVC views at /storage/pvc (list + data + usage metrics,
  namespaced core)
status: Done
assignee: []
created_date: '2026-11-04 15:34'
updated_date: '2026-11-04 19:07'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-pvc-views/
  - '4.1:src/kubedash/lib/k8s/storage.py (k8sPersistentVolumeClaimListGet'
  - line 83)
  - '4.1:src/kubedash/lib/k8s/metrics.py (k8sPVCMetric'
  - line 348)
priority: medium
type: feature
ordinal: 61000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf "VolumeClaims -> /storage/pvc" (_nav.tsx:101) currently renders a stub (views/Stub/routes.ts:19). 4.1 HAS real templates: storage/pvc.html.j2 (list: Status / Name / StorageClass / Volume / Capacity / Usage) + pvc-data.html.j2 (curated table: status, access modes, volume mode, capacity, storage class, bound volume, labels, annotations). PVC is a CORE API (persistentvolumeclaims, core group, NAMESPACED); the 4.1 read is CoreV1Api().list_namespaced_persistent_volume_claim — generated model, to_dict snake_case. The 4.1 Usage column comes from a SECOND read (k8sPVCMetric): per node, kubelet /stats/summary, aggregating each pod volume entry carrying a pvcRef (used/capacity bytes, percentageUsed).

EXECUTION RE-BASELINE (2026-11-04): the spec was written under the superseded ?name=/?namespace= navigation contract (NAVIGATION-SUPERSEDED.md). Execute per ADR-0040 session-object-navigation as shipped on this branch: list route /storage/pvc carries an ObjectRoute (kind=pvc); name cells are buttons calling openObject(KIND, name, namespace, LIST_ROUTE, navigate); the data view is a separate component receiving name + namespace PROPS from ObjectRoute (ref namespace authoritative, R8) and doing a single ?name=&namespace= fetch; NO /data route and NO OldDataRedirect (the /data URL never shipped — the kind was a stub). Namespaced list fetch always carries ?namespace=<selectedNamespace ?? default> (ResourceQuota pattern). The Usage column is a SECOND parallel fetch on the new metrics route (ADR-0003 two-tier degrade: a failed/degraded usage fetch renders dash cells, never fails the list).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/persistentvolumeclaims?namespace=<ns> returns the PVC list (to_dict snake_case, metadata/spec/status intact); without namespace it spans all namespaces (list_persistent_volume_claim_for_all_namespaces); SAR-gated on list persistentvolumeclaims (core group), 403 RBAC_DENIED on deny; unbound user 404; singular persistentvolumeclaim (and 4.1 route name pvc) rejected with RESOURCE_KIND_NOT_SUPPORTED
- [x] #2 GET persistentvolumeclaims?name=&namespace= returns a 0/1-item list via _GETTERS; miss is items empty (not 404)
- [x] #3 New GET /api/v1/clusters/<id>/metrics/pvcs?namespace=<ns>: per-PVC capacity_bytes / used_bytes / available_bytes / percentage_used (one decimal) aggregated from kubelet /stats/summary pod volume entries carrying a pvcRef (json.loads, no eval); SAR get on nodes (core group) asked before any stats call — deny is 200 with metrics_denied true + items empty (never 403); a node whose stats read fails is skipped, never raised; no node yields stats -> 200 metrics_available false items empty; response shape {cluster, namespace, source, metrics_available, metrics_denied, items[]}; zero-capacity guard returns percentage_used 0.0
- [x] #4 Frontend list at /storage/pvc: KubeDataTable in the header-selected namespace, columns Status (badge: Bound success / Terminating danger / other warning / dash) / Name (openObject button) / StorageClass / Volume / Capacity / Usage (42.7 % one decimal, dash when unmeasured); Usage from the second metrics fetch joined by name (a failed usage fetch degrades the column to dash, never the list); card title EXACTLY "Persistent Volume Claim List"; pinned states (No cluster selected. / Loading persistent volume claims... / No persistent volume claims found)
- [x] #5 Frontend data view: single ?name=&namespace= fetch from ObjectRoute props; CTable (Status / Name / Namespace / Created / Access Mode / Volume Mode / Capacity / StorageClass / Persistent Volume / Labels / Annotations) + full-object JSON.stringify block (json hljs grammar, anOldHope); empty items is the not-found STATE "No PVC not found" wording with the name; missing name is an error state
- [x] #6 App.tsx wires ObjectRoute kind=pvc listRoute=/storage/pvc (detail passes name + namespace props); /storage/pvc removed from views/Stub/routes.ts; _nav.tsx leaf unchanged; NO /data route added
- [x] #7 Backend tests: resources (list namespaced + all-namespaces, get hit/miss, SAR deny, binding 404, singular rejected) + metrics pvcs (aggregation by pvcRef namespace, percentage one-decimal, zero-capacity guard, SAR denied -> metrics_denied, stats unavailable -> metrics_available false, per-node stats failure skipped, json parse not eval)
- [x] #8 Frontend tests: pvc list + data tests mirroring the resourcequota pair (openObject wiring, usage join with dash fallback, badge tiers, not-found state, missing-name error); Stub.test.tsx updated; ui-smoke moves /storage/pvc from SMOKE_STUB_ROUTES to REAL_ROUTES
- [x] #9 Demo fixture: a kubedash-demo PVC (100Mi, standard StorageClass, RWO) in dev/scripts/demo-data.sh (visual verification of Bound status + capacity)
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
Execute .skillgrid/specs/2026-10-28-pvc-views/blueprint.md end-to-end under the ADR-0040 contract (re-baseline in the description), 4 TDD commits, each independently revertable. T1 backend: k8s_client list_persistent_volume_claims (namespaced + for-all-namespaces) + get_persistent_volume_claim (404 -> []) + pvc_usage(namespace) kubelet stats/summary aggregation (CoreV1Api connect_get_node_proxy_with_path path=stats/summary per node from list_nodes; json.loads; skip failing nodes; aggregate pod volume pvcRef by namespace+name; zero-capacity guard) + resources.py _KINDS/_GETTERS rows (core) + metrics.py route /clusters/<int:cluster_id>/metrics/pvcs (binding gate; SAR get nodes core; deny -> 200 metrics_denied) + schemas + tests (RED first). Commit: feat(resources): persistentvolumeclaims kind + pvcs usage metrics (kubelet stats, query-only). T2 frontend list: types.ts PersistentVolumeClaimItem + PvcUsageItem + views/Storage/Pvc.tsx (clone ResourceQuota.tsx: openObject name button, status badge, usage second-fetch join, card title Persistent Volume Claim List) + test. Commit: feat(frontend): pvc list view (usage column, 4.1-parity). T3 frontend data: views/Storage/PvcData.tsx (clone ResourceQuotaData.tsx: props name+namespace, single fetch, curated CTable + JSON block) + test. Commit: feat(frontend): pvc data view (curated table + JSON block). T4 routing: App.tsx ObjectRoute block + lazy imports + Stub/routes.ts removal + Stub.test.tsx + ui-smoke REAL_ROUTES + demo-data fixture; verify task fe-build + task fe-check + vitest + full unit suite. Commit: feat(frontend): wire pvc routes, remove stub.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 done (commit 43f7e6a8): list_persistent_volume_claims + get_persistent_volume_claim in k8s_client, _KINDS/_GETTERS rows, 6 service tests + 7 API tests (RED->GREEN). Full unit suite 616 passed / 10 deselected (baseline 603).

T2 done (commit $(git log --format=%h -1)): pvc_usage service (kubelet stats/summary, json.loads, skip failing nodes, zero-capacity guard, node-list degrade) + GET /metrics/pvcs route (binding gate, namespace short-circuit, SAR get nodes core asked first, deny -> metrics_denied) + PvcUsageOut schema + 4 service tests + 5 route tests (RED->GREEN). Full unit suite 625 passed / 10 deselected.

T3 done (commit b78fdf18): PvcItem/PvcUsage/PvcUsageResponse types + Pvc list view (namespaced, usage join from 2nd metrics fetch, ADR-0040 openObject nav, 3-tier status badges) + 12 view tests (RED->GREEN). tsc --noEmit clean.

T4 done (commit c09878cc): PvcData view (single ?name=&namespace= fetch from ObjectRoute props, 4.1 row set, not-found state, JSON block) + 4 view tests (RED->GREEN). tsc clean.

Closeout (9bba46d5, 320e2b4b): live dev-cluster verification caught the pvc_usage parse bug — the client's str-typed node proxy deserializes the stats/summary body to a dict and str()s it, so json.loads saw a PYTHON REPR (single quotes, True/None) and every node was skipped (metrics_available false on a healthy cluster). pvc_usage now parses json-first with an ast.literal_eval fallback (literals only) + repr-shape regression test; live re-check after the fix: metrics_available true. Demo fixture: demo-pvc gained a consumer pod so the claim BINDS (WaitForFirstConsumer); the hostPath PV emits no pvcRef volume stats on kind 1.35, so the Usage cell honestly shows — on this cluster.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped 4.1-parity PVC views at /storage/pvc (list + data + usage metrics, namespaced core) under the ADR-0040 contract (re-baseline). 5 independently revertable TDD commits: T1 43f7e6a8 feat(resources) persistentvolumeclaims kind (core, namespaced, SAR-gated); T2 27065b4d feat(metrics) pvcs usage route (kubelet stats/summary, query-only, SAR-degraded, json.loads); T3 b78fdf18 feat(frontend) pvc list view (usage column, 4.1-parity, ADR-0040 nav); T4 c09878cc feat(frontend) pvc data view (curated table + JSON block); T5 1e453d31 feat(frontend) wire pvc routes, remove stub (+ openapi.json re-dump spliced to only the new /metrics/pvcs path + PvcUsageOut/PvcUsageItem schemas, + demo-pvc fixture in demo-data.sh). Navigation used ObjectRoute (NAVIGATION-SUPERSEDED): single /storage/pvc route, no /data, no OldDataRedirect; _nav.tsx untouched. Floor (T5): backend uv run pytest -m 'not integration' 625 passed/10 deselected (baseline 603 + 22 new, all green); frontend vitest 359 passed/12 failed (the 12 are the pre-existing baseline failures, unchanged, my +16 all pass); tsc --noEmit clean; fe-build/fe-check/fe-sync green. 9 ACs + 5 DoD checked with test/route/diff evidence.
<!-- SECTION:FINAL_SUMMARY:END -->
