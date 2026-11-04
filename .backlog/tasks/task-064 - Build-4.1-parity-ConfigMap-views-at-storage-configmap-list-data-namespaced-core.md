---
id: TASK-064
title: >-
  Build 4.1-parity ConfigMap views at /storage/configmap (list + data,
  namespaced core)
status: Done
assignee: []
created_date: '2026-11-04 15:33'
updated_date: '2026-11-04 16:54'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-configmap-views/
  - '4.1:src/kubedash/lib/k8s/storage.py (k8sConfigmapListGet'
  - line 200)
priority: medium
type: feature
ordinal: 60000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf "ConfigMaps -> /storage/configmap" (_nav.tsx:99) currently renders a stub (views/Stub/routes.ts:17). 4.1 HAS real templates: storage/configmap.html.j2 (list: Name / Created — deliberately sparse) + configmap-data.html.j2 (metadata table + per-key data table with pre/code values). ConfigMap is a CORE API (configmaps, core group, NAMESPACED); the 4.1 read is CoreV1Api().list_namespaced_config_map — generated model, to_dict snake_case. Port the 4.1 shape to 5.0 with the ratified deltas (briefing.md R1-R5): list gains a Data Keys count column (free — data is public on the list read, unlike secrets); data page ADDS the full-object JSON block (json hljs grammar, truthful classifier); single ?name=&namespace= fetch on the data page (no list-then-filter); SAR-gated per ADR-0004 on the generic /resources route.

EXECUTION RE-BASELINE (2026-11-04): the spec was written under the superseded ?name=/?namespace= navigation contract (NAVIGATION-SUPERSEDED.md). Execute per ADR-0040 session-object-navigation as shipped on this branch: list route /storage/configmap carries an ObjectRoute (kind=configmap); name cells are buttons calling openObject(KIND, name, namespace, LIST_ROUTE, navigate); the data view is a separate component receiving name + namespace PROPS from ObjectRoute (ref namespace authoritative, R8) and doing a single ?name=&namespace= fetch; NO /data route and NO OldDataRedirect (the /data URL never shipped — the kind was a stub). Namespaced list fetch always carries ?namespace=<selectedNamespace ?? default> (ResourceQuota pattern).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/configmaps?namespace=<ns> returns the ConfigMap list (to_dict snake_case, metadata/data/binaryData intact); without namespace it spans all namespaces (list_config_map_for_all_namespaces); SAR-gated on list configmaps (core group), 403 RBAC_DENIED on deny; unbound user 404
- [x] #2 GET configmaps?name=&namespace= returns a 0/1-item list via _GETTERS; miss is items empty (not 404); singular configmap rejected with RESOURCE_KIND_NOT_SUPPORTED
- [x] #3 Frontend list at /storage/configmap: KubeDataTable in the header-selected namespace, columns Name (openObject button) / Data Keys / Created; Data Keys = Object.keys(data ?? {}).length (0 is a count, dash only when data absent); card title EXACTLY "Configmaps List"; pinned states (No cluster selected. / Loading configmaps... / No configmaps found)
- [x] #4 Frontend data view: single ?name=&namespace= fetch from ObjectRoute props; CTable (Name / Namespace / Kind / Created / Version / Labels / Annotations) + Data table (one row per data entry, value in pre/code, No data when absent) + full-object JSON.stringify block (json hljs grammar, anOldHope); empty items is the not-found STATE "No ConfigMap not found" wording with the name; missing name is an error state
- [x] #5 App.tsx wires ObjectRoute kind=configmap listRoute=/storage/configmap (detail passes name + namespace props); /storage/configmap removed from views/Stub/routes.ts; _nav.tsx leaf unchanged; NO /data route added
- [x] #6 Backend tests: list (namespaced + all-namespaces), get-by-name hit/miss, SAR deny, binding 404, singular kind rejected
- [x] #7 Frontend tests: configmap list + data tests mirroring the resourcequota pair (openObject wiring, fetch URLs with namespace, data table rows, not-found state, missing-name error); Stub.test.tsx updated; ui-smoke moves /storage/configmap from SMOKE_STUB_ROUTES to REAL_ROUTES
- [x] #8 Demo fixture: a kubedash-demo ConfigMap with data keys in dev/scripts/demo-data.sh (visual verification of Data Keys + data table)
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
Execute .skillgrid/specs/2026-10-28-configmap-views/blueprint.md end-to-end under the ADR-0040 contract (re-baseline in the description), 4 TDD commits, each independently revertable. T1 backend: k8s_client list_config_maps (namespaced + for-all-namespaces branch, no data stripping) + get_config_map (to_dict; 404 -> []) + resources.py _KINDS/_GETTERS rows (core group) + tests (RED first). Commit: feat(resources): configmaps kind (core, namespaced, SAR-gated). T2 frontend list: types.ts ConfigMapItem + views/Storage/ConfigMap.tsx (clone ResourceQuota.tsx pattern: openObject name button, namespace from store, Data Keys column, card title Configmaps List) + test. Commit: feat(frontend): configmap list view (4.1-parity, ADR-0040 nav). T3 frontend data: views/Storage/ConfigMapData.tsx (clone ResourceQuotaData.tsx: props name+namespace, single fetch, CTable + Data table pre/code + JSON block) + test. Commit: feat(frontend): configmap data view (data table + JSON block). T4 routing: App.tsx ObjectRoute block + lazy imports + Stub/routes.ts removal + Stub.test.tsx + ui-smoke REAL_ROUTES + demo-data fixture; verify task fe-build + task fe-check + vitest + full unit suite. Commit: feat(frontend): wire configmap routes, remove stub.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 done (commit 41620987): list_configmaps/get_configmap in k8s_client.py (no data stripping, 404->[], 5xx->unreachable), _KINDS/_GETTERS rows (core group), 6 service tests + 6 API tests. RED captured (6 AttributeError + 5 RESOURCE_KIND_NOT_SUPPORTED). GREEN: targeted 12/12; full suite 577 passed, 10 deselected (baseline 565).

T2 done (commit 373e7042): ConfigMapItem type + views/Storage/ConfigMap.tsx (namespaced ResourceQuota pattern: openObject name button w/ row namespace, Data Keys column 0-vs-dash, title 'Configmaps List') + 8 list tests. RED captured (module not found); vitest 8/8; tsc clean. T3 done (commit b08f2bb8): views/Storage/ConfigMapData.tsx (ObjectRoute props name+namespace, single ?name=&namespace= fetch, CTable Name/Namespace/Kind/Created/Version/Labels/Annotations verbatim + per-key Data CTable pre/code pre-wrap + JSON block anOldHope) + 5 data tests. RED captured (module not found); vitest 5/5; tsc clean.

T4 done (commit c966685e): App.tsx ObjectRoute kind=configmap listRoute=/storage/configmap, detail passes name+namespace props (NO /data route, no R7 redirect — first build); stub row dropped from views/Stub/routes.ts; Stub.test.tsx viewPaths updated (5/5); ui-smoke moves /storage/configmap SMOKE_STUB_ROUTES -> REAL_ROUTES; demo-data.sh gains demo-config (3 data keys incl. multi-line app-config), header + echo updated, bash -n OK. Floor: task fe-build green (tsc+eslint+vite, ConfigMap chunks built), task fe-check green, task fe-sync synced; vitest full 320 passed / 12 failed (the 12 pre-existing users/groups/admin_permissions failures; all 13 new configmap tests pass); git diff --stat 08e37b50..HEAD = exactly the 14 expected files, frontend/src/_nav.tsx untouched.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ConfigMap views (list + data, namespaced core) shipped per the ADR-0040 re-baseline: 4 TDD commits — 41620987 feat(resources): configmaps kind (core, namespaced, SAR-gated); 373e7042 feat(frontend): configmap list view (data-keys column, 4.1-parity, ADR-0040 nav); b08f2bb8 feat(frontend): configmap data view (per-key data table + JSON block); c966685e feat(frontend): wire configmap routes, remove stub. Verified: RED captured before each implementation (6 AttributeError + 5 RESOURCE_KIND_NOT_SUPPORTED; 2x module-not-found). Backend: 6 service + 6 API tests green; full uv run pytest -m 'not integration' = 577 passed, 10 deselected, 8 warnings (baseline 565 + 12 new). Frontend: 8 list + 5 data tests green; vitest full = 320 passed / 12 failed (only the 12 pre-existing users/groups/admin_permissions failures). task fe-build (tsc+eslint+vite), fe-check, fe-sync all green. Scope: git diff --stat 08e37b50..HEAD = exactly the 14 spec-zone files, frontend/src/_nav.tsx untouched. Demo fixture demo-config (3 data keys incl. multi-line) added to dev/scripts/demo-data.sh; ui-smoke moves /storage/configmap to REAL_ROUTES.
<!-- SECTION:FINAL_SUMMARY:END -->
