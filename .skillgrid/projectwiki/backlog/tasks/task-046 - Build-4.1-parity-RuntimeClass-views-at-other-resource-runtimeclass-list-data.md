---
id: TASK-046
title: >-
  Build 4.1-parity RuntimeClass views at /other-resource/runtimeclass (list +
  data)
status: Done
assignee: []
created_date: '2026-10-28 12:19'
updated_date: '2026-10-29 15:49'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-runtimeclass-views/
priority: medium
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'Runtime Class -> /other-resource/runtimeclass' (_nav.tsx:116) currently renders a stub (views/Stub/routes.ts:28). 4.1 has NO runtimeclass template (dead nav link in 4.1; the kind appears only in its RBAC template ClusterRoles), so 'based on 4.1' means 4.1's placement (Other Resources, ratified deviation ADR-0022) + its RBAC treatment (runtimeclasses is cluster-scoped, node.k8s.io/v1), with the page shape taken from the ratified 5.0 PriorityClass precedent (list + data views) and TASK-032's _KINDS/SAR pattern.

Backend:
1. k8s_client.py: list_runtime_classes (NodeV1Api.list_runtime_class, to_dict, mirror list_priority_classes lines 264-273) + get_runtime_class (read_runtime_class, 404 -> [], other ApiException -> _unreachable, mirror get_priority_class lines 775-786). Client __init__ must expose a NodeV1Api attribute (self._node) alongside _scheduling.
2. resources.py: _KINDS['runtimeclasses'] = ('list_runtime_classes', 'runtimeclasses', 'node.k8s.io'); _GETTERS['runtimeclasses'] = 'get_runtime_class'. No new route — the generic list_resources route handles list + ?name=. SAR is automatic: get/list on runtimeclasses, group node.k8s.io, namespace None.

Frontend:
3. types.ts: RuntimeClassItem (metadata, handler, overwrite_node_sel_no_toleration, scheduling, pod_level_overhead) — to_dict snake_case, cluster-scoped.
4. views/OtherResource/RuntimeClass.tsx: clone PriorityClass.tsx (breadcrumb, card title EXACTLY 'Runtime Classes', KubeDataTable). Columns: Name (links to data page), Handler, Overwrite Node Sel No Toleration, Pod Level Overhead (cpu + memory compact, e.g. '100m / 128Mi', or dash), Created. Query key ['runtimeclasses', clusterId]; empty state 'No runtime classes found'.
5. views/OtherResource/RuntimeClassData.tsx: clone PriorityClassData.tsx — single ?name= fetch (no 4.1 list-then-filter), NOT_FOUND -> 'No RuntimeClass '<name>' found' (state, not error), CTable (Name/Kind/Created/Handler/Overwrite Node Sel No Toleration/Pod Level Overhead/Labels/Annotations), full-object JSON block via SyntaxHighlighter language=json (truthful-classifier rule ratified for PriorityClassData final review 2026-10-28), style anOldHope, JSON.stringify(item, null, 2).
6. App.tsx: route /other-resource/runtimeclass + /other-resource/runtimeclass/data (mirror the priorityclass block, lines 367-375). Remove /other-resource/runtimeclass from views/Stub/routes.ts. Nav leaf unchanged.

Ratified deviations (record in docstrings): (1) 4.1 had no RuntimeClass page — list+data shape follows the 5.0 PriorityClass precedent, not a 4.1 template; (2) Other Resources placement per ADR-0022; (3) ?name= query-param navigation, no sessionStorage/hidden-form workarounds; (4) JSON block with json hljs grammar.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/clusters/<id>/resources/runtimeclasses returns the RuntimeClass list, SAR-gated on list runtimeclasses (node.k8s.io), 403 RBAC_DENIED on deny
- [x] #2 GET /api/v1/clusters/<id>/resources/runtimeclasses?name=<name> returns the single RuntimeClass via _GETTERS; 404 -> empty items
- [x] #3 frontend RuntimeClass.tsx renders the list with Name/Handler/Overwrite Node Sel No Toleration/Pod Level Overhead/Created columns; card title exactly 'Runtime Classes'; name links to the data page
- [x] #4 frontend RuntimeClassData.tsx renders detail at /other-resource/runtimeclass/data?name= via a single ?name= fetch; NOT_FOUND is a first-class state; labels/annotations tables; full-object JSON block (json hljs grammar)
- [x] #5 /other-resource/runtimeclass removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [x] #6 Backend tests: new tests/services/test_k8s_client_runtimeclasses.py (list ignores namespace, get hit/404/5xx) + test_resources.py extensions (200, ignores namespace, get-by-name hit/miss, SAR deny, binding 404, singular kind rejected)
- [x] #7 Frontend tests: runtime_classes.test.tsx + runtime_class_data.test.tsx (mirror priority_class tests); Stub.test.tsx updated for the removed route
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
## Implementation plan (2026-10-28, execution session)

Executing `.skillgrid/specs/2026-10-28-runtimeclass-views/blueprint.md` end-to-end, 4 tasks in order, TDD per task (RED evidence captured before implementing), one conventional commit per task after its gate is green.

- T1 backend: k8s_client.py (NodeV1Api self._node + list_runtime_classes + get_runtime_class) + resources.py (_KINDS/_GETTERS runtimeclasses, node.k8s.io) + new tests/services/test_k8s_client_runtimeclasses.py + test_resources.py FakeK8s + 6 tests. Commit: feat(resources): runtimeclasses kind (node.k8s.io, cluster-scoped, SAR-gated)
- T2 frontend list: types.ts RuntimeClassItem + views/OtherResource/RuntimeClass.tsx + tests/views/runtime_classes.test.tsx (clone of priority_classes.test.tsx). Commit: feat(frontend): runtimeclass list view (Other Resources, 4.1-parity nav leaf)
- T3 frontend data: views/OtherResource/RuntimeClassData.tsx + tests/views/runtime_class_data.test.tsx (clone of priority_class_data.test.tsx; AnyHandler typing for MSW spreads). Commit: feat(frontend): runtimeclass data view (single ?name= fetch, JSON block)
- T4 routing: App.tsx two routes + views/Stub/routes.ts line 28 removal + Stub.test.tsx expectation update. Commit: feat(frontend): wire runtimeclass routes, remove stub

Verification floor: targeted pytest + full unit suite (3 Docker kind-fixture errors = baseline), targeted vitest (runtime_classes, runtime_class_data, Stub), task fe-build, task fe-check, git diff --stat (no _nav.tsx, no files outside blueprint File Structure).

Known baselines (do not fix): backend 3 kind-fixture errors (missing Docker); frontend users/groups/admin_permissions failures. Unrelated dirty files (.skillgrid/cache/mnemonic/*, .backlog/tasks/task-045..047, .skillgrid/specs/2026-10-28-resourcequota-views/) never staged.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T1 backend DONE — commit 718eda35 "feat(resources): runtimeclasses kind (node.k8s.io, cluster-scoped, SAR-gated)". RED: 4 service tests failed with AttributeError (no list_runtime_classes/get_runtime_class/_node). GREEN: 4/4 service tests pass; test_resources.py 65 passed + 3 known kind-fixture ScopeMismatch errors (kind_client session-vs-function app fixture; pre-existing, not Docker-related — Docker is up). Full unit suite: 471 passed, 10 deselected in ~182s, RC 0. Note: kind-tier pytest hangs on exit (testcontainers teardown dials 1.2.3.4 SYN_SENT); ran it interruptible.

T2 frontend list DONE — commit 7580d592 "feat(frontend): runtimeclass list view (Other Resources, 4.1-parity nav leaf)". RED: vitest failed to resolve src/views/OtherResource/RuntimeClass. GREEN: 5/5 tests pass (rows+data-links, overhead rendering incl. em-dash, no-cluster, error, empty state). Note: git post-commit hook (skillgrid mnemonic) is slow — commits can exceed the 120s shell timeout; commit itself lands, wait for the hook.

HANDOFF (2026-10-28, execution complete): commits on `rebase` — 718eda35 T1 backend, 7580d592 T2 list view, 33adbbe7 T3 data view, 786100f5 T4 routing/stub removal, cab0e37a state.yaml. RED/GREEN captured per task. Verification floor: backend unit 471 passed (3 known kind-fixture ScopeMismatch errors remain, pre-existing); targeted vitest 14/14; fe-build + fe-check green; git diff --stat vs 718eda35^ shows no _nav.tsx and only blueprint File Structure files (the mnemonic cache md files in the diff belong to the concurrent e7536e83 backlog commit, not to this change). Deviations from blueprint: (1) none in code — implementation matched the blueprint's exact test/implementation snippets (RuntimeClassItem gained an index signature to match the sibling PriorityClassItem pattern, which the view's toRow tolerates via typed fields). (2) Environment: the 3 kind-fixture errors are ScopeMismatch (kind_client session-scoped vs function-scoped app fixture), not missing-Docker as the baseline note said — Docker is up; they are pre-existing and unchanged. (3) The kind-tier pytest hangs at exit (testcontainers teardown dials 1.2.3.4); I ran it interruptible (SIGINT after the run printed its summary). (4) Full vitest suite has pre-existing failures beyond users/groups/admin_permissions: node.test.tsx 'node-detail-renders' (1 test, verified failing at HEAD with my work stashed — not introduced by this change). Orchestrator: QA gate + code review next.
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
Resolves the dead 4.1 nav leaf '/other-resource/runtimeclass' to a real, SAR-gated, read-only list + data pair under Other Resources (ADR-0022 placement; 5.0 PriorityClass precedent for shape — 4.1 had no runtimeclass template).

What changed (4 commits on `rebase`, each independently revertable):
- 718eda35 backend: K8sClient.list_runtime_classes/get_runtime_class (kubernetes NodeV1Api, node.k8s.io/v1, cluster-scoped; namespace arg accepted-and-ignored; 404 -> [] ; other ApiException -> 502 ClusterUnreachableError); resources.py _KINDS+_GETTERS rows — no new route (the generic list_resources serves list and ?name=, SAR gate automatic: list/get on runtimeclasses, group node.k8s.io, namespace None).
- 7580d592 frontend list: RuntimeClassItem type + views/OtherResource/RuntimeClass.tsx (KubeDataTable, card title exactly 'Runtime Classes', columns Name/Handler/Overwrite Node Sel No Toleration/Pod Level Overhead/Created, name links to data page, pinned states).
- 33adbbe7 frontend data: views/OtherResource/RuntimeClassData.tsx — single ?name= fetch (no 4.1 list-then-filter), NOT_FOUND as pinned STATE ('No RuntimeClass '<name>' found', muted, no error styling), CTable with labels/annotations sub-tables, full-object JSON block (JSON.stringify, hljs json grammar, anOldHope).
- 786100f5 routing: App.tsx wires /other-resource/runtimeclass + /data; views/Stub/routes.ts drops the stub entry; Stub.test.tsx updated. _nav.tsx byte-identical (verified via git diff --stat). cab0e37a: state.yaml in_flight entry.

Tests: backend tests/services/test_k8s_client_runtimeclasses.py (4 tests) + test_resources.py 6 new tests (list 200, ignores namespace, get-by-name hit/miss, SAR denied with node.k8s.io group assertion, binding 404, singular kind rejected); frontend tests/views/runtime_classes.test.tsx (5 tests) + runtime_class_data.test.tsx (4 tests), Stub.test.tsx updated.

Verification: backend unit suite 471 passed / 10 deselected; test_resources.py 65 passed + 3 known kind-fixture ScopeMismatch errors (pre-existing baseline); targeted vitest 14/14; task fe-build (tsc+eslint+vite) green; task fe-check (air-gap) green; full vitest run shows only pre-existing failures (users/groups/admin_permissions + one node.test.tsx detail test).

Handoff: QA gate + code review are the orchestrator's next step. Spec files in .skillgrid/specs/2026-10-28-runtimeclass-views/ were already committed in the spec commit (dfab2f25); no spec drift during execution.
<!-- SECTION:FINAL_SUMMARY:END -->
