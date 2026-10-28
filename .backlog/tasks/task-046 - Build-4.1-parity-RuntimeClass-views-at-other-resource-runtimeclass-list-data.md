---
id: TASK-046
title: >-
  Build 4.1-parity RuntimeClass views at /other-resource/runtimeclass (list +
  data)
status: In Progress
assignee: []
created_date: '2026-10-28 12:19'
updated_date: '2026-10-28 12:50'
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
- [ ] #1 GET /api/v1/clusters/<id>/resources/runtimeclasses returns the RuntimeClass list, SAR-gated on list runtimeclasses (node.k8s.io), 403 RBAC_DENIED on deny
- [ ] #2 GET /api/v1/clusters/<id>/resources/runtimeclasses?name=<name> returns the single RuntimeClass via _GETTERS; 404 -> empty items
- [ ] #3 frontend RuntimeClass.tsx renders the list with Name/Handler/Overwrite Node Sel No Toleration/Pod Level Overhead/Created columns; card title exactly 'Runtime Classes'; name links to the data page
- [ ] #4 frontend RuntimeClassData.tsx renders detail at /other-resource/runtimeclass/data?name= via a single ?name= fetch; NOT_FOUND is a first-class state; labels/annotations tables; full-object JSON block (json hljs grammar)
- [ ] #5 /other-resource/runtimeclass removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [ ] #6 Backend tests: new tests/services/test_k8s_client_runtimeclasses.py (list ignores namespace, get hit/404/5xx) + test_resources.py extensions (200, ignores namespace, get-by-name hit/miss, SAR deny, binding 404, singular kind rejected)
- [ ] #7 Frontend tests: runtime_classes.test.tsx + runtime_class_data.test.tsx (mirror priority_class tests); Stub.test.tsx updated for the removed route
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
## Implementation plan (2026-10-28, execution session)

Executing `.skillgrid/specs/2026-10-28-runtimeclass-views/blueprint.md` end-to-end, 4 tasks in order, TDD per task (RED evidence captured before implementing), one conventional commit per task after its gate is green.

- T1 backend: k8s_client.py (NodeV1Api self._node + list_runtime_classes + get_runtime_class) + resources.py (_KINDS/_GETTERS runtimeclasses, node.k8s.io) + new tests/services/test_k8s_client_runtimeclasses.py + test_resources.py FakeK8s + 6 tests. Commit: feat(resources): runtimeclasses kind (node.k8s.io, cluster-scoped, SAR-gated)
- T2 frontend list: types.ts RuntimeClassItem + views/OtherResource/RuntimeClass.tsx + tests/views/runtime_classes.test.tsx (clone of priority_classes.test.tsx). Commit: feat(frontend): runtimeclass list view (Other Resources, 4.1-parity nav leaf)
- T3 frontend data: views/OtherResource/RuntimeClassData.tsx + tests/views/runtime_class_data.test.tsx (clone of priority_class_data.test.tsx; AnyHandler typing for MSW spreads). Commit: feat(frontend): runtimeclass data view (single ?name= fetch, JSON block)
- T4 routing: App.tsx two routes + views/Stub/routes.ts line 28 removal + Stub.test.tsx expectation update. Commit: feat(frontend): wire runtimeclass routes, remove stub

Verification floor: targeted pytest + full unit suite (3 Docker kind-fixture errors = baseline), targeted vitest (runtime_classes, runtime_class_data, Stub), task fe-build, task fe-check, git diff --stat (no _nav.tsx, no files outside blueprint File Structure).

Known baselines (do not fix): backend 3 kind-fixture errors (missing Docker); frontend users/groups/admin_permissions failures. Unrelated dirty files (.skillgrid/cache/mnemonic/*, .backlog/tasks/task-045..047, .skillgrid/specs/2026-10-28-resourcequota-views/) never staged.
<!-- SECTION:PLAN:END -->
