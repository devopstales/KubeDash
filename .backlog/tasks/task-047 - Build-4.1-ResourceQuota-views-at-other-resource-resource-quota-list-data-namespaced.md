---
id: TASK-047
title: >-
  Build 4.1 ResourceQuota views at /other-resource/resource-quota (list + data,
  namespaced)
status: In Progress
assignee: []
created_date: '2026-10-28 12:35'
updated_date: '2026-10-28 12:49'
labels:
  - feature
dependencies: []
references:
  - '4.1:src/kubedash/templates/other-resources/resource-quota.html.j2'
  - '4.1:src/kubedash/templates/other-resources/resource-quota-data.html.j2'
  - '4.1:src/kubedash/lib/k8s/other.py (k8sQuotaListGet'
  - line 203)
  - 'kubedash_4:backend/app/api/resources.py'
  - .skillgrid/specs/2026-10-28-resourcequota-views/
priority: medium
ordinal: 43000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The nav leaf 'Resource Quota -> /other-resource/resource-quota' (_nav.tsx:114) currently renders a stub (views/Stub/routes.ts:26). 4.1 HAS real templates for this kind (unlike RuntimeClass): other-resources/resource-quota.html.j2 (list: Name/Namespace/Request/Limit) + resource-quota-data.html.j2 (data: Name/Created/Namespace/Creation/Selectors/Scopes/Annotations/Labels/Status table) + k8sQuotaListGet (lib/k8s/other.py:203, CoreV1Api, NAMESPACED — session ns_select). Port the shape to 5.0 with the ratified deltas: ?name= query-param navigation (no hidden forms/sessionStorage), JSON full-object block with the json hljs grammar on the data page, CoreUI/KubeDataTable, SAR gating per ADR-0004 on the generic /resources route. Backend: k8s_client.py gains list_resource_quotas (CoreV1Api list_namespaced_resource_quota OR list_resource_quota_for_all_namespaces, to_dict, namespace param) + get_resource_quotas (read_namespaced_resource_quota, 404 -> [], other ApiException -> _unreachable) mirroring list_secrets/get_secret; resources.py adds _KINDS['resourcequotas'] = ('list_resource_quotas', 'resourcequotas', '') and _GETTERS['resourcequotas'] = 'get_resource_quotas'. Frontend: ResourceQuotaItem in types.ts (metadata, spec.scopes, spec.scope_selector, status.hard, status.used); views/OtherResource/ResourceQuota.tsx (KubeDataTable columns Name/Namespace/Requests/Limits/Created — Request & Limit cells show requests.cpu, requests.memory, limits.cpu, limits.memory as used/hard, missing keys render as em dash; name links to the data page with ?name=&namespace=); views/OtherResource/ResourceQuotaData.tsx (single ?name=&namespace= fetch, CTable Name/Created/Namespace/Scope/Labels/Annotations/Status table, NOT_FOUND as a state 'No ResourceQuota '<name>' found', full-object JSON block via SyntaxHighlighter language=json style anOldHope). App.tsx routes /other-resource/resource-quota + /other-resource/resource-quota/data; remove the stub route; _nav.tsx leaf unchanged. Full spec: .skillgrid/specs/2026-10-28-resourcequota-views/
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GET /api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns> returns the quota list for that namespace, SAR-gated on list resourcequotas (core, group ''), 403 RBAC_DENIED on deny; without a namespace param the list spans all namespaces
- [ ] #2 GET /api/v1/clusters/<id>/resources/resourcequotas?name=<name>&namespace=<ns> returns the single ResourceQuota via _GETTERS; 404 -> empty items
- [ ] #3 frontend ResourceQuota.tsx renders the list with Name/Namespace/Requests/Limits/Created columns; Request and Limit cells show requests.cpu, requests.memory, limits.cpu, limits.memory as used/hard (missing -> em dash); card title exactly 'Resource Quota List'; name links to the data page
- [ ] #4 frontend ResourceQuotaData.tsx renders detail at /other-resource/resource-quota/data?name=&namespace= via a single fetch; CTable Name/Created/Namespace/Scope/Labels/Annotations + Status table (Resource/Used/Hard Limit); NOT_FOUND is a first-class state; full-object JSON block (json hljs grammar)
- [ ] #5 /other-resource/resource-quota removed from views/Stub/routes.ts; App.tsx wires both views; _nav.tsx leaf unchanged
- [ ] #6 Backend tests: tests/services/test_k8s_client_resourcequotas.py (namespaced list, all-ns list, get hit/404/5xx) + test_resources.py extensions (200, namespace scoping, get-by-name, SAR deny, binding 404, singular kind rejected)
- [ ] #7 Frontend tests: resource_quotas.test.tsx + resource_quota_data.test.tsx (mirror network_policies / priority_class_data patterns); Stub.test.tsx updated
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
## Implementation plan — /other-resource/resource-quota (4.1 port, TASK-047)

Spec zone complete: .skillgrid/specs/2026-10-28-resourcequota-views/ (briefing.md R1-R5, blueprint.md, adr.md, acceptance.feature). Blueprint is the plan of record; summary below.

Tracer thread, 4 commits, each independently revertable:

### T1 — Backend: resourcequotas kind (core, namespaced, SAR-gated)
- k8s_client.py: list_resource_quotas(namespace: str|None) (list_namespaced_resource_quota OR list_resource_quota_for_all_namespaces, to_dict, _unreachable on ApiException) + get_resource_quota(namespace, name) (read_namespaced_resource_quota, 404 -> [], else _unreachable). No __init__ change (self._v1 exists).
- resources.py: _KINDS["resourcequotas"] = ("list_resource_quotas", "resourcequotas", "") + _GETTERS["resourcequotas"] = "get_resource_quota" — both rows land in the same commit as the methods (getattr seam).
- Tests: new tests/services/test_k8s_client_resourcequotas.py (6 tests, object.__new__ + SimpleNamespace, mirror secrets) + test_resources.py (FakeK8s methods + 6 tests: 200-in-ns, all-namespaces w/o param, get-by-name hit/miss, SAR denied w/ asked-assertion, binding 404, singular kind rejected).
- TDD: RED on new service tests -> implement -> GREEN.
- Commit: feat(resources): resourcequotas kind (core, namespaced, SAR-gated)

### T2 — Frontend: list view (independent of T3 after T1)
- types.ts: ResourceQuotaItem (metadata, spec.scopes/scope_selector, status.hard/used).
- views/OtherResource/ResourceQuota.tsx: KubeDataTable; namespace = useClusterStore.selectedNamespace ?? 'default' (NetworkPolicy pattern); card title EXACTLY 'Resource Quota List'; columns Name(link)/Namespace/Requests/Limits/Created; cell = '<key>: <used> / <hard>' with '—' for missing keys (certainty rule, 4.1 would KeyError); name link is the SOLE producer of ?name=&namespace= (row's OWN namespace); fetch /api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns>; pinned states (No cluster selected. / Loading resource quotas... / No resource quotas found).
- Test: resource_quotas.test.tsx (clone network_policies.test.tsx pattern; fetch URL exact, cell contents, missing-key dashes, empty/error/no-cluster states).
- Commit: feat(frontend): resource quota list view (4.1 port, namespaced)

### T3 — Frontend: data view (independent of T2 after T1)
- views/OtherResource/ResourceQuotaData.tsx: clone PriorityClassData.tsx; single ?name=&namespace= fetch (query enabled on cluster+name+namespace); CTable Name/Created/Namespace/Scope/Labels/Annotations; Status table Resource/Used/Hard Limit over 4.1's four dims in 4.1's order (limits.cpu, limits.memory, requests.cpu, requests.memory) with '—' for missing; full-object JSON.stringify(item,null,2) block, hljs grammar json (truthful-classifier rule), style anOldHope; miss = state 'No ResourceQuota '<name>' found' (not error); missing name = 'Error: resource quota name not provided'.
- Test: resource_quota_data.test.tsx (clone priority_class_data.test.tsx; single-fetch assertion, status table rows, not-found state w/o .text-danger, missing-name; type server.use spreads AnyHandler[] — tsc covers test files).
- Commit: feat(frontend): resource quota data view (4.1 tables + JSON block)

### T4 — Routing + stub removal + full verification
- App.tsx: two ProtectedRoute entries (mirror priorityclass block).
- Stub/routes.ts: drop line 26; Stub.test.tsx: drop the Resource Quota expectation. _nav.tsx UNCHANGED (verified via git diff --stat).
- Verify: task fe-build (tsc+lint+build) + task fe-check (air-gap) + pnpm vitest run + uv run pytest -m "not integration" -q.
- Commit: feat(frontend): wire resource-quota routes, remove stub

Key risks/pins: (1) _KINDS+_GETTERS rows are one behavior — 500 if a getter method is missing; (2) data view must treat items:[] as not-found state, not error; (3) pinned copy is verbatim (e2e smoke contract: 'Resource Quota List'); (4) fe-build typechecks tests.

Verification floor at end: the blueprint's 4 commands + git diff --stat shows only File-Structure files touched.
<!-- SECTION:PLAN:END -->
