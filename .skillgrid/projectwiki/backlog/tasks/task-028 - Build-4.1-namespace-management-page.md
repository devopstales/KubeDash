---
id: TASK-028
title: Build 4.1 namespace management page
status: Done
assignee:
  - '@devopstales'
created_date: '2026-10-21 16:30'
updated_date: '2026-10-21 17:11'
labels: []
dependencies: []
references:
  - .skillgrid/specs/2026-10-21-namespace-page/briefing.md
  - .skillgrid/specs/2026-10-21-namespace-page/blueprint.md
  - .skillgrid/specs/2026-10-21-namespace-page/acceptance.feature
type: feature
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The /cluster/namespace route is still a placeholder, so operators cannot use the 4.1 namespace list or manage namespaces from the React SPA. Preserve the current multi-cluster resource API and selected-cluster behavior while restoring the approved 4.1 experience. Design: .skillgrid/specs/2026-10-21-namespace-page/briefing.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The selected cluster namespace list renders Status, Namespace, Repository, Pipeline, Created, and Action in the 4.1 DataTable structure
- [x] #2 KubeDash admins with Kubernetes authorization can create valid namespaces and delete non-protected namespaces
- [x] #3 Non-admin users cannot see mutation controls and mutation endpoints reject unauthorized callers
- [x] #4 default, kube-system, kube-public, and kube-node-lease cannot be deleted
- [x] #5 Repository and Pipeline annotation values render only as safe HTTP(S) links
- [x] #6 Backend and frontend tests cover listing, creation, deletion, authorization, protected namespaces, and API error states
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
1. Add the Cucumber acceptance feature and commit it before code changes.
2. Add K8sClient create/delete namespace methods with 409, 404, and transport error tests.
3. Add admin- and SAR-gated POST/DELETE namespace resource routes, DNS-label validation, and protected namespace tests.
4. Add the React 4.1 Namespace List, safe annotation links, modal creation, confirmed deletion, shared header cache refresh, route wiring, and MSW tests.
5. Run targeted suites, frontend build/air-gap checks, and Qlty; re-run tests after fixes.

Detailed executable plan: .skillgrid/specs/2026-10-21-namespace-page/blueprint.md
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Verified 2026-10-21:
- uv run pytest tests/api/test_resources.py tests/services/test_k8s_client_namespaces.py -q -m "not integration" → 31 passed
- pnpm vitest tests/views/namespaces.test.tsx tests/views/Stub.test.tsx → 12 passed
- task fe-build → tsc/eslint/vite OK (Namespaces-CgPeI37l.js in dist)
- task fe-check failed on leftover SecretData highlight.js strings + existing DataTables message URLs; Namespaces chunk had no hits
- qlty fmt formatted the view test; ruff B904 fixed on create_namespace
Ruling: OIDC login() is role=user; mutation tests promote sub-oidc-1 to admin.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Replaced the /cluster/namespace stub with the 4.1 Namespace List. Admins can create valid namespaces and delete non-protected ones; both surfaces share the [namespaces, clusterId] query. Protected names (default, kube-system, kube-public, kube-node-lease) are rejected without a Kubernetes call. Verified with 31 backend unit tests, 12 Vitest tests, and task fe-build.
<!-- SECTION:FINAL_SUMMARY:END -->
