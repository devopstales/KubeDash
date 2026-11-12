---
id: TASK-058
title: 'TICKET-04: migrate cluster-permission views (SA, role, cluster-role, bindings)'
status: Done
assignee: []
created_date: '2026-10-29 16:36'
updated_date: '2026-11-03 11:40'
labels: []
milestone: m-2
dependencies:
  - TASK-056
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 54000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): migrate ClusterPermission/ServiceAccounts.tsx, ServiceAccountData.tsx, Role.tsx, RoleData.tsx, ClusterRole.tsx, ClusterRoleData.tsx, RoleBinding.tsx, ClusterRoleBinding.tsx to the ObjectRoute contract. Cross-links (binding -> role/cluster-role/SA, SA -> secret data) become openObject calls with the target kind. The ServiceAccounts -> /security/secret?selected= producer is deleted (R9, paired with TASK-057's consumer change). SATISFIES: opening an object from a list leaves the URL clean; one route per kind (detail only for matching ref).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every name cell in the 4 list views opens the matching data view via ref with location.search === ''
- [ ] #2 cross-kind links (binding -> role, SA -> secret) resolve to the target kind's detail
- [ ] #3 pnpm test tests/views/service_accounts* tests/views/roles* tests/views/role_bindings* tests/views/cluster_roles* tests/views/cluster_role_bindings* exits 0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test over the 5 test files green
- [ ] #7 no data?name= link producer remains in ClusterPermission/
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - re-point the 5 view test files. 2: migrate the 8 views (cross-links via openObject with target kind). 3: App.tsx additive ObjectRoute wraps.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Started: read templates (PriorityClass/Secret/ObjectRoute/ShareObjectButton), all 8 ClusterPermission views, App.tsx routes, and all 5 test files. Plan: migrate views to openObject + props, add ObjectRoute wrappers in App.tsx, re-point tests.

Migrated all 8 ClusterPermission views (ServiceAccounts/ServiceAccountData/Role/RoleData/ClusterRole/ClusterRoleData/RoleBinding/ClusterRoleBinding) to ADR-0040: name cells are buttons + ShareObjectButton, cross-kind links (binding→role/cluster-role/SA, SA→secret) use openObject with the target kind, ?selected= producer deleted (R9), data views take {name,namespace} props (no useSearchParams). App.tsx: 3 ObjectRoute wrappers (serviceaccount/role/clusterrole) ALONGSIDE existing /data routes + Legacy*Data shims for TICKET-07. Tests re-pointed: click→detail-render with location.search==='' and cross-kind target-detail assertions. 5/5 target test files pass (33 tests); fe-build green; git diff backend/ empty. Full suite: only pre-existing users/groups/node/admin_permissions failures (confirmed failing on HEAD too).
<!-- SECTION:NOTES:END -->
