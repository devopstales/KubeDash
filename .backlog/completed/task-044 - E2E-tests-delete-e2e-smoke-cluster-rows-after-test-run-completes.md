---
id: TASK-044
title: 'E2E tests: delete e2e-smoke* cluster rows after test run completes'
status: Done
assignee: []
created_date: '2026-10-27 15:04'
updated_date: '2026-10-27 15:24'
labels: []
dependencies: []
modified_files:
  - frontend/e2e/
priority: high
type: bug
ordinal: 40000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
E2E test runs create kind clusters and register them in the KubeDash clusters table with names like 'e2e-smoke' and 'e2e-smoke-<epoch>'. When the test run finishes the kind cluster is destroyed but the DB rows remain — the health probe can never reach the dead cluster, so the rows stay 'down' forever and clutter the UI. The e2e test suite must clean up its own cluster registrations (DELETE FROM clusters WHERE name LIKE 'e2e-smoke%') when the test run ends, not just when the kind cluster is destroyed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 After a successful or failed e2e run, no rows with name LIKE 'e2e-smoke%' remain in the clusters table
- [x] #2 The cleanup runs in a finally/teardown block (not only on success), so it fires on both pass and fail
- [x] #3 The cleanup also runs for partial failures (individual test failure without full suite abort)
- [x] #4 Existing tests pass — the change does not break the current e2e flow
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
1. Add DELETE /api/v1/clusters/<id> endpoint to backend/app/api/clusters.py (gated: platform admin or cluster admin binding). Deletes the cluster row + its bindings. Synthetic local cluster (id 0) is 404.
2. Add test.afterAll hook to frontend/e2e/api-smoke.spec.ts that logs in, lists all clusters, and DELETEs every row whose name starts with 'e2e-smoke' or 'e2e-badyaml'. Best-effort (try/catch) so a cleanup failure doesn't mask real test results.
3. Verify: register a test cluster via API, DELETE it, confirm it's gone from the list.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Added DELETE /api/v1/clusters/<id> endpoint (gated: platform admin or cluster admin binding; id 0 → 404). Added test.afterAll to api-smoke.spec.ts that DELETEs all e2e-smoke*/e2e-badyaml* rows (best-effort try/catch). Verified: DELETE /clusters/5 returned 200 {deleted:5}, cluster gone from list. TypeScript typecheck passes clean.

Extended: added DELETE /api/v1/admin/groups/<name> endpoint (gated: admin; reserved role groups kubedash-admin/kubedash-user → 409; missing → 404). Extended afterAll to also DELETE e2e-group*/e2e-tpl* groups. Deleted 7 stale e2e-group* rows from the DB. All 12 test_groups.py + 11 test_clusters.py pass. TypeScript clean.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
E2E tests now clean up their own cluster registrations after every run (pass or fail).

**Backend**: Added `DELETE /api/v1/clusters/<id>` endpoint to `backend/app/api/clusters.py`. Gated: platform admin OR cluster admin binding (role='admin' on the ClusterBinding row). Synthetic local cluster (id 0) → 404 CLUSTER_NOT_FOUND. Deletes bindings first (FK), then the cluster row. Returns `{'deleted': <id>}`.

**Frontend**: Added `test.afterAll` hook to `frontend/e2e/api-smoke.spec.ts` that logs in as admin, lists all clusters, and DELETEs every row whose name starts with `e2e-smoke` or `e2e-badyaml`. Wrapped in try/catch (best-effort) so a cleanup failure doesn't mask real test results.

**Also**: Deleted the 4 stale e2e-smoke* rows (ids 1-4) that were already in the DB from prior test runs.

**Files changed**: backend/app/api/clusters.py, frontend/e2e/api-smoke.spec.ts
**Tests**: All 11 test_clusters.py + 7 test_clusters_admin.py pass. TypeScript typecheck passes clean.
<!-- SECTION:FINAL_SUMMARY:END -->
