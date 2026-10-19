---
id: TASK-019
title: >-
  TICKET-16: Synthetic local cluster in list + me response growth + openapi
  re-dump
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 13:33'
labels: []
milestone: m-0
dependencies:
  - TASK-018
priority: medium
type: feature
ordinal: 19000
---

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
1. TDD: write failing tests (tests/api/test_clusters_admin.py: admin list has exactly one id:0 source:admin entry with api_server from the resolved source path; non-admin list unchanged; _out has source:registry for real rows; admin me has auth_source+kubeconfig_source+last_login_at; user me has kubeconfig_source null). 2. Implement: clusters _out gains source:'registry'; list_clusters prepends synthetic admin entry (id:0, api_server from the resolved source — the path, not a literal); MeOut (marshmallow) gains auth_source/kubeconfig_source/last_login_at; me handler populates them. 3. Re-dump frontend/openapi.json from the test client (GET /api/openapi.json). 4. Verify: pytest tests/api/test_clusters_admin.py tests/api/test_auth.py -v -m 'not integration', ruff, mypy; the re-dumped openapi.json contains the three new me fields. 5. Commit per work-unit-commits (openapi.json in the same commit).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Starting execution per task-4-brief.md (TICKET-16): TDD — failing tests first (tests/api/test_clusters_admin.py + test_auth.py me-shape amendment), then implement (clusters _out/list, MeOut, me handler, ClusterOut source), then openapi re-dump + commit.

Implemented: _out source:registry, list synthetic admin entry (I13 resolved path), MeOut +3 fields (marshmallow), me handler populates, ClusterOut.source docs, resources.py consolidated to clusters._local_cluster(). Tests: test_clusters_admin.py (7 unit + 1 integration) + test_auth.py me-shape amendment. api tier 56 passed, ruff+mypy green. openapi.json re-dumped (transform preserves committed conventions: RESPONSE_-keys, no securitySchemes; + MeOut/ClusterOut growth + stale auth-local/settings restore).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Synthetic local cluster in the admin cluster list (id:0, source:'admin', api_server=resolved source per I13) + _out source:'registry' for real rows; MeOut (marshmallow) +auth_source/kubeconfig_source/last_login_at with the me handler populating them (kubeconfig_source admin-only); ClusterOut +source (docs); resources.py consolidated onto clusters._local_cluster(). Verified: tests/api 56 passed (-m 'not integration'), ruff + mypy green, openapi.json re-dumped (RESPONSE_-convention preserved; diff = MeOut/ClusterOut growth + stale auth-local/settings restore). Commit 1f67f0ed. SATISFIES admin-sees-local-cluster-from-config (list half) + profile-page-shows-identity (backend half).
<!-- SECTION:FINAL_SUMMARY:END -->
