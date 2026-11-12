---
id: TASK-018
title: >-
  TICKET-15: Admin kubeconfig source in client pool (id:0 branch, readyz probe,
  SAR convergence)
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 13:04'
labels: []
milestone: m-0
dependencies:
  - TASK-017
priority: high
type: feature
ordinal: 18000
---

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. RED: tests/test_admin_source.py (pure resolve, pool role-gate, id:0 short-circuit admin/non-admin, readyz probe, lazy+cache, build seam). 2. GREEN: k8s_client.py (resolve_admin_source, build_admin_client, admin_factory + _get_admin_client_for + id:0 branch, source attr, admin_client_ok); api/clusters.py + api/resources.py synthetic Cluster(id=0) short-circuit; app/__init__.py readyz probe. 3. Verify focused suite + ruff + mypy. 4. Commit feat(clusters).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TICKET-15 complete. commits 2547a511 (impl) + f135e474 (fix round 1). Gated: tests/test_admin_source.py + test_clusters.py + test_resources.py + test_rbac.py + tasks = 38 passed (-m not integration); ruff + mypy clean. resolve_admin_source pure (empty→in-cluster, path→kubeconfig-file); build_admin_client (missing file→ValueError with path); K8sClientPool(admin_factory=...) + _get_admin_client_for (lazy I4, cached, non-admin→ClusterNotFoundError); id:0 branch INSIDE pool.get (C-NEW-2 — all 5 call sites unchanged, rbac.py:77 SAR converges); source attribute registry/admin; readyz admin-kubeconfig probe (I-NEW-6 probe-not-resolver, key ABSENT in in-cluster mode, 503 names admin-kubeconfig on missing file); id:0 handler short-circuits in api/clusters.py + api/resources.py BEFORE bound_cluster_or_404. Review round 1 found 2 Important (both fixed in f135e474): (1) GET /clusters/0 returned 200 for non-admin — the brief promised 404; fixed with a bare kc.pool.get(_local_cluster()) gate call + new pinning test; (2) test_resources_zero_404_for_non_admin passed for the wrong reason (real pool → 500 from load_incluster_config in rbac.can); fixed by injecting FakeAdminK8s pool into both res.pool and rb.pool — branch-removal sensitivity verified. Re-review clean. Minor deferred: get_cluster double-constructs _local_cluster() (cosmetic); pre-existing test_health PG-fixture failure (parked); synthetic Cluster literal duplicated across the two API files (consolidation belongs to TICKET-16).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Admin kubeconfig source in the client pool (ADR-0021): resolve_admin_source (pure), build_admin_client (kubeconfig-file / in-cluster, missing file → ValueError), K8sClientPool(admin_factory=...) with lazy cached role-gated _get_admin_client_for, and the id:0 branch INSIDE pool.get (C-NEW-2) so the SAR path (rbac.py:77) converges unchanged. id:0 handler short-circuits in clusters/resources APIs before the binding gate; non-admin id:0 → 404 CLUSTER_NOT_FOUND (all three routes). readyz gains a probe-only admin-kubeconfig check (absent in in-cluster mode). Verified: 38/38 focused (12 new + regression suites), ruff+mypy clean, review clean after one fix round.
<!-- SECTION:FINAL_SUMMARY:END -->
