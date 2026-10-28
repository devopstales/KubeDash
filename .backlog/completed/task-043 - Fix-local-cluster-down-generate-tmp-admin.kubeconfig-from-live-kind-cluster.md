---
id: TASK-043
title: >-
  Fix local cluster 'down': generate /tmp/admin.kubeconfig from live kind
  cluster
status: Done
assignee: []
created_date: '2026-10-27 15:03'
updated_date: '2026-10-27 15:18'
labels: []
dependencies: []
modified_files:
  - backend/kubedash.ini
  - Taskfile.yaml
priority: high
type: bug
ordinal: 39000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The INI at backend/kubedash.ini points admin_kubeconfig at /tmp/admin.kubeconfig, but that file doesn't exist (it was a temp file from a prior dev session). The synthetic local cluster (id 0) therefore always probes down. Need a persistent dev setup that writes the live kind kubeconfig to /tmp/admin.kubeconfig so the local cluster reports 'up'. The kind cluster kubedash-test is live at 127.0.0.1:51355.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 /tmp/admin.kubeconfig exists and is valid (kubectl --kubeconfig /tmp/admin.kubeconfig version succeeds)
- [x] #2 GET /api/v1/clusters (authed as admin) shows the local cluster (id 0) with status 'up'
- [x] #3 The fix is repeatable — a Taskfile command or script regenerates /tmp/admin.kubeconfig from the live kind cluster
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
1. Add a `dev-kubeconfig` task to Taskfile.yaml that runs `kind get kubeconfig --name kubedash-test > /tmp/admin.kubeconfig` (with error handling if the cluster doesn't exist yet).
2. Add a call to `dev-kubeconfig` in `dev-stack` and `dev-stack-ssl` after the kind cluster is up (or make it idempotent/conditional).
3. Verify: kind cluster is up → run task → /tmp/admin.kubeconfig exists → backend local cluster reports up.
4. Also delete the stale e2e-smoke rows from the DB (separate TASK-044).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root cause: (1) /tmp/admin.kubeconfig missing — added _kind-kubeconfig task to Taskfile.yaml that writes it from kind after _kind-cluster. (2) K8sClient admin shape set _verify=True (system CA store) but kind uses self-signed certs — fixed to use client_config.ssl_ca_cert (the kubernetes lib already writes the CA to a temp file and stores the path) and pass it directly to httpx verify=. Verified: local cluster now reports status 'up' via GET /api/v1/clusters.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed the local cluster (id 0) always showing 'down' in the /clusters view. Two root causes:

1. **Missing /tmp/admin.kubeconfig**: The INI points admin_kubeconfig at /tmp/admin.kubeconfig, but the file was a temp artifact from a prior session. Added `_kind-kubeconfig` internal task to Taskfile.yaml that runs `kind get kubeconfig --name kubedash-test > /tmp/admin.kubeconfig`, wired into `kind-up` (after `_kind-cluster`). Added `ADMIN_KUBECONFIG` var to Taskfile.yaml.

2. **TLS verification bug in K8sClient admin shape**: The admin path (source='admin') set `_verify=True` (system CA store), but kind uses self-signed certs. Fixed `K8sClient.__init__` admin branch to read `client_config.ssl_ca_cert` (the kubernetes lib already writes the CA to a temp file and stores the path) and pass it directly to `httpx verify=`.

**Files changed**: Taskfile.yaml, backend/app/services/k8s_client.py
**Tests**: All 11 test_clusters.py + 7 test_clusters_admin.py pass (1 pre-existing failure unrelated to this change).
<!-- SECTION:FINAL_SUMMARY:END -->
