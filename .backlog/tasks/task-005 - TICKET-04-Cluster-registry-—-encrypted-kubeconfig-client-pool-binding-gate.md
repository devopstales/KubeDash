---
id: TASK-005
title: >-
  TICKET-04: Cluster registry — encrypted kubeconfig + client pool + binding
  gate
status: To Do
assignee: []
created_date: '2026-10-17 12:58'
labels: []
milestone: m-0
dependencies:
  - TASK-004
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: AES-256-GCM encrypt/decrypt_kubeconfig (one-way OD-2, ADR-0002), bound_cluster_or_404 helper, K8sClient (host verbatim, CA from kubeconfig, 5s readyz), K8sClientPool, ClusterApi (register/list/get/health with 409/422/502 paths), blackholed-server bounded-timeout test. Current: no cluster access. Expected: registered kubeconfig stored encrypted, clients pooled per cluster, health probed with bounded timeout.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_encryption.py tests/api/test_clusters.py -m 'not integration' green: at-rest hides plaintext + round-trip; wrong key fails; register->list bound; dup 409; bad yaml 422; unbound user []; blackholed port 502 CLUSTER_UNREACHABLE < 8s; readyz URL/CA unit assertions
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R3 acceptance met; OD-2 human checkpoint passed; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. app/services/k8s_client.py (encrypt/decrypt, bound_cluster_or_404, K8sClient, pool)
2. app/schemas/cluster.py + app/api/clusters.py ClusterApi; register in api/__init__.py
3. pyproject +cryptography
4. tests/test_encryption.py + tests/api/test_clusters.py (incl. blackhole + readyz URL/CA)
5. pytest green; commit (Refs: TASK-004)
<!-- SECTION:PLAN:END -->
