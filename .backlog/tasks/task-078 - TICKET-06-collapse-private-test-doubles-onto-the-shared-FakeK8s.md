---
id: TASK-078
title: 'TICKET-06: collapse private test doubles onto the shared FakeK8s'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-077
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
priority: high
type: feature
ordinal: 74000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 6: the shared `FakeK8s` (at `backend/tests/fakes/fake_k8s.py` since TICKET-01) absorbs every private fake — authoritative list: `grep -rlEn "class _?Fake.*K8s" backend/tests/` (currently 9 files: `test_resources.py`, `test_clusters.py`, `test_events.py`, `test_permissions.py`, `test_gateway_api.py`, `test_metrics_pvcs.py`, `test_metrics_summary.py`, `test_permission.py`, `test_admin_source.py` — fold in the metric fakes and `FakeAdminK8s`). One constructor `(kubeconfig, data=None, readyz_result=True, available=True, raise_unreachable=False, crd_absent=frozenset())` covering all private signatures; the mutation/metrics/`readyz` methods each suite calls ported 1:1 (conflicting canned values resolved per-suite via constructor data, not branches); the union of recording hooks (`last_pod_label_selector`, `pvc_usage_calls`, `node_usage_calls`, `calls`, `crd_instance_calls`, `last_rules`/`last_labels`); swap the imports, delete the private fakes. A suite whose private fake disappears keeps its passing tests — fix the shared fake, never the expectation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration"` green; `grep -rlEn "class _?Fake.*K8s" backend/tests/` → exactly 1 file (`tests/fakes/fake_k8s.py`); every suite injects the shared fake through `pool.factory`.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: one-double
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 6: the shared `FakeK8s` (at `backend/tests/fakes/fake_k8s.py` since TICKET-01) absorbs every private fake — authoritative list: `grep -rlEn "class _?Fake.*K8s" backend/tests/` (currently 9 files: `test_resources.py`, `test_clusters.py`, `test_events.py`, `test_permissions.py`, `test_gateway_api.py`, `test_metrics_pvcs.py`, `test_metrics_summary.py`, `test_permission.py`, `test_admin_source.py` — fold in the metric fakes and `FakeAdminK8s`). One constructor `(kubeconfig, data=None, readyz_result=True, available=True, raise_unreachable=False, crd_absent=frozenset())` covering all . 2: verify per Acceptance: `uv run pytest -m "not integration"` green; `grep -rlEn "class _?Fake.*K8s" backend/tests/` → exactly 1 file (`tests/fakes/fake_k8s.py`); every suite injects the shared fake through `pool.factory`.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
