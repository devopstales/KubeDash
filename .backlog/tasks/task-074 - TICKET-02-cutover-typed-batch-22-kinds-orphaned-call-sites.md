---
id: TASK-074
title: 'TICKET-02: cutover typed batch (22 kinds) + orphaned call-sites'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-073
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
ordinal: 70000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 2: port the 22 batch fixtures 1:1 from the current `FakeK8s` method bodies into `k8s_data.py` (+ `crds` wire-form fixture; `ingresses` is new snake_case data) and confirm they match the existing route-test assertions (fix fixtures, never expectations); add the 22 `_typed` reader entries in `K8sClient.__init__`; flip the 22 rows to `method=None`; delete the 22 per-kind methods from `k8s_client.py` (incl. `list_pods` — `label_selector` is now an engine kwarg) + matching fake methods; migrate the 3 production call-sites in the same commit (`gateway_api.py` `get_ingress` → `client.get("ingresses", ns, name)`; `metrics.py` → `client.list("nodes", None)` / `client.list("pods", None)`; `resources.py` crds instances route → `client.get("crds", None, name)`, `list_crd_instances` stays); rewrite the batch's `tests/services/test_k8s_client_*.py` against the engine.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration"` green with zero changed route-test expectations; pods `?labelSelector=app=web` recorded on the fake only with a namespace (absent without); other kinds ignore it; PV list = cluster list filtered to the selected namespace via `claim_ref` (free/unbound PVs always visible); a transport failure on the 10 legacy 500 read paths returns 502 `CLUSTER_UNREACHABLE` (no 500 `INTERNAL_ERROR` remains on read paths); `grep -n "def list_namespaces\|def list_nodes\|def list_pods" backend/app/services/k8s_client.py` → 0 matches; `uv run ruff check . && uv run mypy app` clean.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: typed-kinds-catalog; persistentvolumes-claim-namespace-filter; pods-label-selector-forwarded
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 2: port the 22 batch fixtures 1:1 from the current `FakeK8s` method bodies into `k8s_data.py` (+ `crds` wire-form fixture; `ingresses` is new snake_case data) and confirm they match the existing route-test assertions (fix fixtures, never expectations); add the 22 `_typed` reader entries in `K8sClient.__init__`; flip the 22 rows to `method=None`; delete the 22 per-kind methods from `k8s_client.py` (incl. `list_pods` — `label_selector` is now an engine kwarg) + matching fake methods; migrate the 3 production call-sites in the same commit (`gateway_api.py` `get_ingress` → `client.g. 2: verify per Acceptance: `uv run pytest -m "not integration"` green with zero changed route-test expectations; pods `?labelSelector=app=web` recorded on the fake only with a namespace (absent without); other kinds ignore it; PV list = cluster list filtered to the selected namespace via `claim_ref` (free/unbound PVs always visible); a transport failure on the 10 legacy 500 read paths returns 502 `CLUSTER_UNREACHABLE` (no 500 `INTERNAL_ERROR` remains on read paths); `grep -n "def list_namespaces\|def list_nodes\|def list_pods" backend/app/services/k8s_client.py` → 0 matches; `uv run ruff check . && uv run mypy app` clea. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
