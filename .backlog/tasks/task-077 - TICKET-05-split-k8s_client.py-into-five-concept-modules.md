---
id: TASK-077
title: 'TICKET-05: split k8s_client.py into five concept modules'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-076
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
ordinal: 73000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 5 (move-only, behaviour identical): create `backend/app/services/kubeconfig_crypto.py` (`key()`, `encrypt_kubeconfig`, `decrypt_kubeconfig` — the `KUBEDASH_SECRET_KEY` one-way door untouched), `kubeconfig_binding.py` (`bound_cluster_or_404`, `resolve_admin_source`), `k8s_metrics.py` (`node_metrics`, `node_usage`, `pvc_usage`, `_node_metrics`, `_parse_stats_body`, `_parse_cpu`, `_parse_bytes` moved verbatim — `cluster_allocation.py` keeps its deliberate private copy, out of scope per user decision 2026-11-07); `k8s_client.py` keeps client construction + engine + mutations + `readyz` + `K8sClientPool` (seam owner) + `get_crd_served` delegate + non-catalog reads (`list_events`, `list_crd_instances`) + thin one-line metrics delegates; update every importer of the moved names (authoritative sweep: `grep -rln "from app.services.k8s_client import" backend/app backend/tests` — ~16 source/test files, import-only edits; `test_resources.py`'s lazy `encrypt_kubeconfig` import included).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` all green (from `backend/`); the moved functions exist at the named modules with docstrings intact; no file still imports a moved name from `k8s_client`; `wc -l backend/app/services/k8s_client.py` < ~900; `K8sClientPool` still in `k8s_client.py`; `cluster_allocation.py` diff is empty.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: concepts-split
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 5 (move-only, behaviour identical): create `backend/app/services/kubeconfig_crypto.py` (`key()`, `encrypt_kubeconfig`, `decrypt_kubeconfig` — the `KUBEDASH_SECRET_KEY` one-way door untouched), `kubeconfig_binding.py` (`bound_cluster_or_404`, `resolve_admin_source`), `k8s_metrics.py` (`node_metrics`, `node_usage`, `pvc_usage`, `_node_metrics`, `_parse_stats_body`, `_parse_cpu`, `_parse_bytes` moved verbatim — `cluster_allocation.py` keeps its deliberate private copy, out of scope per user decision 2026-11-07); `k8s_client.py` keeps client construction + engine + mutations + `read. 2: verify per Acceptance: `uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` all green (from `backend/`); the moved functions exist at the named modules with docstrings intact; no file still imports a moved name from `k8s_client`; `wc -l backend/app/services/k8s_client.py` < ~900; `K8sClientPool` still in `k8s_client.py`; `cluster_allocation.py` diff is empty.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
