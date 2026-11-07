---
id: TASK-073
title: 'TICKET-01: door check: catalog schema, engine, tracer kinds'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies: []
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
ordinal: 69000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 1 (the door check; stop-the-line if it fails): create `backend/app/services/kinds.py` (`KindSpec` dataclass + all 41 rows transcribed from `_KINDS`/`_GETTERS` + per-method bodies + the `strip_secret_data`/`pv_claim_filter` projectors), `backend/app/services/crds.py` (`served_version`/`custom`/`crd_body` moved verbatim from `k8s_client.py`), move `FakeK8s` to `backend/tests/fakes/fake_k8s.py` (catalog-driven `list`/`get` + `crd_absent` toggle + `last_pod_label_selector` recording), new `backend/tests/fixtures/k8s_data.py` (3 tracer entries), the `K8sClient.list(kind, namespace, label_selector)`/`get(kind, namespace, name)` engine + `build_typed_readers(...)` in `k8s_client.py`, rework `resources.py` dispatch from `KINDS` (SAR from `spec.group`/`spec.plural` per ADR-0004, `?name=` gettable gate, `labelSelector` forwarded only for `pods`), delete `_KINDS`/`_GETTERS`, flip the 3 tracer rows to `method=None`, delete the 6 tracer methods. Failing tests first (blueprint Task 1 Step 1 a-e, incl. shape assertions).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration"` green (from `backend/`); tracer route tests pass (fixture items, snake_case typed / camelCase wire shapes, SAR attrs `("list", "ingressclasses", None, None, "networking.k8s.io")`, `?name=absent` → 200 `items: []`, secrets list stripped); engine stub tests pass (transport `ApiException` → `ClusterUnreachableError`, mis-registered CRD → `ClusterUnreachableError`); `grep -n "_KINDS\|_GETTERS" backend/app/api/resources.py` → 0 matches; the 6 tracer methods are gone from `k8s_client.py`; the door-check verdict is recorded in the commit body — if any kind needs per-kind branching inside the engine beyond {namespace branch, 404, CRD-absent, transport, projector, `label_selector`}, STOP and report (blueprint invalidated, user decides). `uv run ruff check . && uv run mypy app` clean.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: tracer-kinds-catalog; engine-transport-failure-502; crd-absent-degrade; unknown-kind-404; get-name-semantics; secrets-list-strips-data
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 1 (the door check; stop-the-line if it fails): create `backend/app/services/kinds.py` (`KindSpec` dataclass + all 41 rows transcribed from `_KINDS`/`_GETTERS` + per-method bodies + the `strip_secret_data`/`pv_claim_filter` projectors), `backend/app/services/crds.py` (`served_version`/`custom`/`crd_body` moved verbatim from `k8s_client.py`), move `FakeK8s` to `backend/tests/fakes/fake_k8s.py` (catalog-driven `list`/`get` + `crd_absent` toggle + `last_pod_label_selector` recording), new `backend/tests/fixtures/k8s_data.py` (3 tracer entries), the `K8sClient.list(kind, namespace, l. 2: verify per Acceptance: `uv run pytest -m "not integration"` green (from `backend/`); tracer route tests pass (fixture items, snake_case typed / camelCase wire shapes, SAR attrs `("list", "ingressclasses", None, None, "networking.k8s.io")`, `?name=absent` → 200 `items: []`, secrets list stripped); engine stub tests pass (transport `ApiException` → `ClusterUnreachableError`, mis-registered CRD → `ClusterUnreachableError`); `grep -n "_KINDS\|_GETTERS" backend/app/api/resources.py` → 0 matches; the 6 tracer methods are gone from `k8s_client.py`; the door-check verdict is recorded in the commit body — if any kind needs p. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
