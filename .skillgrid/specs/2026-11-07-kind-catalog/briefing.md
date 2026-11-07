# Kind Catalog — Backend Read Path (Change A) — Briefing

> Companion to `blueprint.md` (the how). The *why* for this change: the
> 2026-11-07 architecture review (jscpd health 32/E; 8 of the last 10 commits
> are new-kind work touching 9–10 files). Decisions: ADR-0041 (in force,
> 2026-11-07); interview decisions `interview/kind-arch-20261107` (mnemonic,
> all 16 settled).

## What

KubeDash reads ~41 resource Kinds. Every Kind is currently *coded*: per-kind
`list_X`/`get_X` methods on `K8sClient` (~80 of them), the `_KINDS`/`_GETTERS`
string tables in `ResourceApi`, and a 1,145-line `FakeK8s` that copies method
names and already drifted — ingresses and the Gateway API kinds have **no
API-tier tests at all** because the double never grew to match.

This change declares the Kinds: a typed **kind catalog** + one generic
`list(kind, ns)` / `get(kind, ns, name)` engine on `K8sClient`, at the
existing `K8sClientPool.factory` seam (no new protocol). Per-kind methods
survive only as named overrides where behaviour genuinely differs.
`ResourceApi`'s dispatch and the test doubles derive from the same registry.
The five `k8s_client.py` concepts (crypto, binding, metrics, CRD resolution,
pool) split into focused modules. Cutover is kind-by-kind, no facade: the
suite is green at every commit.

## Requirements

- **R1.** A kind catalog registry (registry kind → API plural, group,
  version, scope, CRD flag, projector) is the single source of backend kind
  reads. Rows port `_KINDS` verbatim (plural, group) + per-method bodies
  (version, scope, CRD flag).
- **R2.** One generic engine implements the shared read pattern: namespace
  branch, `?name=` 404 → `[]`, CRD-absent degrade → `[]` (glossary:
  *CRD-absent degrade*), transport failure → `ClusterUnreachableError` → 502.
- **R3.** Named overrides only where behaviour genuinely differs:
  `list_pods` (`labelSelector`), PV claim-namespace filter (projector),
  secrets data-strip (projector), CRD-instance projection — plus anything the
  door check (blueprint Task 1) surfaces.
- **R4.** `_KINDS`/`_GETTERS` deleted from `resources.py`; dispatch + SAR
  group/plural derive from the catalog. No behaviour change: the SAR gate is
  asked before the read with the same attributes (ADR-0004); same error
  codes; same response shapes.
- **R5.** One shared `FakeK8s` (kind → items data) behind the existing
  factory seam + one fixture module `tests/fixtures/k8s_data.py`; the eight
  test doubles collapse onto it. A catalog kind with no fixture data fails
  its own test (drift becomes a test failure).
- **R6.** The missing API-tier tests (ingresses, Gateway API kinds) are
  recovered via a parametrized test over the catalog.
- **R7.** `k8s_client.py` (2,487L) splits into `kubeconfig_crypto.py`,
  `k8s_metrics.py`, `crds.py`, `kubeconfig_binding.py`; `k8s_client.py`
  keeps client construction + engine + mutations + `readyz` + pool. The
  factory seam is unchanged.
- **R8.** Behaviour preserved: `uv run pytest -m "not integration"` green
  per commit; `ruff` + `mypy` clean; no REST shape change.

## Success

- Adding a Kind = one catalog row + one fixture entry (no new methods, no
  `resources.py` table row).
- The CRD-absent degrade rule has one home (the engine).
- `k8s_client.py` < ~600 lines; no per-method complexity above the engine.
- The ADR-0010 informer-cache adapter later faces a handful of methods, not
  ~88.

## Out of scope

- Frontend registry (change B), navigation seam (change C), dead-code chore
  (change D).
- Informer-cache implementation (ADR-0010) — only the seam it will plug into
  shrinks.
- A `ResourceReader` protocol — a hypothetical seam until the second adapter
  arrives (ADR-0041).
- New dependencies. Behaviour changes. Migrations.
