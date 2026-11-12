# Tasks — Kind Catalog (Backend Read Path, Change A)

> **STATUS:** `sliced` (2026-11-07)

> Sliced from `.skillgrid/specs/2026-11-07-kind-catalog/blueprint.md`.
> Vertical tracer-bullet tickets, dependency-ordered, sized for one fresh
> agent context window.

## Epic Summary

Replace the ~73 per-kind `list_X`/`get_X` methods + `_KINDS`/`_GETTERS`
string tables + 9 drifting test doubles with a typed kind catalog (41
`KindSpec` rows), one generic `K8sClient.list`/`get` read engine at the
existing `K8sClientPool.factory` seam, and one catalog-driven `FakeK8s`
behind per-kind fixture data (ADR-0041, in force). Behaviour is unchanged
except the one documented transport normalization: the 10 legacy 500 read
paths become 502 `CLUSTER_UNREACHABLE` (user decision 2026-11-07). The
cutover is sequenced kind-by-kind — door check (3 tracer kinds) → typed
batch (22) → CRD batch (12) → coverage recovery → module split → double
collapse — with the suite green at every commit.

## Delivery Strategy

| Field | Value |
|-------|-------|
| Estimated changed lines | 6200-6800 (deletions dominate the cutover batches) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (T01 door check) → PR 2 (T02+T03 cutover batches) → PR 3 (T04+T05+T06 coverage/split/doubles) → PR 4 (T07 docs + measurement) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | Door check: catalog schema + engine + 3 tracer kinds + dispatch rework | PR 1 | `cd backend && uv run pytest tests/api/test_resources.py -m "not integration"` | unit suite via `K8sClientPool.factory` injection (no cluster; `FakeK8s` + `ApiException` stubs) | the 4 new files (`kinds.py`, `crds.py`, `fake_k8s.py`, `k8s_data.py`) + reverts of `k8s_client.py`/`resources.py`/`test_resources.py` |
| 2 | Cutover batches: 34 more kinds (22 typed + 12 CRD), 65 method deletions, 3 call-site migrations | PR 2 | `cd backend && uv run pytest tests/api/test_resources.py tests/services -m "not integration"` | unit suite via factory injection | restore the 55 deleted per-kind methods + flip rows back to `method=` + restore the 3 call-sites (PR 1 state untouched) |
| 3 | Coverage recovery + concept split + double collapse | PR 3 | `cd backend && uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` | unit suite + static analysis | the parametrized test block (additive), the 3 new modules + import sweep, the fake collapse — each an independent revert |
| 4 | Docs + measurement (ARCHITECTURE read-path section, kind-addition procedure, jscpd health) | PR 4 | `cd backend && wc -l app/services/k8s_client.py && grep -c "    def list_\|    def get_" app/services/k8s_client.py` | N/A (docs + measurement only, no behaviour change) | `.skillgrid/ARCHITECTURE.md` revert |

> The four plain-text guard lines above are the **contract** —
> `skillgrid:subagent-execution` matches them literally. If risk is High,
> `Chained PRs recommended` MUST be `Yes` and every work unit MUST name a
> focused test, a runtime harness (or `N/A` + reason), and a rollback
> boundary.

## Tickets

### TICKET-01 - door check: catalog schema, engine, tracer kinds

- **Tracker ID:** TASK-073
- **Scope:** blueprint Task 1 (the door check; stop-the-line if it fails):
  create `backend/app/services/kinds.py` (`KindSpec` dataclass + all 41
  rows transcribed from `_KINDS`/`_GETTERS` + per-method bodies + the
  `strip_secret_data`/`pv_claim_filter` projectors), `backend/app/services/crds.py`
  (`served_version`/`custom`/`crd_body` moved verbatim from `k8s_client.py`),
  move `FakeK8s` to `backend/tests/fakes/fake_k8s.py` (catalog-driven
  `list`/`get` + `crd_absent` toggle + `last_pod_label_selector` recording),
  new `backend/tests/fixtures/k8s_data.py` (3 tracer entries), the
  `K8sClient.list(kind, namespace, label_selector)`/`get(kind, namespace, name)`
  engine + `build_typed_readers(...)` in `k8s_client.py`, rework
  `resources.py` dispatch from `KINDS` (SAR from `spec.group`/`spec.plural`
  per ADR-0004, `?name=` gettable gate, `labelSelector` forwarded only for
  `pods`), delete `_KINDS`/`_GETTERS`, flip the 3 tracer rows to
  `method=None`, delete the 6 tracer methods. Failing tests first
  (blueprint Task 1 Step 1 a-e, incl. shape assertions).
- **Acceptance:** `uv run pytest -m "not integration"` green (from
  `backend/`); tracer route tests pass (fixture items, snake_case typed /
  camelCase wire shapes, SAR attrs `("list", "ingressclasses", None, None,
  "networking.k8s.io")`, `?name=absent` → 200 `items: []`, secrets list
  stripped); engine stub tests pass (transport `ApiException` →
  `ClusterUnreachableError`, mis-registered CRD → `ClusterUnreachableError`);
  `grep -n "_KINDS\|_GETTERS" backend/app/api/resources.py` → 0 matches; the
  6 tracer methods are gone from `k8s_client.py`; the door-check verdict is
  recorded in the commit body — if any kind needs per-kind branching inside
  the engine beyond {namespace branch, 404, CRD-absent, transport,
  projector, `label_selector`}, STOP and report (blueprint invalidated,
  user decides). `uv run ruff check . && uv run mypy app` clean.
- **SATISFIES:** tracer-kinds-catalog; engine-transport-failure-502;
  crd-absent-degrade; unknown-kind-404; get-name-semantics;
  secrets-list-strips-data
- **Files:** `backend/app/services/kinds.py` (new ~220), `backend/app/services/crds.py` (new ~70), `backend/app/services/k8s_client.py`, `backend/app/api/resources.py`, `backend/tests/api/test_resources.py`, `backend/tests/fakes/fake_k8s.py` (new ~150), `backend/tests/fixtures/k8s_data.py` (new ~130)
- **Size:** ~1100 (M)
- **Blocks:** TICKET-02
- **Blocked by:** none
- **Fails-when:** `uv run pytest -m "not integration"` exits non-zero, or
  any tracer route/engine test fails, or `grep -n "_KINDS\|_GETTERS"
  backend/app/api/resources.py` prints any line

### TICKET-02 - cutover typed batch (22 kinds) + orphaned call-sites

- **Tracker ID:** TASK-074
- **Scope:** blueprint Task 2: port the 22 batch fixtures 1:1 from the
  current `FakeK8s` method bodies into `k8s_data.py` (+ `crds` wire-form
  fixture; `ingresses` is new snake_case data) and confirm they match the
  existing route-test assertions (fix fixtures, never expectations); add
  the 22 `_typed` reader entries in `K8sClient.__init__`; flip the 22 rows
  to `method=None`; delete the 22 per-kind methods from `k8s_client.py`
  (incl. `list_pods` — `label_selector` is now an engine kwarg) + matching
  fake methods; migrate the 3 production call-sites in the same commit
  (`gateway_api.py` `get_ingress` → `client.get("ingresses", ns, name)`;
  `metrics.py` → `client.list("nodes", None)` / `client.list("pods", None)`;
  `resources.py` crds instances route → `client.get("crds", None, name)`,
  `list_crd_instances` stays); rewrite the batch's
  `tests/services/test_k8s_client_*.py` against the engine.
- **Acceptance:** `uv run pytest -m "not integration"` green with zero
  changed route-test expectations; pods `?labelSelector=app=web` recorded on
  the fake only with a namespace (absent without); other kinds ignore it;
  PV list = cluster list filtered to the selected namespace via `claim_ref`
  (free/unbound PVs always visible); a transport failure on the 10 legacy
  500 read paths returns 502 `CLUSTER_UNREACHABLE` (no 500 `INTERNAL_ERROR`
  remains on read paths); `grep -n "def list_namespaces\|def list_nodes\|def list_pods"
  backend/app/services/k8s_client.py` → 0 matches; `uv run ruff check . &&
  uv run mypy app` clean.
- **SATISFIES:** typed-kinds-catalog; persistentvolumes-claim-namespace-filter;
  pods-label-selector-forwarded
- **Files:** `backend/app/services/k8s_client.py`, `backend/tests/fixtures/k8s_data.py`, `backend/tests/fakes/fake_k8s.py`, `backend/tests/api/test_resources.py`, `backend/app/api/gateway_api.py`, `backend/app/api/metrics.py`, `backend/app/api/resources.py`, the batch's `backend/tests/services/test_k8s_client_*.py`
- **Size:** ~1800 (L)
- **Blocks:** TICKET-03
- **Blocked by:** TICKET-01
- **Precondition:** TICKET-01 committed — `backend/app/services/kinds.py`
  holds 41 rows, `K8sClient.list`/`get` exist, and `uv run pytest -m "not
  integration"` is green
- **Fails-when:** `uv run pytest -m "not integration"` exits non-zero, or
  any pre-existing per-kind route-test expectation had to change (fixtures
  absorb mismatches, not expectations), or a legacy 500 read path still
  returns 500 on transport failure

### TICKET-03 - cutover CRD batch (12 kinds)

- **Tracker ID:** TASK-075
- **Scope:** blueprint Task 3: add the 12 wire-form (camelCase) fixture
  entries (all new data — the fake drifted; shape reference: the real
  methods' wire dicts + API-tier assertions) for ciliumnetworkpolicies,
  ciliumclusterwidenetworkpolicies, verticalpodautoscalers, gateways,
  httproutes, referencegrants, volumesnapshotclasses, volumesnapshots,
  clusterissuers, issuers, certificaterequests, certificates; add the
  per-kind `test_<kind>_crd_absent_returns_empty` tests + one
  transport-failure negative control; flip the 12 rows to `method=None`;
  delete the 12 list + 11 get methods from `k8s_client.py` + matching fake
  methods; rewrite the batch's service tests against the engine (Task 2
  pattern).
- **Acceptance:** `uv run pytest -m "not integration"` green; each of the
  12 kinds: list route → 200 wire-shape items, `crd_absent={kind}` → 200
  `items: []`, transport failure → 502 `CLUSTER_UNREACHABLE`; the 23 batch
  methods are gone from `k8s_client.py`; `uv run ruff check . && uv run mypy
  app` clean.
- **SATISFIES:** crd-kinds-catalog; crd-absent-degrade;
  engine-transport-failure-502
- **Files:** `backend/tests/fixtures/k8s_data.py`, `backend/app/services/k8s_client.py`, `backend/tests/fakes/fake_k8s.py`, `backend/tests/api/test_resources.py`, the batch's `backend/tests/services/test_k8s_client_*.py`
- **Size:** ~1050 (M)
- **Blocks:** TICKET-04
- **Blocked by:** TICKET-02
- **Precondition:** TICKET-02 committed — the 22 typed rows are
  `method=None` and `uv run pytest -m "not integration"` is green
- **Fails-when:** `uv run pytest -m "not integration"` exits non-zero, or
  any `crd_absent` test returns non-200 or non-empty items, or the negative
  control does not return 502

### TICKET-04 - parametrized API-tier coverage for all 41 catalog kinds

- **Tracker ID:** TASK-076
- **Scope:** blueprint Task 4: the held-out parametrized suite in
  `backend/tests/api/test_resources.py` — iterate every `KINDS` row
  (registry keys as ids): list 200 + items == expected (projector applied
  when set; the 4 LB method rows excluded from list/namespace cases),
  cluster-scoped rows ignore `namespace=kube-system`, gettable rows
  `?name=present` → 1 item / `?name=absent` → `[]`, non-gettable rows
  `?name=` → 404 `RESOURCE_KIND_NOT_SUPPORTED`, per-row SAR attribute
  assertion, CRD rows additionally the CRD-absent case; the meta test
  `test_every_catalog_row_has_fixture_data` (LB overrides exempt with an
  empty-list sentinel + `provider` marker); provider-detection tests for the
  4 external-LB overrides (MetalLB-present wins, MetalLB-absent → Cilium
  fallback, both absent → `[]`) ported from the existing tests.
- **Acceptance:** `uv run pytest -m "not integration"` green; the
  parametrized suite covers all 41 rows (deleting any `FIXTURES` entry makes
  the meta test or that row's case fail — the drift gate); the 3 LB
  provider-detection behaviours assert as specified.
- **SATISFIES:** every-kind-covered; get-name-semantics; unknown-kind-404
- **Files:** `backend/tests/api/test_resources.py`
- **Size:** ~450 (S)
- **Blocks:** TICKET-05
- **Blocked by:** TICKET-03
- **Precondition:** TICKET-03 committed — 37 rows are `method=None` (the 4
  external-LB rows keep their named methods) and `uv run pytest -m "not
  integration"` is green
- **Fails-when:** `uv run pytest -m "not integration"` exits non-zero, or
  the parametrized suite collects fewer than 41 rows

### TICKET-05 - split k8s_client.py into five concept modules

- **Tracker ID:** TASK-077
- **Scope:** blueprint Task 5 (move-only, behaviour identical): create
  `backend/app/services/kubeconfig_crypto.py` (`key()`,
  `encrypt_kubeconfig`, `decrypt_kubeconfig` — the `KUBEDASH_SECRET_KEY`
  one-way door untouched), `kubeconfig_binding.py` (`bound_cluster_or_404`,
  `resolve_admin_source`), `k8s_metrics.py` (`node_metrics`, `node_usage`,
  `pvc_usage`, `_node_metrics`, `_parse_stats_body`, `_parse_cpu`,
  `_parse_bytes` moved verbatim — `cluster_allocation.py` keeps its
  deliberate private copy, out of scope per user decision 2026-11-07);
  `k8s_client.py` keeps client construction + engine + mutations + `readyz`
  + `K8sClientPool` (seam owner) + `get_crd_served` delegate + non-catalog
  reads (`list_events`, `list_crd_instances`) + thin one-line metrics
  delegates; update every importer of the moved names (authoritative sweep:
  `grep -rln "from app.services.k8s_client import" backend/app backend/tests`
  — ~16 source/test files, import-only edits; `test_resources.py`'s lazy
  `encrypt_kubeconfig` import included).
- **Acceptance:** `uv run pytest -m "not integration" && uv run ruff check .
  && uv run mypy app` all green (from `backend/`); the moved functions exist
  at the named modules with docstrings intact; no file still imports a moved
  name from `k8s_client`; `wc -l backend/app/services/k8s_client.py` < ~900;
  `K8sClientPool` still in `k8s_client.py`; `cluster_allocation.py` diff is
  empty.
- **SATISFIES:** concepts-split
- **Files:** `backend/app/services/kubeconfig_crypto.py` (new), `backend/app/services/kubeconfig_binding.py` (new), `backend/app/services/k8s_metrics.py` (new), `backend/app/services/k8s_client.py`, ~16 importer files (import-only edits, found by the named grep)
- **Size:** ~800 (M)
- **Blocks:** TICKET-06
- **Blocked by:** TICKET-04
- **Precondition:** TICKET-04 committed and `uv run pytest -m "not
  integration"` is green
- **Fails-when:** any of pytest/ruff/mypy exits non-zero, or `wc -l
  backend/app/services/k8s_client.py` is >= 900, or the importer grep shows
  a moved name still imported from `k8s_client`

### TICKET-06 - collapse private test doubles onto the shared FakeK8s

- **Tracker ID:** TASK-078
- **Scope:** blueprint Task 6: the shared `FakeK8s` (at
  `backend/tests/fakes/fake_k8s.py` since TICKET-01) absorbs every private
  fake — authoritative list: `grep -rlEn "class _?Fake.*K8s" backend/tests/`
  (currently 9 files: `test_resources.py`, `test_clusters.py`,
  `test_events.py`, `test_permissions.py`, `test_gateway_api.py`,
  `test_metrics_pvcs.py`, `test_metrics_summary.py`, `test_permission.py`,
  `test_admin_source.py` — fold in the metric fakes and `FakeAdminK8s`). One
  constructor `(kubeconfig, data=None, readyz_result=True, available=True,
  raise_unreachable=False, crd_absent=frozenset())` covering all private
  signatures; the mutation/metrics/`readyz` methods each suite calls ported
  1:1 (conflicting canned values resolved per-suite via constructor data,
  not branches); the union of recording hooks (`last_pod_label_selector`,
  `pvc_usage_calls`, `node_usage_calls`, `calls`, `crd_instance_calls`,
  `last_rules`/`last_labels`); swap the imports, delete the private fakes.
  A suite whose private fake disappears keeps its passing tests — fix the
  shared fake, never the expectation.
- **Acceptance:** `uv run pytest -m "not integration"` green;
  `grep -rlEn "class _?Fake.*K8s" backend/tests/` → exactly 1 file
  (`tests/fakes/fake_k8s.py`); every suite injects the shared fake through
  `pool.factory`.
- **SATISFIES:** one-double
- **Files:** `backend/tests/fakes/fake_k8s.py`, `backend/tests/api/test_resources.py`, `test_clusters.py`, `test_events.py`, `test_permissions.py`, `test_gateway_api.py`, `test_metrics_pvcs.py`, `test_metrics_summary.py`, `backend/tests/services/test_permission.py`, `backend/tests/test_admin_source.py`
- **Size:** ~1100 (M)
- **Blocks:** TICKET-07
- **Blocked by:** TICKET-05
- **Precondition:** TICKET-05 committed — the import sweep is complete and
  `uv run pytest -m "not integration"` is green
- **Fails-when:** `uv run pytest -m "not integration"` exits non-zero, or
  `grep -rlEn "class _?Fake.*K8s" backend/tests/` lists more than 1 file

### TICKET-07 - green, measured, documented

- **Tracker ID:** TASK-079
- **Scope:** blueprint Task 7: run the full floor; prove the interface
  shrank — `grep -c "    def list_\|    def get_" backend/app/services/k8s_client.py`
  → only the 4 external-LB override pairs + `list_events` remain, `wc -l`
  recorded; re-run `npx jscpd --health --reporters ai .` and record the new
  health score + `k8s_client.py`/`test_resources.py` complexity vs the
  2026-11-07 baseline (health 32/E; `k8s_client` cx 393/2,487L;
  `test_resources` cx 307/3,938L); **add** (not modify) the read-path
  section to `.skillgrid/ARCHITECTURE.md` — the as-built catalog + engine +
  five concepts, ADR-0010's informer cache noted as the planned replacement —
  plus the kind-addition procedure (one catalog row + one fixture entry);
  commit with the measurement numbers in the body.
- **Acceptance:** full floor green; the grep count assertion holds; the
  measurement numbers are in the commit body; `ARCHITECTURE.md` contains the
  read-path section + kind-addition procedure.
- **SATISFIES:** green-and-measured
- **Files:** `.skillgrid/ARCHITECTURE.md`
- **Size:** ~100 (S)
- **Blocks:** none
- **Blocked by:** TICKET-06
- **Precondition:** TICKET-06 committed — the full floor
  (`pytest` + `ruff` + `mypy`) is green
- **Fails-when:** any full-floor command exits non-zero, or the grep shows a
  `list_`/`get_` method in `k8s_client.py` beyond the 4 LB override pairs +
  `list_events`, or `ARCHITECTURE.md` lacks the read-path section

## Dependency Graph

```mermaid
graph LR
    T01[TICKET-01 door check] --> T02[TICKET-02 typed batch]
    T02 --> T03[TICKET-03 CRD batch]
    T03 --> T04[TICKET-04 parametrized coverage]
    T04 --> T05[TICKET-05 concept split]
    T05 --> T06[TICKET-06 shared FakeK8s]
    T06 --> T07[TICKET-07 green measured documented]
```

## Execution Order

- **Wave 1:** TICKET-01
- **Wave 2:** TICKET-02 (after TICKET-01)
- **Wave 3:** TICKET-03 (after TICKET-02)
- **Wave 4:** TICKET-04 (after TICKET-03)
- **Wave 5:** TICKET-05 (after TICKET-04)
- **Wave 6:** TICKET-06 (after TICKET-05)
- **Wave 7:** TICKET-07 (after TICKET-06)

> **Acceptance-first (BDD is always on):** a ticket's failing acceptance
> scenario (its `SATISFIES` scenario) is written and confirmed RED *before*
> the implementation that makes it green. TICKET-01's Task-1 Step 1 is the
> RED phase for the engine; each cutover ticket's new assertions (fixture
> matches, crd_absent, 502 normalizations) are confirmed RED against the
> pre-cutover code before the row flips.

## Slicing Notes

- **Why a linear chain (no parallel waves):** every ticket after TICKET-01
  owns at least one of `k8s_client.py`, `test_resources.py`,
  `fake_k8s.py` or `k8s_data.py`, and the global constraint "suite green at
  every commit" (blueprint) forbids interleaved cutover commits. Concrete
  overlaps that killed parallelism: TICKET-02/03 both cut over through
  `k8s_client.py` (method deletions are the commit content); TICKET-04 vs
  TICKET-05 both touch `test_resources.py` (TICKET-05's import sweep hits
  its lazy `encrypt_kubeconfig` import); TICKET-05 vs TICKET-06 both touch
  `test_metrics_pvcs.py`/`test_metrics_summary.py`/`test_clusters.py`/
  `test_admin_source.py` (import-only sweep vs fake deletion).
- **Door check is stop-the-line:** TICKET-01 carries the blueprint's door
  check — a FAILED verdict (any kind needing per-kind branching inside the
  engine) invalidates the blueprint; the executor stops and reports, it does
  not improvise a fifth override (the named-override set is closed, per the
  blueprint's Global Constraints).
- **TICKET-02 is L by deletion volume, not by new logic:** the ~1800
  changed lines are dominated by removed method/fake bodies; the net new
  logic is ~22 `_typed` entries + fixture ports. The blueprint's own task
  seam was kept per the slicing contract (deletions are grep-guided and
  cheap in context).
- **TICKET-03 covers 12, not 13, kinds:** `gatewayclasses` already cut over
  in TICKET-01's door check (that is why the tracer set includes it — the
  served-version branch is exercised at the door, not in Task 3).
- **TICKET-05 is move-only:** behaviour identical, verified by the suite;
  `K8sClientPool` stays in `k8s_client.py` (it is the seam owner, ADR-0006/
  0007/0008 shape unchanged); `cluster_allocation.py` keeps its deliberate
  private quantity-parser copy (out of scope, user decision 2026-11-07).
- **TICKET-06's authoritative list currently names 9 files** (the blueprint
  expected 7 named + `_FakeK8s` + possibly `FakeAdminK8s`; the grep
  additionally surfaces the `test_metrics_*` fakes). All are folded in; the
  blueprint designates the grep as authoritative.
- **Cross-change landing order (note only, NOT ticket blockers):** D
  (dead-code cleanup) → A (this change) → B (frontend kind registry) → C
  (navigation seam). This change must land before B and C consume the
  catalog.
- **Chain strategy is `pending`** (ask-on-risk): the executor asks the
  user at apply time between `stacked-to-main` and `feature-branch-chain`.
