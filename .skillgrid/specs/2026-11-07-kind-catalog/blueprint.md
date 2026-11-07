# Kind Catalog — Backend Read Path — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T2
**Build shape:** Tracer thread — the open risk is engine expressiveness (can one generic engine express all 41 kinds without per-kind branching?); the tracer proves it on two kinds (one typed cluster-scoped, one typed namespaced with a projector) before any batch is cut.
**Classification:** standard (L2 verification floor: full unit suite + build)
**Goal:** Replace the ~88 per-kind `list_X`/`get_X` methods + `_KINDS`/`_GETTERS` string tables + 8 drifting test doubles with a typed kind catalog, one generic read engine at the existing factory seam, and one catalog-driven `FakeK8s` with fixture data — behaviour unchanged.
**Architecture:** `app/services/kinds.py` declares every registry kind as a `KindSpec` (API plural, group, version, scope, CRD flag, projector, named-override method). `K8sClient.list(kind, ns, label_selector)` / `get(kind, ns, name)` are the engine: one behaviour home for the namespace branch, `?name=` 404 → `[]`, CRD-absent → `[]` (glossary: *CRD-absent degrade*), transport failure → `ClusterUnreachableError` → 502. Typed kinds read through the typed clients (model deserialization + `to_dict()` → snake_case, the wire shape today); CRD kinds read through `CustomObjectsApi` at the CRD's served version (wire form, camelCase — also today's shape). `ResourceApi` dispatches and asks SAR from the same registry; `_KINDS`/`_GETTERS` are deleted. Cutover is kind-by-kind: each row flips from `method="list_X"` (legacy dispatch) to `method=None` (engine), the method is deleted, and the suite is green before the next batch.
**Tech Stack:** Python 3.12, Flask 3 + Smorest, kubernetes python client (backend venv), pytest, ruff + mypy.
**Spec:** `./briefing.md`
**Critic:** pending

## Hypothesis

**Claim:** A catalog row + one generic engine expresses the read behaviour of all 41 kinds with no special case beyond the four declared exceptions (pods `labelSelector` pass-through, PV claim-namespace filter, secrets data-strip, external-LB provider detection).
**Right condition:** all 41 rows wired (`method=None`, except the 4 declared overrides); the ~76 per-kind list/get methods deleted; the parametrized suite green for every catalog kind; REST response shapes byte-identical to the legacy path (snake_case typed / camelCase CRD wire form).
**Wrong condition:** the door check (Task 1) finds a kind whose behaviour needs per-kind branching *inside* the engine, or a deserialization shape (snake_case vs wire) drifts, or SAR attributes differ from today's `_KINDS` values.
**Thinnest MVP:** `ingressclasses` + `secrets` migrated end-to-end (catalog rows, engine, `FakeK8s` data, tests green, methods deleted).
**Door check:** Task 1 — if it fails, stop; the blueprint is invalidated and the user decides.

## Terms

- **Kind**, **Kind catalog**, **Registry kind** — `.skillgrid/knowledge/glossary/02-technical-terms.md` (added 2026-11-07 with ADR-0041)
- **CRD-absent degrade** — glossary: a read of a cluster with the CRD uninstalled returns `[]`, not an error
- No other terms; the plan uses only the spec's and the repo's existing vocabulary

## Must-Haves (goal-backward verification)

**Truths** (observable behaviours that must hold):
- [backstop] `GET /api/v1/clusters/<id>/resources/<kind>` returns the same `items` as before for every catalog kind — backstop because a full REST diff needs the held-out parametrized suite (Task 4) + the e2e smoke, not a diff read
- Typed kinds return `to_dict()` snake_case shape; CRD kinds return wire-form (camelCase) shape — no REST shape change for any kind
- `?name=` on a gettable kind: missing object → 200 `items: []`; present → `items: [obj]`; on a non-gettable kind → 404 `RESOURCE_KIND_NOT_SUPPORTED` (as today)
- Cluster-scoped kinds ignore the `namespace` query; CRD kinds branch on the **served** scope (CRD metadata is the authority, glossary)
- CRD-absent kind list → 200 `items: []`; CRD present but read 404 → `[]`; any transport failure → `ClusterUnreachableError` → 502
- `?labelSelector=` on `pods` forwards to the namespaced list call only (ignored without a namespace — the `list_pods` docstring contract); other kinds ignore it
- `list_secrets` items have no `data`/`string_data` keys
- `persistentvolumes` list is the cluster list filtered to the selected namespace via `claim_ref` (free/unbound PVs always visible)
- The SAR gate is asked **before** the read with exactly today's attributes: `(verb, api_resource, namespace, name, api_group)` from the catalog row (ADR-0004)
- External-LB kinds keep MetalLB-primary / Cilium-fallback provider detection (named overrides)
- A catalog row with no fixture data fails its own test (drift becomes a test failure, not a missing test)

**Artifacts** (files that must exist with real implementation):
- `backend/app/services/kinds.py` — `KindSpec` dataclass + `KINDS` registry (41 rows)
- `backend/app/services/crds.py` — served-version resolution + custom-object body helpers (extracted from `k8s_client.py`)
- `backend/app/services/k8s_metrics.py` — node/PV metrics + the shared k8s quantity parser
- `backend/app/services/kubeconfig_crypto.py` — AES-256-GCM kubeconfig encrypt/decrypt (`KUBEDASH_SECRET_KEY` one-way door untouched)
- `backend/app/services/kubeconfig_binding.py` — `bound_cluster_or_404` + `resolve_admin_source`
- `backend/app/services/k8s_client.py` — client construction + typed-reader table + engine + mutations + `readyz` + `K8sClientPool` (slimmed)
- `backend/tests/fakes/fake_k8s.py` — the single shared, catalog-driven double
- `backend/tests/fixtures/k8s_data.py` — per-kind fixture data
- `backend/tests/api/test_resources.py` — parametrized kind tests; no local `FakeK8s`

**Key links** (critical connections that must work together):
- `resources.py` SAR group/plural come from `KindSpec` (the `_KINDS`/`_GETTERS` tables are deleted, not kept in parallel)
- The engine's `crd=True` path calls `crds.served_version(...)`; the `crds` kind row is the one CRD-path kind with a **fixed** version (`apiextensions.k8s.io/v1`, no served resolution)
- `FakeK8s.list`/`get` read the same `KINDS` keys as `resources.py` dispatch — a kind-name typo fails the test that references it
- The Task 4 parametrized test iterates `KINDS` — a future new row automatically gets its API-tier test
- The quantity parser that today is duplicated between `cluster_allocation.py` and `k8s_client.py` (jscpd clone pair) has one home after the split

**One-way-door decisions:** None — no migration, no public API shape change (REST behaviour preserved), no new dependency, no config key. The `KUBEDASH_SECRET_KEY` one-way door is touched only by moving the code that reads it, not by changing it.

## Global Constraints

- Python 3.12; **no new third-party dependencies**
- `app/services/` stays pure Python (no Flask imports) — testable via `K8sClientPool.factory` injection (ADR-0006/0007/0008 shape unchanged)
- `uv run ruff check . && uv run mypy app` clean; `uv run pytest -m "not integration"` green at **every** commit
- REST behaviour preserved: same paths, status codes, error codes, response shapes; SAR gate before every read (ADR-0004); object navigation unchanged (ADR-0040); no hard-coded identity/credential defaults (ADR-0028)
- Conventional commits; this blueprint commits (spec zone) before any code-zone commit
- The named-override set is closed: pods `labelSelector` (engine kwarg, no method), PV claim filter + secrets strip (projectors), the 4 external-LB provider-detect methods. Anything else the batches surface is a door-check failure, not a fifth override

## File Structure

- `backend/app/services/kinds.py` — `KindSpec` + `KINDS`: the typed catalog. No behaviour; data + the two projectors.
- `backend/app/services/crds.py` — `served_version(api_client, group, plural) -> (version, scope) | None`, `custom(api_client) -> CustomObjectsApi`, `crd_body(resp) -> dict` — extracted verbatim from `k8s_client.py` (`_crd_served`, `get_crd_served`, `_custom`, `_crd_body`).
- `backend/app/services/k8s_metrics.py` — `node_metrics`, `node_usage`, `pvc_usage`, `_node_metrics`, `_parse_stats_body`, `_parse_cpu`, `_parse_bytes` (quantity parser — the shared home).
- `backend/app/services/kubeconfig_crypto.py` — `_key`, `encrypt_kubeconfig`, `decrypt_kubeconfig`.
- `backend/app/services/kubeconfig_binding.py` — `bound_cluster_or_404`, `resolve_admin_source`.
- `backend/app/services/k8s_client.py` — `K8sClient.__init__` (API objects + `_typed` reader table), `list(kind, namespace, label_selector)` / `get(kind, namespace, name)` engine, non-catalog reads (`list_events`), mutations (`create_namespace`, `delete_namespace`, `apply_*`, `delete_*`), `readyz`, `K8sClientPool`, `build_admin_client`, `admin_client_ok`.
- `backend/app/api/resources.py` — catalog-derived dispatch + SAR; `_KINDS`/`_GETTERS` deleted; `_APPLY_PLURALS`/`_APPLY_CLUSTER_SCOPED` (apply path) untouched.
- `backend/tests/fakes/fake_k8s.py` — `FakeK8s`: `list`/`get` driven by `KINDS` + fixture data, `crd_absent` toggle, call recording (`last_pod_label_selector` etc.), plus the mutation/metrics methods the suites need.
- `backend/tests/fixtures/k8s_data.py` — `FIXTURES: dict[str, list[dict]]` — per-kind items, ported 1:1 from the current `FakeK8s` method bodies.
- `backend/tests/api/test_resources.py` — parametrized kind tests; imports the shared fake.

## The Catalog (41 rows)

`group`: `""` = core. `crd`: served-version `CustomObjectsApi` path. `method`: `None` = engine; named = closed override set. Projectors live in `kinds.py`.

| kind | group | cluster-scoped | crd | gettable | method (final) | projector |
|---|---|---|---|---|---|---|
| pods | `""` | no | no | no | `None` | — (engine forwards `label_selector`) |
| namespaces | `""` | yes | no | no | `None` | — |
| nodes | `""` | yes | no | no | `None` | — |
| serviceaccounts | `""` | no | no | no | `None` | — |
| roles | `rbac.authorization.k8s.io` | no | no | no | `None` | — |
| rolebindings | `rbac.authorization.k8s.io` | no | no | no | `None` | — |
| clusterroles | `rbac.authorization.k8s.io` | yes | no | no | `None` | — |
| clusterrolebindings | `rbac.authorization.k8s.io` | yes | no | no | `None` | — |
| secrets | `""` | no | no | yes | `None` | `strip_secret_data` |
| crds | `apiextensions.k8s.io` | yes | yes (fixed `v1`) | yes | `None` | — |
| networkpolicies | `networking.k8s.io` | no | no | yes | `None` | — |
| ciliumnetworkpolicies | `cilium.io` | no | yes | yes | `None` | — |
| ciliumclusterwidenetworkpolicies | `cilium.io` | yes | yes | no | `None` | — |
| ingressclasses | `networking.k8s.io` | yes | no | yes | `None` | — |
| ingresses | `networking.k8s.io` | no | no | yes | `None` | — |
| priorityclasses | `scheduling.k8s.io` | yes | no | yes | `None` | — |
| runtimeclasses | `node.k8s.io` | yes | no | yes | `None` | — |
| storageclasses | `storage.k8s.io` | yes | no | yes | `None` | — |
| resourcequotas | `""` | no | no | yes | `None` | — |
| services | `""` | no | no | yes | `None` | — |
| poddisruptionbudgets | `policy` | no | no | yes | `None` | — |
| verticalpodautoscalers | `autoscaling.k8s.io` | no | yes | yes | `None` | — |
| gatewayclasses | `gateway.networking.k8s.io` | yes | yes | yes | `None` | — |
| gateways | `gateway.networking.k8s.io` | no | yes | yes | `None` | — |
| httproutes | `gateway.networking.k8s.io` | no | yes | yes | `None` | — |
| referencegrants | `gateway.networking.k8s.io` | yes | yes | yes | `None` | — |
| horizontalpodautoscalers | `""` | no | no | yes | `None` | — |
| limitranges | `""` | no | no | yes | `None` | — |
| configmaps | `""` | no | no | yes | `None` | — |
| volumesnapshotclasses | `snapshot.storage.k8s.io` | yes | yes | yes | `None` | — |
| volumesnapshots | `snapshot.storage.k8s.io` | no | yes | yes | `None` | — |
| persistentvolumeclaims | `""` | no | no | yes | `None` | — |
| persistentvolumes | `""` | yes | no | yes | `None` | `pv_claim_filter` |
| clusterissuers | `cert-manager.io` | yes | yes | yes | `None` | — |
| issuers | `cert-manager.io` | no | yes | yes | `None` | — |
| certificaterequests | `cert-manager.io` | no | yes | yes | `None` | — |
| certificates | `cert-manager.io` | no | yes | yes | `None` | — |
| ipaddresspools | `metallb.io` | yes | yes | yes | `list_ipaddresspools` | — |
| l2advertisements | `metallb.io` | no | yes | yes | `list_l2advertisements` | — |
| bgppeers | `metallb.io` | yes | yes | yes | `list_bgppeers` | — |
| bgpadvertisements | `metallb.io` | yes | yes | yes | `list_bgpadvertisements` | — |

Typed reader table (engine, typed kinds only — one line per kind, built in `K8sClient.__init__` from the existing API objects): kind → `(list_all, list_ns, get_all, get_ns)`, e.g. `pods → (v1.list_pod_for_all_namespaces, v1.list_namespaced_pod, —, —)`, `ingresses → (networking.list_ingress_for_all_namespaces, networking.list_namespaced_ingress, —, networking.read_namespaced_ingress)`. `get_ns` generated methods take `(name, namespace)`; `get_all` take `(name)`. Cluster-scoped kinds have no `list_ns`/`get_ns`.

---

### Task 1: Door check — catalog schema, engine, tracer kinds (ingressclasses + secrets)

**Files:**
- Create: `backend/app/services/kinds.py`, `backend/app/services/crds.py`, `backend/tests/fixtures/k8s_data.py`
- Modify: `backend/app/services/k8s_client.py` (engine + `_typed` entries for the two kinds; `_crd_served`/`get_crd_served`/`_custom`/`_crd_body` delegate to `crds.py`), `backend/app/api/resources.py` (registry dispatch), `backend/tests/api/test_resources.py` (FakeK8s `list`/`get` for the two kinds)
- Test: `backend/tests/api/test_resources.py`

**Interfaces:**
- Produces: `KindSpec` dataclass `(plural: str, group: str, cluster_scoped: bool = False, crd: bool = False, version: str | None = None, gettable: bool = False, method: str | None = "list_<snake>", projector: Callable[[list[dict[str, Any]], str | None], list[dict[str, Any]]] | None = None)`; `KINDS: dict[str, KindSpec]` (all 41 rows seeded — `method` names ported from `_KINDS`, `gettable` from `_GETTERS`, `crd`/`cluster_scoped`/`version` from the method bodies); `K8sClient.list(kind: str, namespace: str | None = None, label_selector: str | None = None) -> list[dict[str, Any]]`; `K8sClient.get(kind: str, namespace: str | None, name: str) -> list[dict[str, Any]]`; `crds.served_version(api_client, group, plural) -> tuple[str, str] | None`
- Seam: `K8sClientPool.factory` — the engine is reached through the same factory-injected client the route uses; `FakeK8s` satisfies `list`/`get` identically
- Deletion test: deleting the engine re-creates ~10 lines of try/except + namespace branch + 404/CRD-absent handling per kind across 76 call sites (the `resources.py` route + every future adapter, ADR-0010)
- Adapters: 2 at the seam — real `K8sClient` + `FakeK8s`

**SATISFIES:** `tracer-kinds-catalog`

- [ ] **Step 1: Write the failing tests.** In `test_resources.py`: (a) `test_ingressclasses_via_catalog` — route `GET .../resources/ingressclasses` returns the fixture items from `k8s_data.FIXTURES["ingressclasses"]`, SAR asked with `("list", "ingressclasses", <ns>, None, "networking.k8s.io")`; (b) `test_ingressclasses_get_missing_returns_empty` — `?name=absent` → 200 `items: []`; (c) `test_secrets_strip_data` — fixture secrets with `data`/`string_data` come back stripped; (d) engine unit tests on `K8sClient` with a stub `ApiException`: transport failure → `ClusterUnreachableError`; (e) **shape assertions**: typed item keys snake_case (`creation_timestamp`), CRD-path item keys wire camelCase (`creationTimestamp`) — pin the two deserialization regimes now. Run: `uv run pytest tests/api/test_resources.py -k "via_catalog or get_missing or strip_data" -v`. Expected: FAIL (`KINDS`/`list`/`get` not defined).
- [ ] **Step 2: Implement `kinds.py`** — `KindSpec` + all 41 rows (source: `_KINDS`/`_GETTERS` tables + per-method bodies, transcribed row by row) + `strip_secret_data`/`pv_claim_filter` projectors.
- [ ] **Step 3: Implement `crds.py`** — move `_crd_served`, `get_crd_served` logic (read CRD by fully-qualified `plural.group` name, 404 → `None`, other ApiException → `ClusterUnreachableError`), `_custom`, `_crd_body` to module functions taking `api_client`; `k8s_client.py` delegates (same behaviour, same docstrings).
- [ ] **Step 4: Implement the engine** in `k8s_client.py` — `list`/`get` per the Architecture section: `spec = KINDS[kind]`; `spec.method is not None` → `getattr(self, spec.method)(namespace, label_selector=label_selector) if kind == "pods" else ...` — **no**: engine only handles `method is None` rows; the route does the method branch (see Step 5). Typed branch: `_typed[kind]` reader; CRD branch: `crds.served_version` (absent → `[]`), `CustomObjectsApi` at served version/scope, wire items. `label_selector` forwarded on the namespaced typed branch only (all namespaced generated methods accept it; cluster-scoped branches never pass it).
- [ ] **Step 5: Rework `resources.py` dispatch** — `spec = KINDS.get(kind)` (missing → `ResourceKindNotSupportedError`); SAR from `spec.group`/`spec.plural` with today's argument order (`rbac.can(user, cluster, verb, api_resource, namespace, name, api_group)`); `name` path: `spec.gettable` gate (else `RESOURCE_KIND_NOT_SUPPORTED`), `namespace = namespace or "default"`, then `client.get(kind, namespace, name)`; list path: `client.list(kind, namespace, label_selector=request.args.get("labelSelector"))` **only when `kind == "pods"`** otherwise `client.list(kind, namespace)`; `method` rows dispatch via `getattr(client, spec.method)` inside `client.list`/`get` (the client routes its own overrides — `resources.py` stays override-agnostic). Delete `_KINDS`/`_GETTERS`; keep `_APPLY_PLURALS`/`_APPLY_CLUSTER_SCOPED`.
- [ ] **Step 6: FakeK8s `list`/`get`** — catalog-driven: `list(kind, ns, label_selector=None)` reads `FIXTURES[kind]`, filters by `metadata.namespace` for namespaced rows when `ns` given, returns `[]` for `crd_absent` rows, records `last_pod_label_selector`; `get(kind, ns, name)` filters by name → `[]` when missing. Seed `FIXTURES["ingressclasses"]` (wire form) + `FIXTURES["secrets"]` (with `data`/`string_data`) from the current fake bodies.
- [ ] **Step 7: Flip the two rows** (`method=None`) and delete `list_ingress_classes`, `get_ingress_class`, `list_secrets`, `get_secret` from `k8s_client.py` (and the matching `FakeK8s` methods).
- [ ] **Step 8: Run + door-check verdict.** `uv run pytest -m "not integration"`. Green → door check PASSED; record it in the commit body. Any per-kind branching needed inside the engine beyond {namespace branch, 404, CRD-absent, transport, projector, `label_selector`} → **stop, report, user decides** (door check FAILED).
- [ ] **Step 9: Commit.** `refactor: kind catalog + generic read engine; cutover ingressclasses, secrets (door check passed)`

### Task 2: Typed batch — core, rbac, node, storage, scheduling, policy, autoscaling, networking, apiextensions

**Kinds (21):** namespaces, nodes, serviceaccounts, pods, roles, rolebindings, clusterroles, clusterrolebindings, networkpolicies, ingresses, priorityclasses, runtimeclasses, storageclasses, resourcequotas, services, poddisruptionbudgets, horizontalpodautoscalers, limitranges, configmaps, persistentvolumeclaims, persistentvolumes, crds (22 rows).

**Files:**
- Modify: `backend/app/services/k8s_client.py` (`_typed` entries for the batch; delete the batch's methods), `backend/tests/fixtures/k8s_data.py` (fixture entries ported 1:1 from the current `FakeK8s` bodies + test assertions in `test_resources.py`), `backend/tests/api/test_resources.py` (delete the batch's fake methods)
- Test: `backend/tests/api/test_resources.py` (existing per-kind tests are the behaviour backstop)

**Interfaces:**
- Consumes: Task 1's engine, `KINDS`, `FakeK8s.list`/`get`
- Produces: nothing new — the batch is row flips + deletions

**SATISFIES:** `typed-kinds-catalog`

- [ ] **Step 1: Port fixtures.** For each kind in the batch, add `FIXTURES[kind]` — items copied 1:1 from the current `FakeK8s` method bodies (the named source), plus any items the existing route tests assert on. Add `crds` fixture (wire form, as `list_crds` returns).
- [ ] **Step 2: Add `_typed` reader entries** in `K8sClient.__init__` for the batch (bound method references per the Catalog section's reader table).
- [ ] **Step 3: Run the suite** — `uv run pytest -m "not integration"`. The existing per-kind route tests now exercise the engine path for the un-flipped rows only after the flip; run first to confirm the fixture data matches existing assertions (fix fixtures, never test expectations, on mismatch).
- [ ] **Step 4: Flip the 22 rows** (`method=None`) in `kinds.py`.
- [ ] **Step 5: Delete the batch's per-kind methods** from `k8s_client.py` (`list_namespaces`, `list_nodes`, …, `get_persistent_volume`, `list_crds`, `get_crd` — including the `pods` method; `label_selector` is now an engine kwarg) and the matching `FakeK8s` methods.
- [ ] **Step 6: Run + commit.** `uv run pytest -m "not integration"` green → `refactor: cutover typed kind batch to catalog engine (22 kinds)`

### Task 3: CRD batch — served-version `CustomObjectsApi` kinds

**Kinds (13):** ciliumnetworkpolicies, ciliumclusterwidenetworkpolicies, verticalpodautoscalers, gatewayclasses, gateways, httproutes, referencegrants, volumesnapshotclasses, volumesnapshots, clusterissuers, issuers, certificaterequests, certificates. (The 4 external-LB kinds stay named overrides — closed set.)

**Files:**
- Modify: `backend/tests/fixtures/k8s_data.py` (wire-form fixture entries for the 13), `backend/app/services/k8s_client.py` (delete the batch's methods), `backend/tests/api/test_resources.py` (delete the batch's fake methods; add per-kind CRD-absent assertions)

**Interfaces:**
- Consumes: Task 1's engine CRD branch + `crds.served_version`; Task 2's fixture convention
- Produces: nothing new

**SATISFIES:** `crd-kinds-catalog`

- [ ] **Step 1: Fixtures + `crd_absent` wiring.** `FIXTURES` entries for the 13 (wire form — the named source: the current `FakeK8s` method bodies, e.g. `list_gateway_classes` returns wire dicts); `FakeK8s` gains `crd_absent: frozenset[str]` (default empty) → `list` returns `[]` for rows in it.
- [ ] **Step 2: CRD-absent tests.** For each of the 13: `test_<kind>_crd_absent_returns_empty` — fake with `crd_absent={kind}`, route → 200 `items: []`. Plus one negative control: a transport failure (fake raising) → 502 `CLUSTER_UNREACHABLE`.
- [ ] **Step 3: Flip the 13 rows** (`method=None`); delete `list_cilium_network_policies`, `get_gateway_class`, `list_http_routes`, … (the 13 pairs) from `k8s_client.py` and the matching fake methods.
- [ ] **Step 4: Run + commit.** `uv run pytest -m "not integration"` green → `refactor: cutover CRD kind batch to served-version engine (13 kinds)`

### Task 4: Coverage recovery — parametrized API-tier tests for every catalog kind

**Files:**
- Modify: `backend/tests/api/test_resources.py` (parametrized suite + meta test)
- Test: same

**Interfaces:**
- Consumes: `KINDS` (Task 1), `FIXTURES` (Tasks 1–3)
- Produces: the drift gate — a future row with no fixture data or no working engine path fails here

**SATISFIES:** `every-kind-covered`

- [ ] **Step 1: Parametrized suite.** `@pytest.mark.parametrize("spec", KINDS.values(), ids=lambda s: <registry kind>)` (the registry dict keys as ids): (a) list 200 + items == `FIXTURES[kind]` (namespaced rows also assert a `namespace=` filter case); (b) cluster-scoped rows: `namespace=kube-system` is ignored; (c) gettable rows: `?name=<fixture item>` → 1 item; `?name=absent` → `[]`; non-gettable rows: `?name=` → 404 `RESOURCE_KIND_NOT_SUPPORTED`; (d) SAR attribute assertion per row: `(verb, spec.plural, ns, name, spec.group)` recorded on the fake; (e) `crd` rows additionally the CRD-absent case (reuses Task 3's fake toggle).
- [ ] **Step 2: Meta test.** `test_every_catalog_row_has_fixture_data` — every `KINDS` key has a non-empty `FIXTURES` entry (the external-LB overrides are exempt: their data comes from provider detection; assert they at least appear in `FIXTURES` as an empty-list sentinel + a `provider` marker).
- [ ] **Step 3: Provider-detection tests** for the 4 external-LB overrides (MetalLB-present wins, MetalLB-absent → Cilium fallback, both absent → `[]`) — ported from the existing `test_gateway_api`/resource tests.
- [ ] **Step 4: Run + commit.** Full `uv run pytest -m "not integration"` → `test: parametrized API-tier coverage for all 41 catalog kinds`

### Task 5: Split `k8s_client.py` into its five concepts

**Files:**
- Create: `backend/app/services/k8s_metrics.py`, `backend/app/services/kubeconfig_crypto.py`, `backend/app/services/kubeconfig_binding.py`
- Modify: `backend/app/services/k8s_client.py` (move the three concepts out), `backend/app/services/cluster_allocation.py` (use the shared quantity parser)
- Modify: every importer of the moved names — find with `grep -rln "from app.services.k8s_client import" app/ tests/`; update each import list (import-only edits)
- Test: `backend/tests/services/test_k8s_client.py` (and any test importing the moved names — same grep)

**Interfaces:**
- Produces: `k8s_metrics.node_metrics(client, ...)`, `k8s_metrics.pvc_usage(client, ...)`, `k8s_metrics.parse_bytes(s) -> int` (the quantity parser — the single home, replacing the jscpd-clone pair in `cluster_allocation.py`), `kubeconfig_crypto.encrypt_kubeconfig` / `decrypt_kubeconfig` / `key_from_secret(secret)`, `kubeconfig_binding.bound_cluster_or_404(user, cluster_id)` / `resolve_admin_source(user, cluster_id)`
- Seam: unchanged (`K8sClientPool` stays in `k8s_client.py` — it is the seam owner; `wsgi.py` and the API layer import paths for the pool are untouched)
- Deletion test: n/a — this is a move; behaviour identical, verified by the suite

**SATISFIES:** `concepts-split`

- [ ] **Step 1: `git mv`-style extraction.** Move the functions verbatim (docstrings included) into the three modules; `k8s_client.py` re-imports nothing from them except what it calls internally (`bound_cluster_or_404` stays called where it's called — the *API layer* calls it, not `k8s_client`).
- [ ] **Step 2: Update all imports** from Step 1's grep; `cluster_allocation.py` switches to `k8s_metrics.parse_bytes`.
- [ ] **Step 3: Run + commit.** `uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` green → `refactor: split k8s_client into crypto/metrics/binding modules`. Post-check: `wc -l app/services/k8s_client.py` < ~900 (engine + mutations + pool).

### Task 6: Collapse the eight test doubles onto one shared `FakeK8s`

**Files:**
- Create: `backend/tests/fakes/fake_k8s.py` (the current `test_resources.py` `FakeK8s`, now catalog-driven for reads, moves here)
- Modify: `backend/tests/api/test_resources.py`, `backend/tests/api/test_clusters.py`, `backend/tests/api/test_events.py`, `backend/tests/api/test_permissions.py`, `backend/tests/services/test_permission.py` (or the actual locations — `grep -rln "class FakeK8s" tests/` is the authoritative list; expected 8), each keeping only its own test-specific behaviour (subclass or fixture data) and importing the shared fake

**Interfaces:**
- Consumes: `KINDS` + `FIXTURES`
- Produces: `FakeK8s` (shared) — every suite's `pool.factory` injection point
- Deletion test: a suite whose private fake disappears keeps its passing tests (the shared fake satisfies its calls — mismatches surface as test failures, fix the shared fake, never the expectation)

**SATISFIES:** `one-double`

- [ ] **Step 1: Move + generalize.** The shared `FakeK8s` = Tasks 1–4's catalog fake + the mutation/metrics/`readyz` methods the other suites call (each ported 1:1 from the private fakes; conflicting canned values resolved per-suite via constructor data, not branches).
- [ ] **Step 2: Swap the imports**, delete the 7 private fakes.
- [ ] **Step 3: Run + commit.** `uv run pytest -m "not integration"` green → `refactor: single shared FakeK8s (8 doubles → 1)`

### Task 7: Green, measured, documented

**Files:**
- Modify: `ARCHITECTURE.md` (the `k8s_client.py` / read-path section: catalog + engine + the five concepts; the "adding a kind" procedure is now one row + one fixture entry)

**Interfaces:** none

**SATISFIES:** `green-and-measured`

- [ ] **Step 1: Full floor.** `uv run pytest -m "not integration"` + `uv run ruff check .` + `uv run mypy app`.
- [ ] **Step 2: Prove the interface shrank.** `grep -c "    def list_\|    def get_" app/services/k8s_client.py` → only the 4 external-LB override pairs + `list_events` remain; `wc -l` recorded; `npx jscpd --health --reporters ai .` re-run — record the new health score + `k8s_client.py`/`test_resources.py` complexity vs the 2026-11-07 baseline (health 32/E; `k8s_client` cx 393/2,487L; `test_resources` cx 307/3,938L).
- [ ] **Step 3: Update `ARCHITECTURE.md`** read-path section + the kind-addition procedure.
- [ ] **Step 4: Commit.** `docs: kind catalog read path in ARCHITECTURE (ADR-0041 landed)` with the measurement numbers in the body.

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Tasks 1/2/3 (registry + engine); R2 → Task 1 (engine behaviour homes); R3 → Tasks 1/2 (projectors, `label_selector` kwarg, closed override set); R4 → Task 1 Step 5 (tables deleted, SAR from catalog); R5 → Tasks 1/6 (shared fake + fixtures); R6 → Task 4 (parametrized, incl. the drifted kinds); R7 → Task 5 (five concepts); R8 → every task's green step. No gaps.
2. **Must-haves coverage:** every briefing requirement maps to a truth/artifact/key link (R1–R8 ↔ the lists above). The "backstop" truth carries Task 4 as its held-out test.
3. **One-way-door completeness:** none — no migration, no public shape change; nothing to tag.
4. **Placeholder scan:** the only dynamic lists (importer grep, private-fake grep) are named *steps* with the exact command, not TBD values; the 21/13/4 kind lists are exhaustive and closed.
5. **Type consistency:** `KindSpec` fields, `list`/`get` signatures, `crds.served_version` return, `FIXTURES`/`FakeK8s` interfaces used identically in Tasks 1–7.
