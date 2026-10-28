# Priority Classes — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution
> (recommended) or skillgrid:simple-execution to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2 (from `briefing.md`).

**Build shape:** Tracer thread — the `priorityclasses` kind (service method
→ R4 table → list view) is a thin end-to-end path that proves the shape;
the detail view + the nav move thicken it. No integration risk beyond what
the network-policy change already de-risked (same R4 machinery, same SAR
pattern, one less axis: no namespace at all).

**Class:** standard (verification floor L2: full backend unit suite +
`corepack pnpm test` + `task fe-build` + `task fe-check`).

**Goal:** Replace the `/security/priorityclass` stub with a Priority
Classes list + detail (4.1 parity) at `/other-resource/priorityclass`,
backed by one new R4 kind.

**Architecture:** Pure additive on the R4 machinery: two `K8sClient`
methods + one `_KINDS` row + one `_GETTERS` row. The API layer
(`resources.py`) gains no handlers — binding gate, SAR gate, and
`ResourceListOut` come for free. The kind is cluster-scoped (the
`list_nodes` pattern: `namespace` accepted and ignored). Frontend: two
views (cloned from the `Security/Secret` pair) in a new
`views/OtherResource/` folder + `lib/types.ts` block + the nav leaf move
+ stub-route path replacement + the e2e smoke path move.

**Tech Stack:** Flask 3 + Smorest (R4 table); `kubernetes` python client
(`SchedulingV1Api`); marshmallow (existing `ResourceListOut` — no new
schema); React 18 + CoreUI + TanStack Query + `KubeDataTable` +
`react-syntax-highlighter` (already used by `SecretData.tsx`).

**Spec:** `briefing.md` (requirements R1–R4).

**In-force ADRs:** ADR-0004 (SAR is the only gate; cache key carries every
SAR attribute), ADR-0010 (reads through the pool seam; informer cache
interposes *later* — not built), ADR-0020 (air gap — no new dependency),
ADR-0022 (this change retires one `stub` parity row and records the
ratified placement deviation), ADR-0005 (CoreUI).

**Decision note (nav placement):** the leaf moves Security → Other
Resources at `/other-resource/priorityclass` (user decision, 2026-10-27).
The ADR-0022 row is amended in the SAME change (Task 3 Step 5) — it is a
documented, ratified deviation from 4.1, not drift: 4.1's own API lived in
`other_resources.py`, and this becomes the group's first real page.

**Decision note (Created column):** rendered via the EXISTING
`formatTimestamp` in `frontend/src/lib/format.ts` (created by the
2026-10-26-network-policy change: browser-local time, `—` for
null/unparseable). NOT re-invented here.

## Hypothesis

**Claim:** One `_KINDS` row + two `K8sClient` methods make
`/other-resource/priorityclass` a real 4.1-parity feature with zero
changes to the R4 routing/SAR/binding machinery.

**Right condition:** `GET /api/v1/clusters/<id>/resources/priorityclasses`
returns `ResourceListOut` items on a kind-gated cluster; `?name=` returns a
0/1-item list; the list view renders rows; the detail view renders the
fetched object as YAML.

**Wrong condition:** the R4 handler needs a special case for the kind
(proof the table is not the right seam). No other door: the
cluster-scoped list is the plain `list_nodes` pattern, already proven.

**Thinnest MVP:** Task 1 (kind, service + table + one API test).

**Door check:** none beyond Task 1's first API test — there is no
unproven contract in this change (no CRD, no namespace axis, no second
source).

## Terms

Pointers only (canonical in `.skillgrid/knowledge/glossary/` —
`01-business-terms.md` / `02-technical-terms.md`):

- **Resource kind / R4 table** — see `02-technical-terms.md` (the
  `_KINDS` routing table in `backend/app/api/resources.py`; adding a kind
  is one row + one `K8sClient` method).
- **SAR gate** — see `02-technical-terms.md` (ADR-0004 enforcement point,
  `rbac.can` asked BEFORE the read).
- **Pool seam** — see `02-technical-terms.md` (`K8sClientPool`; ADR-0010's
  informer cache interposes here later).
- **Cluster-scoped kind** (usage, this change): a kind whose
  `K8sClient` list method accepts `namespace` and ignores it
  (`list_nodes` pattern) and whose URLs carry no `namespace` param.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):

- `GET /api/v1/clusters/<id>/resources/priorityclasses` returns
  `ResourceListOut` (`kind: "priorityclasses"`, `cluster: <name>`, `items`
  = the cluster's PriorityClasses in kubernetes `to_dict` shape).
  *backstop* (needs a live/kind cluster — the unit tier pins routing and
  error mapping with the `FakeK8s` double; the kind-gated test in
  `test_resources.py` covers the real client).
- `?namespace=<ns>` on the list is accepted and ignored (200, same items —
  the cluster-scoped contract).
- `?name=` returns a 1-item list when the class exists, `[]` on 404
  upstream — the `get_secret` contract.
- SAR denied: a user without `list`/`get` on `priorityclasses` in group
  `scheduling.k8s.io` gets 403 `RBAC_DENIED` naming the resource; the
  cluster read is never attempted (asserted by the SAR record list); the
  SAR carries namespace `None` and the group.
- Binding gate: unbound user / unknown id → 404 `CLUSTER_NOT_FOUND`.
- Singular `priorityclass` is NOT a kind: 404 `RESOURCE_KIND_NOT_SUPPORTED`
  (guards against the 4.1 route-name leaking in as a kind).
- Frontend: `/other-resource/priorityclass` renders the cluster's
  priority classes (Name / Value / Preemption Policy / Global Default /
  Description / Created); no cluster → "No cluster selected."; fetch error
  → error line, never blank; the title text is EXACTLY `Priority Classes`
  (the e2e smoke asserts it with `exact: true`).
- Frontend detail: `/other-resource/priorityclass/data?name=<name>` fetches
  the `?name=` endpoint with NO `namespace` param and renders metadata +
  the object as syntax-highlighted YAML; empty `items` → "not found"
  state; missing `name` → error line, no fetch.
- The nav shows "Priority Classes" under the Other Resources group at the
  new path and NOT under Security; `/security/priorityclass` resolves to
  no route (neither stub nor real).
- `views/Stub/routes.ts` no longer contains the old path; the e2e smoke
  (`frontend/e2e/ui-smoke.spec.ts`) carries the new path with the same
  title and still passes.
- ADR-0022's parity row for this feature shows the new path/group and an
  implemented column.

**Artifacts** (files that must exist with real implementation):

- `backend/app/services/k8s_client.py` — `list_priority_classes`,
  `get_priority_class`, `self._scheduling` on `__init__`.
- `backend/app/api/resources.py` — one `_KINDS` row, one `_GETTERS` row.
- `backend/tests/services/test_k8s_client_priorityclasses.py` — service
  routing + 404-contract tests.
- `backend/tests/api/test_resources.py` — API-level tests (SAR, binding,
  200/404 contracts, kind-not-supported, namespace-ignored).
- `frontend/src/views/OtherResource/PriorityClass.tsx` — list view.
- `frontend/src/views/OtherResource/PriorityClassData.tsx` — detail view.
- `frontend/src/lib/types.ts` — `PriorityClassItem`.
- `frontend/tests/views/priority_classes.test.tsx`,
  `frontend/tests/views/priority_class_data.test.tsx` — view tests
  (view tests live in `frontend/tests/views/`, per `secrets.test.tsx`).
- `frontend/src/_nav.tsx` — leaf moved to the Other Resources group.
- `frontend/src/views/Stub/routes.ts` — old path replaced by the new one,
  then removed with the real routes.
- `frontend/e2e/ui-smoke.spec.ts` — smoke path moved.
- `.skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md` —
  parity row amended.

**Key links** (critical connections that must work together):

- The R4 handler calls `pool.get(cluster)` and dispatches by `_KINDS`
  method name — the new methods must be named EXACTLY
  `list_priority_classes` / `get_priority_class` (the table is the
  contract; a rename is a silent AttributeError at runtime, pinned by the
  API tests).
- The list view's query URL must match the kind string byte-for-byte
  (`priorityclasses`) with NO `namespace` param — pinned by the view test
  asserting the fetch path.
- The detail view's URL carries `name` only; the `namespace` param on a
  cluster-scoped kind is noise the view test must catch (the same
  discipline as `detail-clusterwide-omits-namespace` in the
  network-policy spec).
- The nav leaf, the real route, and the e2e smoke entry all point at
  `/other-resource/priorityclass` — three strings that must agree; the
  smoke suite is the cross-check (it fails if any diverges).

**One-way-door decisions:** None. (One additive table row on an
unpublished-elsewhere internal API; no migration, no schema change, no
published contract. The ADR-0022 row edit is a parity-document amendment,
not an architecture change.)

## Global Constraints

- Backend layering (per AGENTS.md): `app/api/` may not import from
  `app/services/` beyond the pool + `rbac`; `app/services/` stays
  Flask-free. The new `K8sClient` methods live in the service and take no
  Flask objects.
- Air gap (ADR-0020): no new frontend dependency. `react-syntax-highlighter`
  and `KubeDataTable` already exist. `task fe-check` must stay green.
- Conventional commits, atomic work units (per AGENTS.md § Committing &
  branching).
- Backend tests: unit tier via the file-local `FakeK8s` double +
  `_record_sar` (`backend/tests/api/test_resources.py` — that file
  deliberately shadows `tests/api/_helpers.py`); kind-gated tests stay
  under the `integration` marker and are not part of the unit loop.
- Frontend: `corepack pnpm test` (Vitest + RTL + MSW); no Tailwind —
  CoreUI classes only.
- Python style per the repo `black`/`ruff` config; TypeScript strict mode
  with explicit return types on exported functions.
- Dependency: the network-policy change (2026-10-26) must be in the tree
  first (it creates `lib/format.ts` and the `formatTimestamp` helper this
  change reuses). If it is not, Task 2 Step 3a creates `format.ts` with the
  same implementation the network-policy blueprint specifies, and the
  network-policy spec owns the helper's origin.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — +`self._scheduling` in
  `__init__` (after `self._v1`, line ~199); +two methods:
  `list_priority_classes` next to `list_nodes` (line ~227) and
  `get_priority_class` next to `get_secret` (line ~602).
- `backend/app/api/resources.py` (modify) — `_KINDS` +1 row (after the
  `crds` row, line ~54), `_GETTERS` +1 row (after `crds`, line ~59).
- `backend/tests/services/test_k8s_client_priorityclasses.py` (create) —
  `object.__new__` unit pattern (same as
  `test_k8s_client_namespaces.py`).
- `backend/tests/api/test_resources.py` (modify) — +tests appended; the
  file's local `FakeK8s` gains the two new methods.
- `frontend/src/views/OtherResource/PriorityClass.tsx` (create) — list
  view, cloned from `Security/Secret.tsx` structure (minus the namespace
  read).
- `frontend/src/views/OtherResource/PriorityClassData.tsx` (create) —
  detail view, cloned from `Security/SecretData.tsx` structure (minus the
  per-key data decode).
- `frontend/src/lib/types.ts` (modify) — +`PriorityClassItem` at the end of
  the cluster-resource block.
- `frontend/src/App.tsx` (modify) — +2 lazy imports +2 `<Route>` entries
  (next to the other `/other-resource/*` or `/security/*` routes).
- `frontend/src/_nav.tsx` (modify) — move the leaf (Security → Other
  Resources, new path).
- `frontend/src/views/Stub/routes.ts` (modify) — replace the
  `/security/priorityclass` entry's path; remove it in the view task.
- `frontend/e2e/ui-smoke.spec.ts` (modify) — move the smoke entry (line
  ~46) to the new path; same title.
- `.skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md`
  (modify) — amend the parity row (line ~88).
- `frontend/tests/views/priority_classes.test.tsx` (create).
- `frontend/tests/views/priority_class_data.test.tsx` (create).

---

### Task 1: `priorityclasses` kind — service methods + R4 row

**Files:**
- Modify: `backend/app/services/k8s_client.py` (`__init__` ~line 199;
  `list_priority_classes` next to `list_nodes` ~line 227;
  `get_priority_class` next to `get_secret` ~line 602)
- Modify: `backend/app/api/resources.py` (`_KINDS` ~line 54; `_GETTERS`
  ~line 58)
- Test: `backend/tests/services/test_k8s_client_priorityclasses.py` (create)
- Test: `backend/tests/api/test_resources.py` (modify — append)

**Interfaces:**
- Consumes: `K8sClient.__init__`'s `api_client` (the `kubernetes`
  `ApiClient` built from the decrypted kubeconfig — line ~160-199);
  `ApiException.status`; `self._unreachable(kind, e)` (the
  `get_secret`/`get_crd` call shape); the R4 handler's dispatch
  (`getattr(pool.get(cluster), method)(namespace)`).
- Produces:
  - `K8sClient.list_priority_classes(self, _namespace: str | None) -> list[dict[str, Any]]`
  - `K8sClient.get_priority_class(self, _namespace: str, name: str) -> list[dict[str, Any]]`
  - `_KINDS["priorityclasses"] == ("list_priority_classes", "priorityclasses", "scheduling.k8s.io")`
  - `_GETTERS["priorityclasses"] == "get_priority_class"`
- Seam: none new (the pool seam already exists; ADR-0010's cache will
  interpose at `pool.get` without touching these methods).
- Deletion test: deleting the `_KINDS` row makes
  `GET …/resources/priorityclasses` 404 — the endpoint disappears with the
  row; nothing else references the methods except the table.
- Adapters: 2 (the real `K8sClient` in the kind-gated test; `FakeK8s` in
  `test_resources.py`).

**SATISFIES:** `priorityclasses-list-200`,
`priorityclasses-list-ignores-namespace`, `priorityclasses-get-by-name`,
`priorityclasses-sar-denied`, `priorityclasses-binding-404`,
`priorityclasses-kind-singular-rejected` (scenarios in
`acceptance.feature`, written before Task 1 executes).

- [ ] **Step 1: Write the failing service tests**

```python
# backend/tests/services/test_k8s_client_priorityclasses.py
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(scheduling: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._scheduling = scheduling
    return client


def test_list_priority_classes_ignores_namespace() -> None:
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "high"}})
    scheduling = SimpleNamespace(
        list_priority_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
    )
    result = _client(scheduling).list_priority_classes("team-a")
    assert result == [{"metadata": {"name": "high"}}]
    assert seen == [True]  # called once, cluster list


def test_get_priority_class_404_returns_empty_list() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=404)

    scheduling = SimpleNamespace(read_priority_class=read)
    assert _client(scheduling).get_priority_class(None, "gone") == []


def test_get_priority_class_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_priority_class=read)).get_priority_class(None, "high")


def test_list_priority_classes_maps_500_to_unreachable() -> None:
    def list_all() -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_priority_class=list_all)).list_priority_classes(None)
```

- [ ] **Step 2: Run the service tests — expect FAIL** (`_scheduling`
  attribute missing / method missing).

Run: `cd backend && uv run pytest tests/services/test_k8s_client_priorityclasses.py -v`
Expected: FAIL (AttributeError).

- [ ] **Step 3: Implement the service methods**

In `__init__`, immediately after `self._v1 = …` (line ~199):

```python
        self._scheduling = k8s_client.SchedulingV1Api(api_client)
```

Next to `list_nodes` (line ~227):

```python
    def list_priority_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """PriorityClass list in the standard kubernetes dict form
        (``to_dict``). Cluster-scoped: the namespace argument is accepted
        and ignored (the ``list_nodes`` pattern)."""
        resp = self._scheduling.list_priority_class()
        return [pc.to_dict() for pc in resp.items]
```

Next to `get_secret` (line ~602):

```python
    def get_priority_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One PriorityClass as a 0/1-item list; ``[]`` on 404. Cluster-
        scoped: the namespace argument is accepted and ignored. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_secret``'s transport contract."""
        try:
            return [self._scheduling.read_priority_class(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_priority_class", e)
            raise AssertionError("unreachable") from e
```

- [ ] **Step 4: Write the failing API tests** (append to
  `backend/tests/api/test_resources.py`; extend that file's local `FakeK8s`
  class with the two new methods — the handler dispatches via
  `getattr(pool.get(cluster), method)`, so a missing method is a raw
  `AttributeError` → 500 the tests catch immediately):

```python
    def list_priority_classes(self, _namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {
                    "name": "high",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "annotations": None,
                    "labels": {"tier": "critical"},
                },
                "value": 1000,
                "global_default": False,
                "preemption_policy": "PreemptLowerPriority",
                "description": "High priority",
            }
        ]

    def get_priority_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "high":
            return self.list_priority_classes(None)
        return []
```

Use the file's OWN plumbing (its local `_register(api_client, h)` helper,
`auth_client.login()` + `h = {"Authorization": f"Bearer {auth_client.jwt}"}`,
and the file's local `_record_sar(monkeypatch)` — NOT `tests/api/_helpers.py`;
the file deliberately shadows that module). Tests to append:

- `test_list_priorityclasses_200` — `GET …/resources/priorityclasses` → 200,
  `body["kind"] == "priorityclasses"`, `body["items"][0]["metadata"]["name"]
  == "high"`.
- `test_list_priorityclasses_ignores_namespace` — same call with
  `?namespace=team-a` → 200 with the same item.
- `test_get_priority_class_by_name` — `?name=high` → 200, exactly one item
  named `high`; `?name=ghost` → 200 with `items == []`.
- `test_list_priorityclasses_sar_denied` — the file's local
  `_record_sar(monkeypatch)` (deny-all + record); → 403 `RBAC_DENIED`;
  `asked` contains `("list", "priorityclasses", None, None, "scheduling.k8s.io")`
  (tuple shape is `_record_sar`'s record contract `(verb, resource, ns,
  name, group)`, verified against `rbac.can`; namespace is `None` — the
  cluster-scoped SAR, ADR-0004 cache key).
- `test_priorityclass_kind_singular_rejected` —
  `GET …/resources/priorityclass` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.
- The binding-404 contract is already pinned by the file's existing
  binding-gate tests (same handler) — no new test required; if the file
  has no such test, add one mirroring its pattern.

- [ ] **Step 5: Add the R4 rows** (this makes the API tests pass).

In `_KINDS` (after the `"crds"` row):

```python
    "priorityclasses": ("list_priority_classes", "priorityclasses", "scheduling.k8s.io"),
```

In `_GETTERS`:

```python
    "priorityclasses": "get_priority_class",
```

- [ ] **Step 6: Run the API tests — expect PASS**, then the full unit
  suite.

Run: `cd backend && uv run pytest tests/api/test_resources.py tests/services/test_k8s_client_priorityclasses.py -v`
Run: `cd backend && uv run pytest -m "not integration"`
Expected: PASS, all green.

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/k8s_client.py backend/app/api/resources.py \
        backend/tests/services/test_k8s_client_priorityclasses.py \
        backend/tests/api/test_resources.py
git commit -m "feat(api): add priorityclasses kind to cluster resources (list + get)"
```

### Task 2: Frontend — list view + nav move + stub retirement

**Files:**
- Create: `frontend/src/views/OtherResource/PriorityClass.tsx`
- Modify: `frontend/src/lib/types.ts` (append the type)
- Modify: `frontend/src/_nav.tsx` (move the leaf)
- Modify: `frontend/src/App.tsx` (lazy import + `<Route>`)
- Modify: `frontend/src/views/Stub/routes.ts` (remove the old entry)
- Modify: `frontend/e2e/ui-smoke.spec.ts` (move the smoke entry)
- Modify: `.skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md`
  (amend the parity row)
- Test: `frontend/tests/views/priority_classes.test.tsx` (create)

**Interfaces:**
- Consumes: `apiFetch` from `frontend/src/lib/api` (MSW-mocked in tests);
  `useClusterStore` from `frontend/src/store/cluster`
  (`selectedCluster` — NOTE: `selectedNamespace` is NOT read; the kind is
  cluster-scoped); `KubeDataTable` + `Column` from
  `frontend/src/components/KubeDataTable`; `TopMenu`; `formatTimestamp`
  from `frontend/src/lib/format.ts` (owned by the network-policy change);
  the e2e smoke title "Priority Classes" (`ui-smoke.spec.ts:46`).
- Produces:
  - `PriorityClassItem` in `lib/types.ts` (used by Task 3).
  - The rendered list view at `/other-resource/priorityclass` (retires the
    stub at the old path, adds the real route at the new one).
- Seam: the view↔API seam is the fetch URL string; the test asserts the
  exact path `/api/v1/clusters/${id}/resources/priorityclasses` and asserts
  the URL contains NO `namespace` substring — a kind-string drift (e.g.
  `priority-class` singular) or a leaked namespace param fails in Vitest,
  not in a browser.
- Deletion test: the stub entry and the nav leaf move and the real route
  land in the SAME commit — the path never renders a 404 or a blank page
  mid-migration.
- Adapters: 2 (MSW mocks in the test; the live API in e2e).

**SATISFIES:** `list-renders-priority-classes`,
`list-no-cluster-state`, `list-error-state`,
`stub-route-retired-and-moved` (scenarios in `acceptance.feature`).

- [ ] **Step 1: Write the failing view test** —
  `frontend/tests/views/priority_classes.test.tsx`. Pattern: copy the
  render + MSW strategy from `frontend/tests/views/secrets.test.tsx`
  (the closest existing view). Pin:

  - fetch path is EXACTLY `/api/v1/clusters/${id}/resources/priorityclasses`
    and contains no `namespace` substring;
  - rows render name + value + preemption policy + global default +
    description + `formatTimestamp(creation_timestamp)`;
  - the name links to `/other-resource/priorityclass/data?name=high` with
    no `namespace` param;
  - the card/section title text is EXACTLY `Priority Classes` (the e2e
    smoke asserts that string with `exact: true` — a paraphrase breaks the
    smoke suite);
  - store with no cluster → "No cluster selected." and zero fetches;
  - fetch rejecting with a `RBAC_DENIED` body → error line, no crash.

  (Write the concrete assertions against `KubeDataTable`'s rendered cells,
  copying the selector strategy from `secrets.test.tsx`, before running.)

- [ ] **Step 2: Run — expect FAIL** (module not found).

Run: `cd frontend && corepack pnpm test tests/views/priority_classes.test.tsx`

- [ ] **Step 3a: Add the type** (`lib/types.ts`, append at the end of the
  cluster-resource block):

```ts
/** A PriorityClass item as returned by /api/v1/clusters/<id>/resources/priorityclasses (kubernetes to_dict, snake_case; cluster-scoped). */
export interface PriorityClassItem {
  metadata?: {
    name?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  value?: number
  global_default?: boolean
  preemption_policy?: string
  description?: string
  [key: string]: unknown
}
```

- [ ] **Step 3b: Implement the view**

Structure = `Secret.tsx` (same imports, same `useQuery` shape, same
error/loading/empty branches). Differences:

- One query: `queryKey: ['priorityclasses', cluster?.id]` (NO namespace
  segment — the kind is cluster-scoped; a namespace segment would re-cache
  the same data per namespace and is the exact drift the URL assertion
  guards), `enabled: cluster != null`, fetch
  `/api/v1/clusters/${cluster.id}/resources/priorityclasses`.
- Row mapping (`toRow`): name (link to
  `/other-resource/priorityclass/data?name=${encodeURIComponent(name)}`),
  `String(item.value ?? '—')`, `item.preemption_policy ?? '—'`,
  `item.global_default == null ? '—' : String(item.global_default)`,
  `item.description || '—'`,
  `formatTimestamp(item.metadata?.creation_timestamp)`.
- Breadcrumb: `Other Resources` → `Priority Classes` (same pattern as
  Secret; the first real breadcrumb under this group title).
- No namespace selector interaction, no `?selected=` param handling (4.1's
  Service-Accounts cross-linking is not in scope for 4.1-parity of THIS
  feature; pod→priorityclass links stay with the Pods page, which is still
  a stub).

- [ ] **Step 4: Move the nav leaf** in `_nav.tsx`: remove
  `leaf('Priority Classes', '/security/priorityclass')` from the Security
  group; add `leaf('Priority Classes', '/other-resource/priorityclass')`
  to the Other Resources group (position: last leaf of the group, after
  'Runtime Class').

- [ ] **Step 5: Wire the route + retire the stub + amend the docs**

`App.tsx`: lazy import next to the other view imports:

```tsx
const PriorityClassView = React.lazy(() => import('./views/OtherResource/PriorityClass'))
```

+ `<Route path="/other-resource/priorityclass">` (same `ProtectedRoute`
shape as the other real routes).

`views/Stub/routes.ts`: DELETE the
`{ path: '/security/priorityclass', title: 'Priority Classes', admin: false }`
entry (the old path now resolves to nothing).

`frontend/e2e/ui-smoke.spec.ts` (line ~46): change the entry to
`{ path: '/other-resource/priorityclass', title: 'Priority Classes' }` —
the path moves, the title is byte-identical.

`.skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md`
(line ~88): amend the row — path → `/other-resource/priorityclass`,
group → Interface / Other Resources, parity column → implemented
(feature), and append a short note: placement under Other Resources is a
ratified deviation (2026-10-27) — 4.1's API already lived in
`other-resources`; first real page in the group.

- [ ] **Step 6: Run the view tests — expect PASS; then the full frontend
  checks.**

Run: `cd frontend && corepack pnpm test`
Run: `task fe-build` (typecheck + lint + build)
Run: `task fe-check` (air-gap assertion)
Expected: PASS, no new `https?://` or `//cdn.` in the bundle.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/views/OtherResource/PriorityClass.tsx frontend/src/lib/types.ts \
        frontend/src/_nav.tsx frontend/src/App.tsx frontend/src/views/Stub/routes.ts \
        frontend/e2e/ui-smoke.spec.ts \
        .skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md \
        frontend/tests/views/priority_classes.test.tsx
git commit -m "feat(web): priority class list view (4.1 parity) moved to Other Resources"
```

### Task 3: Frontend — detail view (`/other-resource/priorityclass/data`)

**Files:**
- Create: `frontend/src/views/OtherResource/PriorityClassData.tsx`
- Modify: `frontend/src/App.tsx` (lazy import + `<Route>`)
- Test: `frontend/tests/views/priority_class_data.test.tsx` (create)

**Interfaces:**
- Consumes: `PriorityClassItem` from Task 2; `apiFetch`;
  `useClusterStore`; `react-syntax-highlighter` — there is NO shared
  highlighter component in this codebase: `SecretData.tsx` registers its
  languages at its own module scope; this view registers `yaml` at its own
  module scope (same pattern; the hljs language module is a singleton, so a
  second registration is harmless) and uses `language="yaml"` explicitly.
- Produces: the detail route at
  `/other-resource/priorityclass/data?name=<name>`.
- Seam: the URL is fixed-shape (`?name=` only — no `kind` enum needed;
  there is exactly one kind here, unlike the network-policy detail). The
  test asserts the EXACT fetch URL
  `/api/v1/clusters/${id}/resources/priorityclasses?name=<name>` and that
  it contains no `namespace` substring.
- Deletion test: the detail view is the sole consumer of the
  `/other-resource/priorityclass/data` route; deleting it makes the route
  blank (the list row links to it — the pair ships together).
- Adapters: 2 (MSW; e2e).

**SATISFIES:** `detail-renders-priority-class-yaml`,
`detail-not-found-state`, `detail-missing-name-client-error` (scenarios in
`acceptance.feature`).

- [ ] **Step 1: Write the failing view test** — MSW mock of the `?name=`
  endpoint; assertions:

  - valid `name` → fetch hits the EXACT URL (with `encodeURIComponent`);
    response item renders in the metadata block and as a YAML block
    containing the class name;
  - the fetched URL contains no `namespace` substring (cluster-scoped);
  - `items: []` → "not found" state (the copy, pinned in the test:
    `No PriorityClass '<name>' found`);
  - missing `name` param → NO fetch (assert the MSW handler was not
    called) + an error line;
  - no cluster selected → "No cluster selected." and no fetch.

- [ ] **Step 2: Run — expect FAIL.**

Run: `cd frontend && corepack pnpm test tests/views/priority_class_data.test.tsx`

- [ ] **Step 3: Implement the view**

Structure = `SecretData.tsx` (breadcrumb `Other Resources` →
`Priority Classes` → name; metadata table from `metadata.*` + the spec
fields; then the full object as YAML via `JSON.stringify(item, null, 2)`
fed to the highlighter with the `yaml` language — the object is a JS
object, so `yaml` language on JSON text matches what `SecretData.tsx`
already does; verify its exact usage and mirror it).

The `?name=` lookup goes through `apiFetch<ResourceList<PriorityClassItem>>`
on the single URL — no dispatch table (one kind, one URL).

- [ ] **Step 4: Wire the route** in `App.tsx` (lazy import next to
  Task 2's; `<Route path="/other-resource/priorityclass/data">` after it).

- [ ] **Step 5: Run the view tests — PASS; then `corepack pnpm test`,
  `task fe-build`, `task fe-check`.**

- [ ] **Step 6: Commit**

```bash
git add frontend/src/views/OtherResource/PriorityClassData.tsx frontend/src/App.tsx \
        frontend/tests/views/priority_class_data.test.tsx
git commit -m "feat(web): priority class detail view (single-read, yaml render)"
```

### Task 4: End-to-end verification (kind-gated)

**Files:**
- Modify: `backend/tests/api/test_resources.py` (append an
  `integration`-marked test, mirroring the existing kind-gated pattern in
  that file — e.g. the pods-on-kind test)

**Interfaces:**
- Consumes: the file's `kind_client` fixture pattern (a real kind
  cluster); the built SPA + backend dev stack for the manual smoke.
- Produces: the held-out evidence for the `backstop` truth.
- Seam: none.
- Deletion test: n/a (verification task).
- Adapters: 1 (kind) — this is a backstop, not a seam.

**SATISFIES:** `priorityclasses-list-on-kind` (integration scenario).

- [ ] **Step 1: Write the kind-gated test** (`@pytest.mark.integration`):

  A bare kind cluster ships the built-in PriorityClasses
  (`system-cluster-critical`, `system-node-critical`, `exempt`…) — no
  `kubectl apply` needed: `GET …/resources/priorityclasses` and assert
  200 with an item named `system-cluster-critical` and
  `preemption_policy == "Never"`. (If the running kind image's built-ins
  differ, `kubectl create priorityclass` an inline minimal object first
  and assert on that — the test's contract is "the real client's list
  comes back through the R4 route", not a specific built-in.)

- [ ] **Step 2: Run** (only when a kind cluster is available — CI's
  `e2e.yaml` has one): `cd backend && uv run pytest
  tests/api/test_resources.py -m integration -k priorityclasses -v`
  Expected: PASS. (Locally without kind: skip — the marker keeps it out
  of the unit loop.)

- [ ] **Step 3: Manual smoke** (dev stack, ADR-0027 plain-HTTP default):

```bash
task dev-stack
# open http://localhost:8080/other-resource/priorityclass
# expected: the built-in rows render; the Security group no longer lists
# Priority Classes; clicking a name opens the detail with the YAML block
# confirm http://localhost:8080/security/priorityclass no longer matches
# any route (blank/404 — the nav no longer offers it)
```

- [ ] **Step 4: Commit**

```bash
git add backend/tests/api/test_resources.py
git commit -m "test(api): kind-gated priorityclasses list verification"
```

---

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Routing (R4 kind string) | Applicable — one new kind string on a shared route | kind string is table-driven; the singular 4.1 name is explicitly rejected; view tests assert the exact fetch URL + no namespace param | `priorityclasses-kind-singular-rejected` (Task 1); view URL assertions (Tasks 2–3) |
| Shell commands | N/A — no subprocess, shell, or CLI change | — | — |
| Subprocesses | N/A — reads are HTTP via the kubernetes client | — | — |
| Version-control automation | N/A — no hook or git-tooling change | — | — |
| PR automation | N/A | — | — |
| Executable-file classification | N/A | — | — |
| Process integration | N/A — no leader/RQ/SSE surface touched (all reads are request-scoped) | — | — |
| Mnemonic tool contracts | N/A | — | — |
| `_shared/{planning,craft,verification,knowledge}/` | N/A — no skillgrid shared files modified | — | — |

## Verification ladder

Class `standard` → L2: after the final task, run
`cd backend && uv run pytest -m "not integration"`, `corepack pnpm test`,
`task fe-build`, `task fe-check`. The kind-gated test (Task 4) runs in
CI's e2e job.

## Self-Review (run 2026-10-27)

1. **Spec coverage:** R1 → Task 1; R2 → Task 2; R3 → Task 3; R4 → Task 2
   (nav move + stub + smoke + ADR row) + Task 4 (smoke verification). No
   gaps.
2. **Must-haves coverage:** every truth maps to a task's SATISFIES set;
   the backstop truth (kind list) is pinned by Task 4's held-out test.
3. **One-way doors:** none — verified (additive table row, no migration,
   no published contract; the ADR row is a parity-document amendment).
4. **Placeholder scan:** no TBD / "implement later" / "similar to Task N"
   — the kind-gated built-in fallback names its contract explicitly.
5. **Type consistency:** `list_priority_classes` / `get_priority_class` in
   `_KINDS`/`_GETTERS` (Task 1) match the `K8sClient` definitions; the
   frontend kind string `priorityclasses` matches the table; the three
   path strings (nav, route, smoke) are pinned equal by the e2e suite.

## Owed-Decision Gate (input coverage, 2026-10-27)

Every displayed/computed value has a named source:

| Value | Source |
|---|---|
| class name / created / labels / annotations | `metadata.*` of the `to_dict` item (K8s API) |
| value / preemption policy / global default / description | `value`, `preemption_policy`, `global_default`, `description` of the `to_dict` item (top-level in the PriorityClass schema — 4.1's own item shape confirms the placement) |
| Created rendering | `formatTimestamp` on `metadata.creation_timestamp` (named in R2 + decision note) |
| detail YAML block | the fetched item itself, `JSON.stringify` (named in R3) |
| "not found" / error copy | pinned in the view tests (Tasks 2–3) |

**No owed decisions.** (4.1's pod→priorityclass cross-linking is
explicitly out of scope — the Pods page is a stub; the value would have no
rendering surface this change ships.)

## Execution Handoff

- Slicing: 4 tasks → `skillgrid:slicing` produces `tasks.md` with waves
  (W1 = Task 1; W2 = Task 2; W3 = Task 3; W4 = Task 4). Sequential
  chain: Task 2 creates `views/OtherResource/` and the nav move; Task 3
  appends to the same App.tsx and reuses the type.
- `state.yaml`: set
  `changes.2026-10-27-priority-class.phase: blueprint` on handoff.
- **Two execution options:**
  1. **Subagent-Driven (recommended)** — fresh subagent per task, review
     between tasks.
  2. **Inline Execution** — `skillgrid:simple-execution`, batch with
     checkpoints.
