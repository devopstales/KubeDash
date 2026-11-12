# Network Policies — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution
> (recommended) or skillgrid:simple-execution to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2 (from `briefing.md`).

**Build shape:** Tracer thread — the vanilla `networkpolicies` kind (service
method → R4 table → list page) is a thin end-to-end path that proves the
shape; Cilium + the detail page thicken it. Integration risk lives in the
`CustomObjectsApi` 404-absence contract, so that door is checked early
(Task 2 Step 1's first test).

**Class:** standard (verification floor L2: full backend unit suite +
`corepack pnpm test` + `task fe-build` + `task fe-check`).

**Goal:** Replace the `/security/network-policy` stub with a Network
Policies list + detail (4.1 parity), backed by three new R4 kinds
(`networkpolicies`, `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies`).

**Architecture:** Pure additive on the R4 machinery: three `K8sClient`
methods + three `_KINDS` rows (+ two `_GETTERS` rows). The API layer
(`resources.py`) gains no handlers — binding gate, SAR gate, and
`ResourceListOut` come for free. Cilium reads reuse the existing
`_crd_served` served-version logic and degrade CRD-absent to `[]` (expected
state, like `_node_metrics`). Frontend: two views cloned from the
`Security/Secret` pair + a `lib/types.ts` block + stub-route removal.

**Tech Stack:** Flask 3 + Smorest (R4 table); `kubernetes` python client
(`NetworkingV1Api`, `CustomObjectsApi`); marshmallow (existing
`ResourceListOut` — no new schema); React 18 + CoreUI + TanStack Query +
`KubeDataTable` + `react-syntax-highlighter` (already used by
`SecretData.tsx`).

**Spec:** `briefing.md` (requirements R1–R5).

**In-force ADRs:** ADR-0004 (SAR is the only gate; cache key carries every
SAR attribute), ADR-0010 (reads through the pool seam; informer cache
interposes *later* — not built), ADR-0020 (air gap — no new dependency),
ADR-0022 (this change retires one `stub` parity row), ADR-0005 (CoreUI).

**Decision note (Cilium served version):** the CRD's own `spec.versions`
with `served: true` is the version authority — the same rule `_crd_served`
already enforces for the CRD list. Replaces 4.1's hardcoded `cilium.io/v2`.
No new ADR: it is a local reuse of an in-code rule, not a new architectural
decision.

**Decision note (Created column):** rendered as a full timestamp in the
BROWSER's local time (user decision, 2026-10-26: "current time — if CET
then CET", i.e. `toLocaleString`/`toLocaleDateString`, not a UTC/ISO
string). New artifact: `frontend/src/lib/format.ts` with
`formatTimestamp` (rationale: `SecretData.tsx:227` renders the raw ISO
string — the only precedent — but the user chose localized display; a
shared helper keeps both future views consistent).

**Critic:** T2 critic subagent ran (2026-10-26). Verdict: NEEDS FIXES →
applied: C1 (Cilium list path now routes through `_crd_body` — the
generated `CustomObjectsApi` returns a `(data, status, headers)` tuple and
only raises 401; without it a live 500 would `AttributeError`, not 502),
M1 (per-kind URL functions, no shared-arity `Record`), M2 (highlighter:
each view registers languages at module scope; `NetworkPolicyData`
registers `yaml` itself and hardcodes `language="yaml"` — `secretLanguage`
is NOT reused), M3 (decided: new `frontend/src/lib/format.ts`
`formatTimestamp` — browser-local time per user decision 2026-10-26, NOT
ISO), M4 (API-test sketch rewritten against the file's real plumbing:
local `_register`, `auth_client.jwt`, local `_record_sar`), N1 (Task 5
gains the kind-gated no-Cilium absence backstop), N2 (no-served-version
CRD → `ClusterUnreachableError`, mirroring `resources.py:147-148`), N4
(apidocs-baseline contingency removed), N5 (FakeK8s six-method list
explicit), N6 (e2e smoke title copy pinned: "Network Policies"), coverage
(all-namespaces API test added), `_client_with_custom` signature pinned.

## Hypothesis

**Claim:** Three `_KINDS` rows + three `K8sClient` methods make
`/security/network-policy` a real 4.1-parity feature with zero changes to
the R4 routing/SAR/binding machinery.

**Right condition:** `GET /api/v1/clusters/<id>/resources/networkpolicies`
returns `ResourceListOut` items on a kind-gated cluster; `?name=` returns a
0/1-item list; the Cilium kinds return full `spec`-intact items on a
Cilium cluster and `[]` (not 500) on a cluster without Cilium; the list
view renders rows for both sections.

**Wrong condition:** the R4 handler needs a special case for any of the
three kinds (proof the table is not the right seam), OR `CustomObjectsApi`
404s in a shape that cannot be distinguished from a transport failure
without a new error channel (the door check — if the absence contract
cannot be held, Cilium moves to a follow-up change with its own error
handling).

**Thinnest MVP:** Task 1 (vanilla kind, service + table + one API test).

**Door check:** Task 2 Step 1 — the first Cilium test, which pins the
`CustomObjectsApi` 404/404-group contract. If `get_crd_served` cannot
separate "CRD absent" from "cluster unreachable" with the fakes that
represent a live apiserver, stop and re-scope.

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
- **Cilium served version** (new, this change): the `cilium.io` CRD
  version flagged `served: true` in the CRD's own spec — resolved at read
  time, never hardcoded.
- **CRD-absent degrade** (new, this change): a 404 on the CRD or its
  resource list resolves to `[]` items (Cilium not installed = expected
  state), while any other failure raises `ClusterUnreachableError` → 502.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):

- `GET /api/v1/clusters/<id>/resources/networkpolicies?namespace=<ns>`
  returns `ResourceListOut` (`kind: "networkpolicies"`, `cluster: <name>`,
  `items` = the namespace's NetworkPolicies in kubernetes `to_dict` shape).
  *backstop* (needs a live/kind cluster — the unit tier pins routing and
  error mapping with the `FakeK8s` double; the kind-gated test in
  `test_resources.py` covers the real client).
- No `namespace` query → all-namespaces list (the client calls
  `list_network_policy_for_all_namespaces`).
- `?name=` on `networkpolicies` returns a 1-item list when the policy
  exists, `[]` on 404 upstream — the `get_secret` contract.
- SAR denied: a user without `list`/`get` on `networkpolicies` in group
  `networking.k8s.io` gets 403 `RBAC_DENIED` naming the resource; the
  cluster read is never attempted (asserted by the SAR record list).
- Binding gate: unbound user / unknown id → 404 `CLUSTER_NOT_FOUND`.
- `GET …/resources/ciliumnetworkpolicies?namespace=<ns>` returns full CRD
  items with `spec.endpoint_selector` / `spec.ingress` / `spec.egress`
  intact (NOT the condition projection of `list_crd_instances`).
- Cilium version autodetection: a CRD fixture served on `v2alpha1` (not
  `v2`) still resolves and lists — no hardcoded version anywhere in the
  new code.
- CRD absent (CRD read 404, or group unregistered 404) → `items: []`,
  HTTP 200, no 502. *backstop* (the live-shape of "group unregistered" is
  apiserver-dependent; unit fakes pin 404 → `[]` for both the CRD read and
  the instance list, and the kind-gated test pins a live no-Cilium
  cluster).
- Cilium failure other than 404 (e.g. 500) → 502 `CLUSTER_UNREACHABLE`.
- `GET …/resources/ciliumclusterwidenetworkpolicies` ignores `namespace`
  (cluster-scoped) and is list-only: `?name=` on it → 404
  `RESOURCE_KIND_NOT_SUPPORTED` (no `_GETTERS` row).
- `GET …/resources/ciliumnetworkpolicies?name=` → 1-item on hit, `[]` on
  404, and `[]` when the CRD itself is absent.
- Singular `network-policy` is NOT a kind: 404
  `RESOURCE_KIND_NOT_SUPPORTED` (guards against the 4.1 route-name leaking
  in as a kind).
- Frontend: `/security/network-policy` renders the selected namespace's
  NetworkPolicies (Name / Policy Types / Ingress rules / Egress rules /
  Age) and, when non-empty, a Cilium section; no cluster → "No cluster
  selected."; fetch error → error line, never blank.
- Frontend detail: `/security/network-policy/data?name=&kind=` fetches the
  matching kind's `?name=` endpoint and renders metadata + the object as
  syntax-highlighted YAML; empty `items` → "not found" state; `kind`
  outside the closed enum → client error before any fetch.
- `/security/network-policy` is absent from `views/Stub/routes.ts`; the
  e2e smoke path still passes (it only asserts the nav title renders).

**Artifacts** (files that must exist with real implementation):

- `backend/app/services/k8s_client.py` — `list_network_policies`,
  `get_network_policy`, `get_crd_served`, `list_cilium_network_policies`,
  `list_cilium_clusterwide_network_policies`, `get_cilium_network_policy`,
  `self._networking` on `__init__`.
- `backend/app/api/resources.py` — three `_KINDS` rows, two `_GETTERS`
  rows.
- `backend/tests/services/test_k8s_client_networkpolicies.py` — service
  routing + absence-degrade tests.
- `backend/tests/api/test_resources.py` — API-level tests (SAR, binding,
  200/404 contracts, kind-not-supported).
- `frontend/src/views/Security/NetworkPolicy.tsx` — list view.
- `frontend/src/views/Security/NetworkPolicyData.tsx` — detail view.
- `frontend/src/lib/types.ts` — `NetworkPolicyItem`, `CiliumPolicyItem`,
  `PolicyKind`.
- `frontend/src/lib/format.ts` — `formatTimestamp` (browser-local time;
  the Created column's named source, per Decision note).
- `frontend/tests/views/network_policies.test.tsx`,
  `frontend/tests/views/network_policy_data.test.tsx` — view tests
  (the view tests live in `frontend/tests/views/`, per the existing
  `secrets.test.tsx` et al. — NOT a `tests/Security/` folder).
- `frontend/tests/format.test.ts` — `formatTimestamp` unit test.

**Key links** (critical connections that must work together):

- The R4 handler calls `pool.get(cluster)` and dispatches by `_KINDS`
  method name — the new methods must be named EXACTLY `list_network_policies`,
  `list_cilium_network_policies`, `list_cilium_clusterwide_network_policies`
  (the table is the contract; a rename is a silent AttributeError at
  runtime, pinned by the API tests).
- The list view's query URLs must match the kind strings byte-for-byte
  (`networkpolicies`, `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies`)
  — pinned by the view tests asserting the fetch path.
- The detail view's `kind` enum must map 1:1 onto the two `_GETTERS` rows
  + the clusterwide list kind (a `kind` value with no endpoint is a client
  bug, caught by the closed-enum check).
- `get_cilium_network_policy` must call `get_crd_served` FIRST (no CRD →
  `[]` without touching `CustomObjectsApi.list/read` — one less 404 to
  interpret).

**One-way-door decisions:** None. (All three kinds are additive table rows
on an unpublished-elsewhere internal API; no migration, no schema change,
no published contract. The R4 table exists precisely to make kinds
additive — that is ADR-0004's enforcement design, not a door.)

## Global Constraints

- Backend layering (per AGENTS.md): `app/api/` may not import from
  `app/services/` beyond the pool + `rbac`; `app/services/` stays
  Flask-free. The new `K8sClient` methods live in the service and take no
  Flask objects.
- Air gap (ADR-0020): no new frontend dependency. `react-syntax-highlighter`
  is already a dependency (`SecretData.tsx`); `KubeDataTable` already
  exists. `task fe-check` must stay green.
- Conventional commits, atomic work units (per AGENTS.md
  § Committing & branching).
- Backend tests: unit tier via `FakeK8s` double + `sar()` helper
  (`backend/tests/api/_helpers.py`); kind-gated tests stay under the
  `integration` marker and are not part of the unit loop.
- Frontend: `corepack pnpm test` (Vitest + RTL + MSW); no Tailwind —
  CoreUI classes only.
- Python style per the repo `black`/`ruff` config; TypeScript strict mode
  with explicit return types on exported functions.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — +`self._networking` in
  `__init__` (after `self._rbac`, line ~195); +six methods near the
  existing CRD block (after `list_crd_instances`, line ~538) and
  `get_network_policy` next to `get_secret` (line ~587).
- `backend/app/api/resources.py` (modify) — `_KINDS` +3 rows (after the
  `crds` row, line ~54), `_GETTERS` +2 rows (after `crds`, line ~59).
- `backend/tests/services/test_k8s_client_networkpolicies.py` (create) —
  `object.__new__` unit pattern (same as
  `test_k8s_client_namespaces.py` / `test_k8s_client_crds.py`).
- `backend/tests/api/test_resources.py` (modify) — +tests appended;
  `FakeK8s` in this file grows the six new methods (the file's double is
  local to the file, per its docstring).
- `frontend/src/views/Security/NetworkPolicy.tsx` (create) — list view,
  cloned from `Secret.tsx` structure.
- `frontend/src/views/Security/NetworkPolicyData.tsx` (create) — detail
  view, cloned from `SecretData.tsx` structure (minus the per-key data
  decode).
- `frontend/src/lib/types.ts` (modify) — +3 types at the end of the
  cluster-resource block.
- `frontend/src/lib/format.ts` (create) — `formatTimestamp(ts: string |
  null | undefined): string` — browser-local rendering (Decision note).
- `frontend/src/lib/policyUrl.ts` (create) — the pure kind→URL map
  (Task 4's seam).
- `frontend/src/App.tsx` (modify) — +2 lazy imports (after line 42) +2
  `<Route>` entries (after the `/security/secret/data` route, line ~324).
- `frontend/src/views/Stub/routes.ts` (modify) — remove line 24
  (`/security/network-policy`).
- `frontend/tests/views/network_policies.test.tsx` (create).
- `frontend/tests/views/network_policy_data.test.tsx` (create).

---

### Task 1: `networkpolicies` kind — service method + R4 row + list

**Files:**
- Modify: `backend/app/services/k8s_client.py` (`__init__` ~line 195;
  `get_network_policy` after `get_secret` ~line 594)
- Modify: `backend/app/api/resources.py` (`_KINDS` ~line 54; `_GETTERS`
  ~line 58)
- Test: `backend/tests/services/test_k8s_client_networkpolicies.py` (create)
- Test: `backend/tests/api/test_resources.py` (modify — append)

**Interfaces:**
- Consumes: `K8sClient.__init__`'s `api_client` (the `kubernetes`
  `ApiClient` built from the decrypted kubeconfig — line ~160-195);
  `ApiException.status`; the R4 handler's dispatch
  (`getattr(pool.get(cluster), method)(namespace)`).
- Produces:
  - `K8sClient.list_network_policies(self, namespace: str | None) -> list[dict[str, Any]]`
  - `K8sClient.get_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]`
  - `_KINDS["networkpolicies"] == ("list_network_policies", "networkpolicies", "networking.k8s.io")`
  - `_GETTERS["networkpolicies"] == "get_network_policy"`
- Seam: none new (the pool seam already exists; ADR-0010's cache will
  interpose at `pool.get` without touching these methods).
- Deletion test: deleting the `_KINDS` row makes
  `GET …/resources/networkpolicies` 404 — the endpoint disappears with the
  row; nothing else references the method except the table.
- Adapters: 2 (the real `K8sClient` in kind-gated tests; `FakeK8s` in
  `test_resources.py`).

**SATISFIES:** `networkpolicies-list-namespaced`,
`networkpolicies-list-all-namespaces`, `networkpolicies-get-by-name`,
`networkpolicies-sar-denied`, `networkpolicies-binding-404`,
`networkpolicies-kind-singular-rejected` (scenarios in `acceptance.feature`,
written before Task 1 executes).

- [ ] **Step 1: Write the failing service tests**

```python
# backend/tests/services/test_k8s_client_networkpolicies.py
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import K8sClient


def _client(networking: object) -> K8sClient:
    client = object.__new__(K8sClient)
    client._networking = networking
    return client


def test_list_network_policies_namespaced_hits_namespaced_api() -> None:
    seen: list[object] = []
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "deny-all"}})
    networking = SimpleNamespace(
        list_namespaced_network_policy=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1],
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[]),
    )
    result = _client(networking).list_network_policies("team-a")
    assert result == [{"metadata": {"name": "deny-all"}}]
    assert seen == ["team-a"]


def test_list_network_policies_no_namespace_lists_all() -> None:
    item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "np"}})
    networking = SimpleNamespace(
        list_namespaced_network_policy=lambda ns: (_ for _ in ()).throw(AssertionError("must not be called")),
        list_network_policy_for_all_namespaces=lambda: SimpleNamespace(items=[item]),
    )
    result = _client(networking).list_network_policies(None)
    assert result == [{"metadata": {"name": "np"}}]


def test_get_network_policy_404_returns_empty_list() -> None:
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=404)

    networking = SimpleNamespace(read_namespaced_network_policy=read)
    assert _client(networking).get_network_policy("team-a", "gone") == []


def test_get_network_policy_other_api_error_maps_to_unreachable() -> None:
    def read(_name: str, _ns: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(read_namespaced_network_policy=read)).get_network_policy("team-a", "np")


def test_list_network_policies_maps_500_to_unreachable() -> None:
    def list_namespaced(_ns: str) -> None:
        raise ApiException(status=500)

    with pytest.raises(ClusterUnreachableError):
        _client(SimpleNamespace(list_namespaced_network_policy=list_namespaced)).list_network_policies("team-a")
```

- [ ] **Step 2: Run the service tests — expect FAIL** (`_networking`
  attribute missing / method missing).

Run: `cd backend && uv run pytest tests/services/test_k8s_client_networkpolicies.py -v`
Expected: FAIL (AttributeError / AttributeError on `_networking`).

- [ ] **Step 3: Implement the service methods**

In `__init__`, immediately after `self._rbac = …` (line ~195):

```python
        self._networking = k8s_client.NetworkingV1Api(api_client)
```

After `get_secret` (~line 594):

```python
    def list_network_policies(self, namespace: str | None) -> list[dict[str, Any]]:
        """NetworkPolicy list in the standard kubernetes dict form (``to_dict``).
        No field stripping — a policy's spec is what the view renders."""
        resp = (
            self._networking.list_namespaced_network_policy(namespace)
            if namespace
            else self._networking.list_network_policy_for_all_namespaces()
        )
        return [p.to_dict() for p in resp.items]

    def get_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One NetworkPolicy as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_secret``'s transport contract."""
        try:
            return [self._networking.read_namespaced_network_policy(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_network_policy", e)
            raise AssertionError("unreachable") from e
```

(Note: confirm the existing `_unreachable` helper signature before use —
`get_crd` at line ~475 shows the established `self._unreachable("get_crd", e)`
call shape; follow it exactly.)

- [ ] **Step 4: Write the failing API tests** (append to
  `backend/tests/api/test_resources.py`; extend that file's `FakeK8s`
  class with the two new methods):

```python
    def list_network_policies(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "deny-all", "namespace": namespace or "default"},
                "spec": {
                    "pod_selector": {},
                    "policy_types": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": [{"to": [{"ip_block": {"cidr": "0.0.0.0/0"}}]}],
                },
            }
        ]

    def get_network_policy(self, namespace: str, name: str) -> list[dict]:
        if name == "deny-all":
            return [{"metadata": {"name": name, "namespace": namespace}}]
        return []
```

Use the file's OWN plumbing (its local `_register(api_client, h)` helper,
`auth_client.login()` + `h = {"Authorization": f"Bearer {auth_client.jwt}"}`,
and the file's local `_record_sar(monkeypatch)` — lines ~491-504 — NOT
`tests/api/_helpers.py`; the file deliberately shadows that module):

```python
def test_list_networkpolicies_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "networkpolicies"
    assert body["items"][0]["metadata"]["name"] == "deny-all"


def test_list_networkpolicies_all_namespaces(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    # no namespace query -> the FakeK8s all-namespaces branch is used (200, items present)
    ...


def test_get_network_policy_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    # ?name= returns a 0/1-item list; a missing name yields items == []
    ...


def test_list_networkpolicies_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # the SAR was asked BEFORE the read, with the group (ADR-0004 cache key):
    assert ("list", "networkpolicies", "team-a", None, "networking.k8s.io") in asked
```

(The `...` bodies follow the same shape as the shown tests — the
all-namespaces variant asserts `FakeK8s.list_network_policies(None)`
returned its all-namespaces fixture, e.g. by giving that branch a
distinctly-named item. Write the bodies before running; no placeholder
ships.)

- [ ] **Step 5: Add the R4 rows** (this makes the API tests pass).

In `_KINDS` (after the `"crds"` row):

```python
    "networkpolicies": ("list_network_policies", "networkpolicies", "networking.k8s.io"),
```

In `_GETTERS`:

```python
    "networkpolicies": "get_network_policy",
```

- [ ] **Step 6: Run the API tests — expect PASS**, then the full unit
  suite.

Run: `cd backend && uv run pytest tests/api/test_resources.py tests/services/test_k8s_client_networkpolicies.py -v`
Run: `cd backend && uv run pytest -m "not integration"`
Expected: PASS, all green. (`test_apidocs.py` asserts Swagger asset
serving only — no per-path baseline — so new kinds cannot break it; if
it fails, the cause is unrelated to this change.)

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/k8s_client.py backend/app/api/resources.py \
        backend/tests/services/test_k8s_client_networkpolicies.py \
        backend/tests/api/test_resources.py
git commit -m "feat(api): add networkpolicies kind to cluster resources (list + get)"
```

### Task 2: Cilium kinds — served-version autodetect + absence degrade

> **Door check** (Hypothesis): Step 1's first test pins the
> `CustomObjectsApi` 404 contract. If the fake cannot model
> "CRD absent vs cluster unreachable" faithfully (i.e. the real
> apiserver returns something other than a 404-series `ApiException` for
> an unregistered group), STOP and report — the blueprint re-scopes
> Cilium before building on a wrong contract.

**Files:**
- Modify: `backend/app/services/k8s_client.py` (CRD block after
  `list_crd_instances`, ~line 538)
- Modify: `backend/app/api/resources.py` (`_KINDS` +2 rows; `_GETTERS`
  +1 row)
- Test: `backend/tests/services/test_k8s_client_networkpolicies.py` (modify — append)
- Test: `backend/tests/api/test_resources.py` (modify — append)

**Interfaces:**
- Consumes: `K8sClient._custom()` (the `CustomObjectsApi` accessor,
  line ~450); `K8sClient._crd_body(resp)` (static, line ~460 — the
  `(data, status, headers)` tuple mapper: only 401 is raised by the
  generated method, every other non-2xx arrives in the tuple and maps to
  `ClusterUnreachableError`; `list_crds` at line ~488 is the usage
  reference); `K8sClient._crd_served(crd)` (static, line ~477);
  `K8sClient.get_crd(_namespace, name)` (line ~492, 404 → `[]`,
  non-404 → raises via `_crd_body`/`_unreachable` — the wrapper in Step 3
  therefore needs NO extra `except`); `self._unreachable(kind, e)`
  (line ~623, raises and does not return).
- Produces:
  - `K8sClient.get_crd_served(self, group: str, plural: str) -> tuple[str, str] | None` —
    `(served_version, scope)` where scope is `"Namespaced"` | `"Cluster"`;
    `None` when the CRD is absent (404).
  - `K8sClient.list_cilium_network_policies(self, namespace: str | None) -> list[dict[str, Any]]`
  - `K8sClient.list_cilium_clusterwide_network_policies(self, _namespace: str | None) -> list[dict[str, Any]]`
  - `K8sClient.get_cilium_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]`
  - `_KINDS["ciliumnetworkpolicies"] == ("list_cilium_network_policies", "ciliumnetworkpolicies", "cilium.io")`
  - `_KINDS["ciliumclusterwidenetworkpolicies"] == ("list_cilium_clusterwide_network_policies", "ciliumclusterwidenetworkpolicies", "cilium.io")`
  - `_GETTERS["ciliumnetworkpolicies"] == "get_cilium_network_policy"`
  - (NO `_GETTERS` row for the clusterwide kind — list-only by design.)
- Seam: none new (same pool seam; the `CustomObjectsApi` fake in
  `test_k8s_client_crds.py`'s `_FakeApiClient` is the existing contract
  reference for how the generated custom-object methods are faked).
- Deletion test: deleting `get_crd_served` re-creates the version
  resolution inside each of the three Cilium methods — it exists to be
  called by exactly those three callers.
- Adapters: 2 (real `CustomObjectsApi` on the `_FakeApiClient` seam;
  `FakeK8s` method stubs in `test_resources.py`).

**SATISFIES:** `cilium-list-uses-served-version`,
`cilium-crds-absent-empty`, `cilium-crds-error-502`,
`cilium-clusterwide-ignores-namespace`, `cilium-get-by-name`,
`cilium-clusterwide-name-not-supported`, `cilium-sar-gated` (scenarios in
`acceptance.feature`).

- [ ] **Step 1: Write the failing service tests — absence contract FIRST**

Append to `test_k8s_client_networkpolicies.py`. The multi-call fake is the
door check's pinned contract — this helper does not exist yet; its
signature is:

```python
def _client_with_custom(
    crd: dict | None = None,          # the CRD dict get_crd returns (absent -> crd_read_404)
    crd_read_404: bool = False,       # get_cluster_custom_object raises ApiException(404)
    custom_list: object | None = None,  # value the custom list call returns (dict body OR (body, status, headers) tuple)
    custom_list_raises: Exception | None = None,  # e.g. ApiException(status=401) — the only status the generated method raises
    record_custom_calls: bool = False,
) -> K8sClient:
    """object.__new__(K8sClient) with _api_client bound to a per-path
    _FakeApiClient (pattern: backend/tests/services/test_k8s_client_crds.py:35-68).
    The fake dispatches on the recorded resource_path so the CRD read and
    the instance list are modeled DISTINCTLY in one client instance."""
```

(Implementation note for the executor: `_FakeApiClient._call_with_legacy_options`
already records `paths` (the `path_params` dict) — key the response by the
plural it contains (`customresourcedefinitions` → CRD read/list;
`ciliumnetworkpolicies` → instance list). The tuple shape
`(body, 500, {})` for non-raised errors is what the LIVE apiserver
produces per `_crd_body`'s docstring — model the 502 test with the tuple,
not a raised `ApiException(500)`, so the test pins the production shape.)

```python
def test_get_crd_served_resolves_served_version_and_scope() -> None:
    # CRD fixture served on v2alpha1 (NOT v2) — pins autodetection
    crd = {
        "spec": {
            "group": "cilium.io",
            "names": {"plural": "ciliumnetworkpolicies"},
            "scope": "Namespaced",
            "versions": [
                {"name": "v2alpha1", "served": True, "storage": True},
            ],
        },
    }
    client = _client_with_custom(crd_list=[crd], custom_list=SimpleNamespace(items=[]))
    assert client.get_crd_served("cilium.io", "ciliumnetworkpolicies") == ("v2alpha1", "Namespaced")


def test_get_crd_served_absent_returns_none() -> None:
    # CRD read 404 -> None (Cilium not installed), NOT an exception
    client = _client_with_custom(crd_read_404=True)
    assert client.get_crd_served("cilium.io", "ciliumnetworkpolicies") is None


def test_list_cilium_network_policies_absent_crds_empty() -> None:
    # get_crd_served is None -> [] WITHOUT calling the custom list (one less 404 to interpret)
    client = _client_with_custom(crd_read_404=True, record_custom_calls=True)
    assert client.list_cilium_network_policies("team-a") == []
    # assert the custom list/read path was never called


def test_list_cilium_network_policies_full_items() -> None:
    # items come back to_dict()-shaped with spec intact
    item = {"metadata": {"name": "cnp", "namespace": "team-a"},
            "spec": {"endpointSelector": {}, "ingress": [{"from": []}]}}
    client = _client_with_custom(crd_list=[_CNP_CRD], custom_list_body=item)
    rows = client.list_cilium_network_policies("team-a")
    assert rows[0]["spec"]["ingress"] == [{"from": []}]
    assert "status" not in rows[0] or "endpointSelector" in rows[0]["spec"]


def test_list_cilium_clusterwide_ignores_namespace() -> None:
    # the namespace argument is accepted but the cluster list is used
    ...


def test_get_cilium_network_policy_404_returns_empty() -> None:
    ...  # read_namespaced_custom_object 404 -> []

def test_cilium_custom_error_500_maps_to_unreachable() -> None:
    # the live shape: (body, 500, {}) tuple from the custom list -> ClusterUnreachableError
    client = _client_with_custom(crd=_CNP_CRD, custom_list=({"items": []}, 500, {}))
    with pytest.raises(ClusterUnreachableError):
        client.list_cilium_network_policies("team-a")
```

(Each `...` is the same assertion pattern as the shown tests — write the
body before running; no placeholder ships.)

- [ ] **Step 2: Run — expect FAIL** (methods missing). The `crd_read_404`
  case is the door check: confirm the fake models the 404 as
  `ApiException(status=404)`, which is what `get_crd` already interprets
  (line ~495) — the contract is pinned by EXISTING passing tests in
  `test_k8s_client_crds.py` before this task touches anything.

Run: `cd backend && uv run pytest tests/services/test_k8s_client_networkpolicies.py -v`

- [ ] **Step 3: Implement**

```python
    _CILIUM_GROUP = "cilium.io"

    def get_crd_served(self, group: str, plural: str) -> tuple[str, str] | None:
        """(served_version, scope) for a CRD, or None when the CRD is absent.

        The CRD's OWN spec is the version+scope authority (reuses
        ``_crd_served``). A 404 on the CRD read means the API group/CRD is
        not installed (e.g. Cilium absent) — the EXPECTED state, so it
        resolves to ``None`` instead of an error. Any other ApiException is
        a transport failure -> ``ClusterUnreachableError``.
        """
        crds = self.get_crd(None, plural)
        if not crds:
            return None
        served = self._crd_served(crds[0])
        if served is None:
            # A CRD that exists but declares no served version is
            # mis-registered Cilium, not "absent": mirror resources.py:147-148
            raise ClusterUnreachableError(f"CRD '{plural}' has no served version")
        return served
```

(`get_crd` contract, verified: 404 → `[]`; any non-404 already raises —
via `_crd_body` for tuple-statuses or `_unreachable` for raised
`ApiException` — so the wrapper needs no extra `except`.)

```python
    def list_cilium_network_policies(self, namespace: str | None) -> list[dict[str, Any]]:
        """CiliumNetworkPolicy items, full to_dict() shape (spec intact).
        CRD absent -> [] (expected state); other failures -> 502 via
        _unreachable (inherited from the custom calls)."""
        served = self.get_crd_served(self._CILIUM_GROUP, "ciliumnetworkpolicies")
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        resp = (
            custom.list_namespaced_custom_object(self._CILIUM_GROUP, version, namespace, "ciliumnetworkpolicies")
            if namespace and scope == "Namespaced"
            else custom.list_cluster_custom_object(self._CILIUM_GROUP, version, "ciliumnetworkpolicies")
        )
        body = self._crd_body(resp)  # (data, status, headers) tuple -> dict; non-2xx -> ClusterUnreachableError
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]
```

(Scope handling: `get_crd_served` returns the CRD's scope; a
CiliumNetworkPolicy CRD is namespaced in practice, but the guard keeps a
mis-registered cluster-scoped CRD from producing a 400 namespaced list.
`list_cilium_clusterwide_network_policies` is the same body with plural
`"ciliumclusterwidenetworkpolicies"` and NO namespace branch — always the
cluster list, `_namespace` accepted-and-ignored like `list_crds`.)
`get_cilium_network_policy` (the `read_namespaced_custom_object` path
returns the item directly — it raises `ApiException` on 404/401 rather
than returning a tuple, per the generated-method contract; keep the
`except` as written, and route a tuple-shaped return through `_crd_body`
defensively is NOT needed — the existing `get_crd` at line ~506 shows the
read path's exact handling: `_crd_body(item)` after the `try` — mirror
that line for `item`):

```python
    def get_cilium_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]:
        served = self.get_crd_served(self._CILIUM_GROUP, "ciliumnetworkpolicies")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.read_namespaced_custom_object(
                self._CILIUM_GROUP, version, namespace, "ciliumnetworkpolicies", name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_cilium_network_policy", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]
```

- [ ] **Step 4: Add the R4 rows**

```python
    "ciliumnetworkpolicies": ("list_cilium_network_policies", "ciliumnetworkpolicies", "cilium.io"),
    "ciliumclusterwidenetworkpolicies": ("list_cilium_clusterwide_network_policies", "ciliumclusterwidenetworkpolicies", "cilium.io"),
```

```python
    "ciliumnetworkpolicies": "get_cilium_network_policy",
```

- [ ] **Step 5: Write the failing API tests** (append; extend that
  file's `FakeK8s` class with ALL SIX new methods — the handler dispatches
  via `getattr(pool.get(cluster), method)`, so any missing method is a
  raw `AttributeError` → 500 the tests will catch immediately:
  `list_network_policies`, `get_network_policy` (Task 1),
  `list_cilium_network_policies`,
  `list_cilium_clusterwide_network_policies`,
  `get_cilium_network_policy`, and the clusterwide list. List methods
  return one fixed item each; get methods return `[]` for unknown names):

- `test_list_ciliumnetworkpolicies_200` — 200, `kind` echo, item has `spec`.
- `test_list_ciliumclusterwidenetworkpolicies_200_ignores_namespace` —
  called WITH `?namespace=team-a`, still 200; the `FakeK8s` method records
  the namespace argument and the test asserts it was ignored (or simply
  that the same items came back).
- `test_ciliumclusterwidenetworkpolicies_name_lookup_not_supported` —
  `?name=x` → 404 `RESOURCE_KIND_NOT_SUPPORTED` (no `_GETTERS` row — the
  handler's existing `kind not in _GETTERS` branch raises it).
- `test_cilium_sar_gated` — the file's local `_record_sar(monkeypatch)`
  (deny-all + record, lines ~491-504); 403 `RBAC_DENIED`; `asked`
  contains `("list", "ciliumnetworkpolicies", "team-a", None, "cilium.io")`
  — that tuple shape IS `_record_sar`'s record contract
  (`(verb, resource, ns, name, group)`, verified against `rbac.can`);
  assert the group and namespace are carried (ADR-0004 cache key).
- `test_cilium_absent_crds_empty_200` — `FakeK8s` Cilium methods return
  `[]`; 200 with `items == []`.

- [ ] **Step 6: Run the API tests — expect PASS; then the full unit
  suite** (same commands as Task 1 Step 6).

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/k8s_client.py backend/app/api/resources.py \
        backend/tests/services/test_k8s_client_networkpolicies.py \
        backend/tests/api/test_resources.py
git commit -m "feat(api): add cilium network policy kinds with served-version autodetect"
```

### Task 3: Frontend — list view (`/security/network-policy`)

**Files:**
- Create: `frontend/src/views/Security/NetworkPolicy.tsx`
- Create: `frontend/src/lib/format.ts` (`formatTimestamp`)
- Modify: `frontend/src/lib/types.ts` (append types)
- Modify: `frontend/src/views/Stub/routes.ts` (remove line 24)
- Modify: `frontend/src/App.tsx` (lazy import + `<Route>`)
- Test: `frontend/tests/views/network_policies.test.tsx` (create — view
  tests live in `frontend/tests/views/`, per `secrets.test.tsx` et al.)
- Test: `frontend/tests/format.test.ts` (create)

**Interfaces:**
- Consumes: `apiFetch` from `frontend/src/lib/api` (the MSW-mocked fetch);
  `useClusterStore` from `frontend/src/store/cluster`
  (`selectedCluster`, `selectedNamespace`); `KubeDataTable` + `Column`
  from `frontend/src/components/KubeDataTable`; `TopMenu`; the route
  `/security/network-policy` (already in `frontend/src/_nav.tsx` line 108
  — the nav entry needs no change); the backend contract
  `ResourceList<T>` from `lib/types.ts`.
- Produces:
  - `NetworkPolicyItem` / `CiliumPolicyItem` / `PolicyKind` in
    `lib/types.ts` (used by Task 4).
  - A rendered list view at the existing nav path (retires the stub).
- Seam: the view↔API seam is the fetch URL string; tests assert the exact
  path (`/api/v1/clusters/${id}/resources/${kind}?namespace=${ns}`) so a
  kind-string drift (e.g. `network-policy` singular) fails in Vitest, not
  in a browser.
- Deletion test: deleting the view file breaks the route (blank page) —
  the stub removal and the view land in the SAME commit so the path never
  404s.
- Adapters: 2 (MSW mocks in the test; the live API in e2e).

**SATISFIES:** `list-renders-namespace-policies`,
`list-cilium-section-shown-when-present`,
`list-cilium-section-hidden-when-empty`, `list-no-cluster-state`,
`list-error-state` (scenarios in `acceptance.feature`).

- [ ] **Step 1: Write the failing tests — format helper FIRST**

```ts
// frontend/tests/format.test.ts
import { formatTimestamp } from '../src/lib/format'

test('formatTimestamp renders browser-local time, not raw ISO', () => {
  // pinned with a fixed input; the assertion is locale-stable:
  const ts = '2026-10-26T10:00:00Z'
  const out = formatTimestamp(ts)
  expect(out).not.toContain('T')            // not the raw ISO string
  expect(out).toMatch(/2026/)               // the date is present
})

test('formatTimestamp handles null and invalid input', () => {
  expect(formatTimestamp(null)).toBe('—')
  expect(formatTimestamp('not-a-date')).toBe('—')
})
```

Then the view test:

```tsx
// frontend/tests/views/network_policies.test.tsx
// Pattern: copy the render + MSW strategy from
// frontend/tests/views/secrets.test.tsx (the closest existing view). Pin:
//  - fetch path for the vanilla kind (exact string, namespace encoded)
//  - rows render name + policy types + ingress/egress counts +
//    formatTimestamp(creation_timestamp)
//  - a second mock for the ciliumnetworkpolicies kind returning one item
//    -> the Cilium section appears
//  - both Cilium kinds returning [] -> section absent
//  - store with no cluster -> "No cluster selected." and zero fetches
//  - vanilla fetch rejecting -> error line, no crash
//  - the card title text is EXACTLY "Network Policies" (the e2e smoke at
//    frontend/e2e/ui-smoke.spec.ts:45 asserts that string with exact: true —
//    the real view must render it or the smoke breaks)
```

(Write the concrete assertions against `KubeDataTable`'s rendered cells,
copying the selector strategy from `secrets.test.tsx`, before running.)

- [ ] **Step 2: Run — expect FAIL** (modules not found).

Run: `cd frontend && corepack pnpm test tests/format.test.ts tests/views/network_policies.test.tsx`

- [ ] **Step 3a: Implement the format helper**

```ts
// frontend/src/lib/format.ts
/** Render a Kubernetes creationTimestamp in the BROWSER's local time
 * (Decision note: the user reads the dashboard in their timezone — if
 * that is CET, CET). Not ISO: a raw `T`-string is the 4.1 shape, not the
 * chosen one. `null`/unparseable -> "—" (certainty rule: no fake dates).
 */
export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString()
}
```

- [ ] **Step 3b: Add the types** (`lib/types.ts`, append after the
  `K8sSecret` block):

```ts
/** A NetworkPolicy item as returned by /api/v1/clusters/<id>/resources/networkpolicies (kubernetes to_dict, snake_case). */
export interface NetworkPolicyItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  spec?: {
    pod_selector?: { match_labels?: Record<string, string> | null } | null
    policy_types?: string[] | null
    ingress?: unknown[] | null
    egress?: unknown[] | null
  }
  [key: string]: unknown
}

/** A CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy item (full CRD to_dict). */
export interface CiliumPolicyItem {
  metadata?: {
    name?: string
    namespace?: string | null
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
  }
  spec?: {
    endpointSelector?: { matchLabels?: Record<string, string> | null } | null
    ingress?: unknown[] | null
    egress?: unknown[] | null
  }
  [key: string]: unknown
}

/** Closed set for the detail page's ?kind= param (4.1 parity). */
export const POLICY_KINDS = ['NetworkPolicy', 'CiliumNetworkPolicy', 'CiliumClusterwideNetworkPolicy'] as const
export type PolicyKind = (typeof POLICY_KINDS)[number]
```

- [ ] **Step 4: Implement the view**

Structure = `Secret.tsx` (same imports, same `useQuery` shape, same
error/loading/empty branches). Differences:

- Three queries (vanilla namespaced, Cilium namespaced, Cilium
  clusterwide), all `enabled: cluster != null`, queryKey
  `['network-policies', cluster?.id, namespace, <kind>]`.
- Row mapping (`toRow`): name (link to
  `/security/network-policy/data?name=…&kind=NetworkPolicy&namespace=…`),
  `spec.policy_types?.join(', ') ?? '—'` (vanilla only — Cilium rows show
  `—`: the CRD has no `policyTypes` field, per the Owed-Decision Gate
  resolution), `spec.ingress?.length ?? 0`, `spec.egress?.length ?? 0`,
  `formatTimestamp(metadata.creation_timestamp)` (the new helper, Step 3a).
- Cilium section: rendered only when
  `ciliumNamespaced.length > 0 || ciliumClusterwide.length > 0`. Its
  rows link with `kind=CiliumNetworkPolicy` /
  `kind=CiliumClusterwideNetworkPolicy` respectively.
- Breadcrumb: `Security` → `Network Policies` (same pattern as Secret).
  The card/section title text is EXACTLY `Network Policies` — the e2e
  smoke (`frontend/e2e/ui-smoke.spec.ts:45`) asserts that string with
  `exact: true`; a paraphrase breaks the smoke suite.

- [ ] **Step 5: Wire the route + remove the stub**

`App.tsx`: after line 42:

```tsx
const NetworkPolicyView = React.lazy(() => import('./views/Security/NetworkPolicy'))
```

after the `/security/secret/data` `</Route>` (~line 324):

```tsx
<Route
  path="/security/network-policy"
  element={
    <ProtectedRoute>
      <NetworkPolicyView />
    </ProtectedRoute>
  }
/>
```

`views/Stub/routes.ts`: delete the `/security/network-policy` entry
(line 24).

- [ ] **Step 6: Run the view tests — expect PASS; then the full frontend
  checks.**

Run: `cd frontend && corepack pnpm test`
Run: `task fe-build` (typecheck + lint + build)
Run: `task fe-check` (air-gap assertion)
Expected: PASS, no new `https?://` or `//cdn.` in the bundle.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/views/Security/NetworkPolicy.tsx frontend/src/lib/types.ts \
        frontend/src/lib/format.ts frontend/src/views/Stub/routes.ts frontend/src/App.tsx \
        frontend/tests/format.test.ts frontend/tests/views/network_policies.test.tsx
git commit -m "feat(web): network policy list view (4.1 parity, vanilla + cilium sections)"
```

### Task 4: Frontend — detail view (`/security/network-policy/data`)

**Files:**
- Create: `frontend/src/views/Security/NetworkPolicyData.tsx`
- Create: `frontend/src/lib/policyUrl.ts` (the pure `policyUrl` function)
- Modify: `frontend/src/App.tsx` (lazy import + `<Route>`)
- Test: `frontend/tests/views/network_policy_data.test.tsx` (create —
  `frontend/tests/views/`, per the suite layout)
- Test: `frontend/tests/policyUrl.test.ts` (create — URL contract)

**Interfaces:**
- Consumes: `NetworkPolicyItem` / `CiliumPolicyItem` / `PolicyKind` from
  Task 3; `apiFetch`; `useClusterStore`; `react-syntax-highlighter` —
  NOTE: there is NO shared highlighter component in this codebase
  (critic finding M2, verified): `SecretData.tsx` registers its
  languages at its own module scope (lines 29-32) and exports only
  `secretLanguage` (a key/value guesser — NOT what this view needs).
  `NetworkPolicyData.tsx` registers the `yaml` language at its own module
  scope (same pattern; the hljs language module is a singleton, so a
  second registration is harmless) and uses `language="yaml"` explicitly.
- Produces: the detail route at
  `/security/network-policy/data?name=&kind=&namespace=`.
- Seam: the `kind` → URL mapping (a table in the view):

  | `kind` | fetch URL |
  |---|---|
  | `NetworkPolicy` | `/api/v1/clusters/${id}/resources/networkpolicies?name=${name}&namespace=${ns}` |
  | `CiliumNetworkPolicy` | `/api/v1/clusters/${id}/resources/ciliumnetworkpolicies?name=${name}&namespace=${ns}` |
  | `CiliumClusterwideNetworkPolicy` | `/api/v1/clusters/${id}/resources/ciliumclusterwidenetworkpolicies?name=${name}` |

  (clusterwide: no `namespace` param — the kind is cluster-scoped; the
  backend ignores it either way, but sending it is noise the test should
  catch.)

  NOTE (critic M1): do NOT type this as
  `Record<PolicyKind, (id, name, ns) => string>` — a shared-arity Record
  compiles with the two-param clusterwide function but forces every
  caller to pass an `ns` the kind must not use, hiding the exact mistake
  the `detail-clusterwide-omits-namespace` scenario exists to catch. The
  type below makes the arity per-kind.
- Deletion test: the detail view is the sole consumer of the `?kind=`
  contract on the frontend; deleting it orphans the `PolicyKind` type
  (keep the type — Task 3's list view builds the links).
- Adapters: 2 (MSW; e2e).

**SATISFIES:** `detail-renders-policy-yaml`,
`detail-not-found-state`, `detail-bad-kind-client-error`,
`detail-clusterwide-omits-namespace` (scenarios in `acceptance.feature`).

- [ ] **Step 0: Extract `policyUrl` into `frontend/src/lib/policyUrl.ts`
  (pure, no React) + write `frontend/tests/policyUrl.test.ts` covering all
  four table rows (the three valid kinds' exact URLs + `null` for an
  invalid kind) — TDD: test first, then the module.** This makes the
  URL contract unit-testable without a render, per the Interfaces seam.

- [ ] **Step 1: Write the failing view test** — MSW mocks per the seam
  table; assertions:

- valid `kind`+`name` → fetch hits the EXACT table URL; response item
  renders in a `<pre>` / SyntaxHighlighter block containing the policy
  name.
- `items: []` → "not found" text (the chosen copy, pinned in the test:
  `No <kind> '<name>' found`).
- `kind=Foo` (outside `POLICY_KINDS`) → NO fetch at all (assert the MSW
  handler was not called) + an error line naming the invalid kind.
- `kind=CiliumClusterwideNetworkPolicy` → URL has no `namespace=` param.
- missing `name` param → error line, no fetch.

- [ ] **Step 2: Run — expect FAIL.**

Run: `cd frontend && corepack pnpm test tests/views/network_policy_data.test.tsx`

- [ ] **Step 3: Implement the view**

Structure = `SecretData.tsx` (breadcrumb `Security` →
`Network Policies` → name; metadata table from `metadata.*`; then the
full object as YAML via `JSON.stringify(item, null, 2)` fed to the
highlighter with the `yaml` language — the object is a JS object, so
`yaml` language on JSON text matches what `SecretData.tsx` already does
for its decoded blocks; verify its exact usage and mirror it).

`kind` validation is the pure `policyUrl` module from Step 0
(`frontend/src/lib/policyUrl.ts`) — per-kind arities, so the type system
makes the clusterwide namespace-omission visible (M1 fix):

```ts
type NamespacedPolicyKind = 'NetworkPolicy' | 'CiliumNetworkPolicy'

function namespacedUrl(id: number, name: string, ns: string, kind: NamespacedPolicyKind): string {
  const resource = kind === 'NetworkPolicy' ? 'networkpolicies' : 'ciliumnetworkpolicies'
  return `/api/v1/clusters/${id}/resources/${resource}?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(ns)}`
}

/** Returns the fetch URL for a valid kind, or null when `kind` is outside
 * POLICY_KINDS (the caller renders the error line and makes NO fetch). */
function policyUrl(kind: string, id: number, name: string, ns: string): string | null {
  if (!POLICY_KINDS.includes(kind as PolicyKind)) return null
  if (kind === 'CiliumClusterwideNetworkPolicy') {
    // cluster-scoped: the namespace param is intentionally absent
    return `/api/v1/clusters/${id}/resources/ciliumclusterwidenetworkpolicies?name=${encodeURIComponent(name)}`
  }
  return namespacedUrl(id, name, ns, kind as NamespacedPolicyKind)
}
```

(The YAML block: `JSON.stringify(item, null, 2)` into
`SyntaxHighlighter` with `language="yaml"` — registered at this module's
own scope, per the Interfaces note. `secretLanguage` from `SecretData.tsx`
is NOT reused: it guesses per key/value pair, which is the wrong
classifier for a whole-object block.)

- [ ] **Step 4: Wire the route** in `App.tsx` (lazy import next to
  Task 3's; `<Route path="/security/network-policy/data">` after it).

- [ ] **Step 5: Run the view tests — PASS; then `corepack pnpm test`,
  `task fe-build`, `task fe-check`.**

- [ ] **Step 6: Commit**

```bash
git add frontend/src/views/Security/NetworkPolicyData.tsx frontend/src/lib/policyUrl.ts \
        frontend/src/App.tsx frontend/tests/policyUrl.test.ts \
        frontend/tests/views/network_policy_data.test.tsx
git commit -m "feat(web): network policy detail view (single-read, kind-dispatched)"
```

### Task 5: End-to-end verification (kind-gated)

**Files:**
- Modify: `backend/tests/api/test_resources.py` (append an
  `integration`-marked test, mirroring `test_list_pods_on_kind` at line
  ~631)
- (No frontend change — the e2e smoke spec already covers the path.)

**Interfaces:**
- Consumes: the `kind_client` fixture (the pattern at line ~631 of
  `test_resources.py` — a real kind cluster); the built SPA + backend
  dev stack for the manual smoke.
- Produces: the held-out evidence for the `backstop` truths.
- Seam: none.
- Deletion test: n/a (verification task).
- Adapters: 1 (kind) — this is a backstop, not a seam.

**SATISFIES:** `networkpolicies-list-on-kind`,
`cilium-absent-on-live-cluster-empty` (integration scenarios).

- [ ] **Step 1: Write the kind-gated tests** (two, both
  `@pytest.mark.integration`):

  1. **List on kind** — `kubectl apply` a minimal deny-all NetworkPolicy
     (inline YAML, cleanup in `finally`), then
     `GET …/resources/networkpolicies?namespace=default` and assert the
     item's `spec.policy_types == ["Ingress", "Egress"]`.
  2. **Live no-Cilium absence** (critic N1 — the backstop the unit fakes
     cannot cover: the REAL apiserver's "group unregistered" response
     shape is exactly the door-check assumption) — a bare kind cluster has
     no `cilium.io` CRDs; assert
     `GET …/resources/ciliumnetworkpolicies?namespace=default` → 200 with
     `items == []`, and same for `ciliumclusterwidenetworkpolicies`. If
     this 502s on a live cluster, the `_crd_body`/404 contract is wrong
     in production — that is the failure the door check exists to catch,
     and it is now caught in CI, not on a customer's cluster.

- [ ] **Step 2: Run** (only when a kind cluster is available — CI's
  `e2e.yaml` has one): `cd backend && uv run pytest
  tests/api/test_resources.py -m integration -k "networkpolicies or cilium" -v`
  Expected: PASS. (Locally without kind: skip — the marker keeps it out
  of the unit loop.)

- [ ] **Step 3: Manual smoke** (dev stack, ADR-0027 plain-HTTP default):

```bash
task dev-stack
# in the cluster: kubectl create networkpolicy deny-all -n default --from='namespaceSelector{}'
# open http://localhost:8080/security/network-policy
# expected: the row renders; clicking it opens the detail with YAML
```

- [ ] **Step 4: Commit**

```bash
git add backend/tests/api/test_resources.py
git commit -m "test(api): kind-gated networkpolicies list verification"
```

---

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Routing (R4 kind strings) | Applicable — three new kind strings on a shared route | kind strings are table-driven; the singular 4.1 name is explicitly rejected; view tests assert the exact fetch URL | `networkpolicies-kind-singular-rejected` (Task 1); view test URL assertions (Tasks 3–4) |
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
`task fe-build`, `task fe-check`. The kind-gated test (Task 5) runs in
CI's e2e job.

## Self-Review (run 2026-10-26)

1. **Spec coverage:** R1 → Task 1; R2 → Task 2; R3 → Task 3; R4 → Task 4;
   R5 → Task 3 (stub removal) + Task 5 (e2e). No gaps.
2. **Must-haves coverage:** every truth maps to a task's SATISFIES set;
   backstop truths (kind list, live CRD-absent) are pinned by Task 5's
   held-out test + the unit absence tests.
3. **One-way doors:** none — verified (additive table rows, no
   migration, no published contract).
4. **Placeholder scan:** the `...` bodies in Task 2 Step 1 and Task 3
   Step 1 are explicitly marked "write the body before running; no
   placeholder ships" — they name the assertion pattern, not a deferral.
   No TBD / "implement later" / "similar to Task N" remains.
5. **Type consistency:** method names in `_KINDS`/`_GETTERS` (Task 1–2)
   match the `K8sClient` definitions; the frontend kind strings match the
   table; `PolicyKind` (Task 3) is consumed by the detail view's
   `KIND_URL` (Task 4).

## Owed-Decision Gate (input coverage, 2026-10-26)

Every displayed/computed value has a named source:

| Value | Source |
|---|---|
| policy name / namespace / created / labels / annotations | `metadata.*` of the `to_dict` item (K8s API) |
| policy types | `spec.policy_types` (vanilla) — rendered as-is; Cilium rows show `—` (4.1 derived it from rule presence; NOT carried: the CRD has no `policyTypes` field, and inventing one is a value without a source) |
| ingress / egress rule counts | `spec.ingress?.length` / `spec.egress?.length` |
| Cilium section visibility | non-emptiness of the two Cilium lists (named in R3) |
| detail YAML block | the fetched item itself, `JSON.stringify` (named in R4) |
| Cilium served version | the CRD's `spec.versions[].served` (named in R2 + decision note) |
| "not found" / error copy | pinned in the view tests (Task 3–4) |

**No owed decisions.** (The Cilium policy-types rendering was the one
candidate; resolved above against the 4.1-reference — 4.1's derivation
only applied to its own synthesized shape; the vanilla column is the
source of truth and Cilium shows `—`.)

## Execution Handoff

- Slicing: 5 tasks → `skillgrid:slicing` produces `tasks.md` with waves
  (Wave 1: Task 1 ∥ Task 3-types is sequential-by-file, so: W1 = Task 1;
  W2 = Task 2 ∥ Task 3; W3 = Task 4; W4 = Task 5).
- `state.yaml`: set
  `changes.2026-10-26-network-policy.phase: blueprint` on handoff.
- **Two execution options:**
  1. **Subagent-Driven (recommended)** — fresh subagent per task, review
     between tasks.
  2. **Inline Execution** — `skillgrid:simple-execution`, batch with
     checkpoints.
