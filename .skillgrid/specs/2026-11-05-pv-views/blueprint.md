# Blueprint — PV Views (4.1 parity port)

**Change:** `2026-11-05-pv-views` · **Briefing:** `briefing.md` ·
**Navigation:** ADR-0040 session object navigation (the current contract —
this spec postdates the supersession; no NAVIGATION-SUPERSEDED file).

## File Structure

```
backend/app/services/k8s_client.py        # + list_persistent_volumes, + get_persistent_volume
backend/app/api/resources.py              # _KINDS["persistentvolumes"], _GETTERS["persistentvolumes"]
backend/tests/services/test_k8s_pvs.py    # NEW — service tests
backend/tests/api/test_resources.py       # + persistentvolumes API tests (SAR 403/200)
frontend/src/lib/types.ts                 # + PersistentVolumeItem
frontend/src/views/Storage/Pv.tsx         # NEW — list view
frontend/src/views/Storage/PvData.tsx     # NEW — data view
frontend/src/App.tsx                      # + ObjectRoute /storage/pv
frontend/src/views/Stub/routes.ts         # - { path: '/storage/pv', ... }
frontend/tests/views/pvs.test.tsx         # NEW — list view tests
frontend/tests/views/pv_data.test.tsx     # NEW — data view tests
frontend/tests/views/Stub.test.tsx        # viewPaths + '/storage/pv'
frontend/e2e/ui-smoke.spec.ts             # '/storage/pv' SMOKE_STUB_ROUTES -> REAL_ROUTES
frontend/src/views/Storage/StorageClassData.tsx    # annotations trim (companion fix)
frontend/src/views/Storage/SnapshotClassData.tsx   # annotations trim (companion fix)
frontend/src/views/Storage/VolumeSnapshotData.tsx  # annotations trim (companion fix)
frontend/src/views/Storage/PvcData.tsx             # annotations trim (companion fix)
frontend/src/views/Storage/ConfigMapData.tsx       # annotations trim (companion fix)
```

## Task 1 — backend kind (commit `feat(resources)`)

### `K8sClient.list_persistent_volumes(namespace: str | None) -> list[dict]`

`self._v1.list_persistent_volume()` (cluster list — the kind is
cluster-scoped); `to_dict()` per item; transport ApiException →
`self._unreachable("list_persistent_volumes", e)` (502 contract).
**Claim-namespace filter** (4.1 parity, bugs fixed — see briefing):
when `namespace is not None`, keep a PV iff
`(spec.claim_ref is None) or (spec.claim_ref.namespace == namespace)`.
Free PVs are always visible; bound PVs only for their claim's namespace.
`namespace is None` (no query param) → all PVs. The filter is pure-Python
on the `to_dict` output:
`spec → claim_ref → namespace`.

### `K8sClient.get_persistent_volume(_namespace: str, name: str) -> list[dict]`

`self._v1.read_persistent_volume(name)`; 0/1-item list; 404 → `[]`; other
ApiException → `ClusterUnreachableError` (the `get_storage_class`
contract). Namespace accepted and ignored (cluster-scoped).

### `resources.py`

```python
# _KINDS (core group, comment: 4.1-parity nav leaf, claim-ns filtered)
"persistentvolumes": ("list_persistent_volumes", "persistentvolumes", ""),
# _GETTERS
"persistentvolumes": "get_persistent_volume",
```

The generic route does the rest: binding gate, SAR `list`/`get` BEFORE the
client call (ADR-0004), `?name=` single-object path (namespace `or
"default"` — ignored by the getter).

### Tests (`test_k8s_pvs.py`, the `test_k8s_client_storageclasses.py` model)

1. `[pvs-claim-ns-filter]` bound-to-selected-ns kept; bound-to-other-ns
   dropped; free PV (claim_ref None) kept.
2. `[pvs-no-ns-all]` `namespace=None` → all items, unfiltered.
3. `[pvs-list-to-dict]` items pass through `to_dict` (no stripping).
4. `[pvs-list-502]` ApiException(500) → `ClusterUnreachableError`.
5. `[pvs-get-by-name]` hit → 1 item; 404 → `[]`; 500 →
   `ClusterUnreachableError`; namespace ignored (seen list).

`test_resources.py`: `persistentvolumes` in the kind table (SAR deny →
403 naming `persistentvolumes`; allow → 200 with items; `?name=` path →
403 `get` / 200 0-1 items). Mirror the storageclasses API tests.

## Task 2 — companion fix: annotations trim (commit `fix(fe)`)

4.1's `trimAnnotations` (lib/helper_functions.py:314) drops exactly two
machine-managed keys. The HPA view already replicates it (46929a10,
2026-11-04, same user decision). Apply the identical pattern to the five
storage data views — each currently has:

```ts
const annotations = Object.entries(item?.metadata?.annotations ?? {})
```

becomes (the HPA shape):

```ts
// 4.1's trimAnnotations (lib/helper_functions.py): the two machine-managed
// keys are dropped from the rendered annotations. Replicated 2026-11-05
// per user request (overrides the 2026-10-28 "render verbatim" recorded
// deviation).
const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'
const LEGACY_CONDITIONS = 'autoscaling.alpha.kubernetes.io/conditions'
const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
  ([key]) => key !== LAST_APPLIED && key !== LEGACY_CONDITIONS,
)
```

Files: StorageClassData, SnapshotClassData, VolumeSnapshotData, PvcData,
ConfigMapData. The raw JSON block (full object) is untouched. Each spec's
adr.md deviation bullet gets a 2026-11-05 override note (docs commit).

## Task 3 — list view (commit `feat(frontend)`)

`Pv.tsx` — the StorageClass.tsx structure (cluster-scoped card) with the
4.1 `pv.html.j2` columns and the Pvc.tsx namespace-source pattern:

- `KIND = 'persistentvolume'`, `LIST_ROUTE = '/storage/pv'`.
- Card title EXACTLY `Persistent Volume List` (the 4.1 header string; the
  e2e smoke asserts it with `exact: true`, like the sibling views).
- Query: `useQuery(['persistentvolumes', cluster?.id, namespace])` →
  `/api/v1/clusters/{id}/resources/persistentvolumes?namespace=...` where
  `namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  (the ResourceQuota/Pvc pattern — the header-selected namespace is the
  CLAIM filter per 4.1, not a scope: free PVs always appear).
- Columns (4.1 order): **Status** (badge: `Bound` → `text-bg-success`,
  `Terminating` → `text-bg-danger`, else `text-bg-warning`; Terminating =
  `metadata.deletion_timestamp` present, 4.1's override), **Name**
  (button → `openObject(KIND, name, undefined, LIST_ROUTE, navigate)` —
  cluster-scoped: no namespace in the ref), **StorageClass**
  (`openObject('storageclass', scName, undefined,
  '/storage/storage-class', navigate)` — cross-kind; `—` when absent),
  **VolumeClaim** (`openObject('persistentvolumeclaim', claimName,
  claimNs, '/storage/pvc', navigate)` — the claim ref carries the claim's
  own namespace, R8; `—` when free), **Capacity**
  (`spec.capacity.storage`, `—` when absent), **Usage** (5.0 addition,
  2026-11-05 user request — "PV usage data is missing"; 4.1's PV view had
  no usage): the PVC list's observed tier verbatim — a second parallel
  `useQuery(['pvc-usage', cluster?.id, namespace])` (shared key: the cache
  is shared with PvcView) on
  `/api/v1/clusters/{id}/metrics/pvcs?namespace=...`, joined by claim
  name (the claim-ns filter makes the join sound); free PVs + every
  ADR-0003 degrade (unavailable/denied/failed fetch) render `—`, and the
  usage query's error never fails the list.
- `toRow(item)` computes `status` with the Terminating override; row shape
  `{ name, status, storageClass, volumeClaim, volumeClaimNamespace,
  capacity }`.
- Empty state: `No persistent volumes found` (the sibling pattern).

`lib/types.ts`:

```ts
export interface PersistentVolumeItem {
  metadata?: {
    name?: string
    creation_timestamp?: string
    deletion_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    capacity?: { storage?: string }
    access_modes?: string[]
    persistent_volume_reclaim_policy?: string
    volume_mode?: string
    storage_class_name?: string
    claim_ref?: { name?: string; namespace?: string }
    csi?: { driver?: string; fs_type?: string; volume_attributes?: Record<string, string> }
    host_path?: { path?: string }
  }
  status?: { phase?: string; message?: string }
  [key: string]: unknown
}
```

### Tests (`pvs.test.tsx`, the `storage_classes.test.tsx` model)

MSW handler for the resources endpoint (assert the `?namespace=` param is
sent); KubeDataTable fake (same as the sibling tests); tests: title exact;
row mapping (bound PV → success badge text `Bound`, name button);
Terminating override (deletion_timestamp → `Terminating` + danger); free PV
(volumeClaim `—`, storageClass `—` when absent); cross-kind cells render
the linked names; empty state; no-cluster state.

## Task 4 — data view (commit `feat(frontend)`)

`PvData.tsx` — the StorageClassData.tsx structure (single `?name=` fetch
from ObjectRoute props; `not found` STATE on empty items; TopMenu
breadcrumb `Storage > PV > <name>`; syntax-highlighted JSON block —
`JSON.stringify` of the to_dict item, `json` grammar). Row set (4.1
`pv-data.html.j2` order):

| Row | Source | Notes |
|---|---|---|
| Status | `status.phase` or `Terminating` when `deletion_timestamp` | 4.1 override |
| Name | `metadata.name` | |
| Created | `formatTimestamp(creation_timestamp)` | |
| Deleted | `formatTimestamp(deletion_timestamp)` | conditional — only when deleting |
| Annotations | trimmed key/value table | 4.1 `trimAnnotations` (Task 2 pattern) |
| Labels | key/value table | |
| StorageClass | `spec.storage_class_name` | link → `openObject('storageclass', ...)` |
| Persistent Volume Claim | `spec.claim_ref.name` | link → `openObject('persistentvolumeclaim', name, claim_ref.namespace, '/storage/pvc')`; label corrected to `Persistent Volume Claim` (4.1's template typo `Clame` is NOT carried over) |
| PVC Namespace | `spec.claim_ref.namespace` | |
| Access Mode | `spec.access_modes` joined | |
| Volume Mode | `spec.volume_mode` | |
| Reclaim Policy | `spec.persistent_volume_reclaim_policy` | |
| Capacity | `spec.capacity.storage` | |
| Local Path | `spec.host_path.path` | conditional, only when hostPath (4.1 XOR) |
| CSI Driver / Filesystem Type | `spec.csi.driver` / `spec.csi.fs_type` | conditional, only when CSI (4.1 XOR) |
| Volume Attributes | `spec.csi.volume_attributes` dynamic key/value table | conditional, only when non-empty |

Absent optional values render `—` (the certainty rule), except the
conditional rows which are omitted entirely (4.1 `{% if %}`).

### Tests (`pv_data.test.tsx`, the `storage_class_data.test.tsx` model)

not-found state (empty items → `not found`, no error); row rendering from
a full hostPath PV (no CSI rows, Local Path row); CSI PV (CSI Driver +
Filesystem Type + Volume Attributes table, no Local Path row); Terminating
(Deleted row present); annotations table excludes
`kubectl.kubernetes.io/last-applied-configuration` (keeps others); claim
link renders the claim name.

## Task 5 — wiring + stub removal (commit `feat(frontend)`)

- `App.tsx`: `ObjectRoute` at `/storage/pv` (cluster-scoped — the
  StorageClass wiring shape; comment: first build of this kind, was a stub,
  no `/data` URL shipped → no R7 redirect).
- `views/Stub/routes.ts`: remove `{ path: '/storage/pv', title: 'Volumes',
  admin: false }`.
- `Stub.test.tsx`: viewPaths gains `/storage/pv` (comment: real view,
  2026-11-05-pv-views, Task 5).
- `ui-smoke.spec.ts`: `{ path: '/storage/pv', title: 'Volumes' }` moves
  from SMOKE_STUB_ROUTES into the REAL_ROUTES block (comment: 4.1-parity
  real view).

## Verification floor

- `uv run pytest -m "not integration"` (backend; new service + API tests
  RED→GREEN).
- Targeted vitest (`pvs`, `pv_data`, the five trimmed data views, `Stub`).
- `task fe-build` + `task fe-check` (air gap) + `task fe-sync`.
- `task e2e` (ui-smoke: `/storage/pv` as a REAL route — title
  `Persistent Volume List` exact; auth-smoke).
- Live dev cluster: list shows the local-path PVs (demo-pvc's PV under
  `kubedash-demo`), data view renders full rows; annotation tables no
  longer show the last-applied blob on any storage data page.

## Commits

1. `docs(specs): pv-views spec (4.1 parity port, claim-ns filtered, ADR-0040 nav)` — this folder.
2. `feat(resources): persistentvolumes kind (core, cluster-scoped, claim-ns filtered, SAR-gated)` — Task 1.
3. `fix(fe): storage data views trim machine-managed annotations (4.1 parity)` — Task 2.
4. `docs(specs): storage views — record the 2026-11-05 trimAnnotations override` — the five adr.md notes.
5. `feat(frontend): pv list view (4.1-parity, ADR-0040 nav)` — Task 3.
6. `feat(frontend): pv data view (4.1 rows + JSON block)` — Task 4.
7. `feat(frontend): wire pv routes, remove stub` — Task 5.

Tracker: one task (TASK-066), AC per task, status → Done at the floor.
