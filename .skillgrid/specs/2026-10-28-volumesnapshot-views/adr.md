# VolumeSnapshot Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `volumesnapshots`, group `snapshot.storage.k8s.io`, namespace = the query namespace or `None` (all-namespaces branch); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the Cilium full-custom-object precedent — `get_crd_served` + `list_cluster_custom_object`/`list_namespaced_custom_object`), same as the VPA and SnapshotClass kinds (the CRD-seam pattern). |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CustomObjectsApi` (the Cilium and `get_crd`/`list_crds` methods already use it; no new attribute needed — `self._custom` already exists); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own template lived in `storage/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (the Cilium full-custom-object seam — the same CRD seam VPA and
SnapshotClass use; this is the **namespaced** member of the family, so the
client methods use `list_namespaced_custom_object` / `get_crd_served`'s scope
authority; the `?namespace=` param is honored, not ignored).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation; the data page is NEW.** 4.1 has ONLY
  a list route (`/volumesnapshot`) — the name link in the list template is
  **commented out** (a dead link), and there is no `/volumesnapshot/data`
  route or data template. 5.0 resolves the dead link with a real data page
  reached by `?name=&namespace=` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision — no hidden forms / POST / `session['ns_select']`).
- **The list honors the header-selected namespace.** 4.1's
  `k8sPersistentVolumeSnapshotListGet` hardcodes
  `list_cluster_custom_object(...)` — an **all-namespaces** read that ignored
  `session['ns_select']` entirely, so the list showed snapshots from every
  namespace regardless of the header selection. 5.0's list view uses
  `useClusterStore.selectedNamespace` (the NetworkPolicies pattern); the
  backend's `namespace=None` branch (all-namespaces) remains for API
  completeness but the page always passes a namespace.
- **CRD version via `get_crd_served`, not 4.1's hardcoded `"v1"`.** 4.1
  hardcodes `"v1"` as the version; if the snapshot CRD is ever served at a
  different version, 4.1 breaks. 5.0 resolves the CRD's OWN served version
  (the `get_crd_served` pattern) — the same authority the Cilium/VPA/
  SnapshotClass kinds use.
- **Deep-index 500 is fixed.** 4.1's `pvs["spec"]["source"]
  ["persistentVolumeClaimName"]` and `pvs["spec"]["volumeSnapshotClassName"]`
  raise `KeyError` (→ 500) on a snapshot whose `spec.source` has no
  `persistentVolumeClaimName` (e.g. a `sourceMode: Volume`-style snapshot or a
  fresh unbound one). 5.0's view renders `—` for absent keys (certainty rule:
  never guess, never crash a row) — the backend does no projection (the full
  object goes to the view, and the view uses optional-chaining reads).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data page
  (new) renders `JSON.stringify` of the item — JSON is a YAML subset, and the
  `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **CRD-absent degrades to `[]`.** 4.1's `k8sPersistentVolumeSnapshotListGet`
  swallows the `ApiException` and returns `[]` (the snapshot operator is
  optional); 5.0 keeps the first-class empty state via the Cilium
  `get_crd_served` contract: CRD 404 → `served is None` → `[]`; any other
  read failure → `ClusterUnreachableError` (502) — the same contract VPA and
  SnapshotClass use.
- **The SnapshotClass / VolumeClaim cells are plain text, not 4.1's
  hidden-form links.** 4.1's list linked those cells to `/storage/snapshot-
  class` and `/storage/pvc` via hidden forms; 5.0 has no PVC page
  destination yet (and the SnapshotClass page lands separately in this
  batch), so both cells render as plain text — the full `spec`/`status` is in
  the JSON block.
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).
  **OVERRIDE 2026-11-05 (user decision):** the trim is now replicated — the
  two machine-managed keys are dropped from the annotations table (the
  2026-11-04 HPA override shape, 46929a10; 2026-11-05-pv-views companion
  fix).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
