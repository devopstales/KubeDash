# PV Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `persistentvolumes`, core group (`""`); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as nodes/priorityclasses/runtimeclasses/storageclasses for a cluster-scoped core kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api.list_persistent_volume`/`read_persistent_volume` (the 4.1 code used them; `self._v1` already exists in the 5.0 client); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by the sibling data views). |
| ADR-0022 (placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping). The nav leaf already exists at `/storage/pv` (`_nav.tsx`, leaf "Volumes"), and 4.1's own template lived in `storage/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |
| ADR-0040 (session object navigation) | One route per kind (`/storage/pv`), no `/data` suffix (the kind was a stub — the URL never shipped, so no R7 redirect). The list's Name/StorageClass/VolumeClaim cells are ADR-0040 object refs (`openObject`): cluster-scoped refs carry no namespace; the cross-kind VolumeClaim ref carries the claim's own namespace (R8). No object identity in the URL. The backend `?name=`/`?namespace=` params are REST query filtering, not navigation (the supersession keeps them). |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path, navigation) and follows an established,
ratified in-repo pattern (StorageClass = the same cluster-scoped core-kind
family, same `_KINDS` + `_GETTERS` wiring, same list+data view pair).

The companion annotations-trim commit is a USER-DECISION override of the
2026-10-28 recorded deviation "trimAnnotations is not replicated"
(identical to the 2026-11-04 HPA override, commit 46929a10). It is recorded
in the affected specs' adr.md files, not a new ADR.

## Recorded deviations from 4.1

- **hostPath PVs are visible in the list (4.1 bug fixed).** 4.1's
  `k8sPersistentVolumeListGet` hits `continue` (instead of appending) when
  `pv.spec.host_path` is set — hostPath PVs never reach the list. On the
  kind dev cluster (local-path provisioner = hostPath PVs) the 4.1 list
  would be empty. 5.0 appends every PV.
- **Unbound PVs do not crash the list (4.1 bug fixed).** 4.1 reads
  `pv.spec.claim_ref.namespace`; when `claim_ref` is None (a free PV) the
  `AttributeError` is swallowed by the generic `except Exception`, which
  returns the PARTIAL list built so far. 5.0 treats `claim_ref is None` as
  always visible (free PVs show regardless of the selected namespace).
- **`?name=` read, not 4.1's list-then-filter.** 4.1's data page re-listed
  the cluster (with the session namespace filter) and picked by name in
  Python — a PV unbound in another namespace could 404 on its own data
  page. 5.0 does a single `?name=` read (the StorageClassData contract; the
  kind is cluster-scoped, so NO `namespace` param reaches the getter).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the `to_dict` item — the ratified rule
  (PriorityClassData final review 2026-10-28).
- **The data row label is `Persistent Volume Claim`** — 4.1's template
  typo `Persistent Volume Clame` is not carried over (cosmetic).
- **`trimAnnotations` IS replicated** (the inverse of the sibling
  2026-10-28 deviation): the annotations table drops
  `kubectl.kubernetes.io/last-applied-configuration` and
  `autoscaling.alpha.kubernetes.io/conditions` (4.1's exact
  `trimAnnotations`), per the 2026-11-05 user request. The raw JSON block
  still contains the full object.
- **The Usage column is a 5.0 addition (2026-11-05 user request — "PV
  usage data is missing").** 4.1's PV view had no usage (only its PVC view
  did). The list reuses the PVC list's observed tier verbatim: a second
  parallel fetch on `GET /api/v1/clusters/{id}/metrics/pvcs?namespace=
  <selected>` (KUBELET `/stats/summary`, NOT metrics.k8s.io), joined by
  claim name. The claim-namespace filter guarantees every bound PV shown
  is bound to a claim IN the selected namespace, so the join is sound. A
  free PV (no `claim_ref`) and every ADR-0003 degrade (unavailable /
  denied / failed fetch) render "—"; the usage query's error never fails
  the list. It reuses the `pvc-usage` TanStack Query key, so the cache is
  shared with the PVC list view (no duplicate kubelet scan when both are
  viewed in one session).
