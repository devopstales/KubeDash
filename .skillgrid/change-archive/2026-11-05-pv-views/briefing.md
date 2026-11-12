# Briefing — PV Views (4.1 parity port)

**Change:** `2026-11-05-pv-views`
**Date:** 2026-11-05
**Trigger:** user request (2026-11-05) — "and `/storage/pv` is missing." The
Storage nav group already has the 4.1 IA leaf `Volumes → /storage/pv`
(`_nav.tsx`), but the path still renders the Stub view — the only Storage
kind never ported (the 2026-10-28 batch covered storageclass, snapshotclass,
volumesnapshot, pvc, configmap).

## What 4.1 has

- `4.1/src/kubedash/blueprint/storage.py` — routes `GET/POST /storage/pv`
  (list) and `POST /storage/pv/data` (detail by re-list + pick-by-name).
- `4.1/src/kubedash/lib/k8s/storage.py::k8sPersistentVolumeListGet` —
  `CoreV1Api().list_persistent_volume()`, filtered to the session-selected
  namespace via `pv.spec.claim_ref.namespace == ns`.
- `4.1/src/kubedash/templates/storage/pv.html.j2` — list: Status badge
  (Bound=success, Terminating=danger, else warning), Name (POST to data),
  StorageClass (POST to storage-class), VolumeClaim (POST to pvc), Capacity.
- `4.1/src/kubedash/templates/storage/pv-data.html.j2` — data rows: Status,
  Name, Created, Deleted (conditional), Annotations (key/value table,
  `trimAnnotations`), Labels, StorageClass (link), Persistent Volume Claim
  (link), PVC Namespace, Access Mode, Volume Mode, Reclaim Policy, Capacity,
  then conditional Local Path (hostPath) XOR (CSI Driver + Filesystem Type),
  then the dynamic `volume_attributes` table.

## Two 4.1 bugs in the list function (recorded deviations)

1. **hostPath PVs are silently skipped** — `if pv.spec.host_path:
   PV.update(...); continue` hits `continue` instead of appending. On the
   kind dev cluster (local-path provisioner = hostPath PVs) the list would
   be empty. 5.0 appends every PV.
2. **Unbound PVs crash the list** — `pv.spec.claim_ref.namespace` raises
   `AttributeError` when `claim_ref` is None; the generic `except Exception`
   swallows it and returns the PARTIAL list built so far. 5.0 treats
   `claim_ref is None` (a free PV) as always visible, regardless of the
   selected namespace.

## Scope

- **Backend:** `K8sClient.list_persistent_volumes(namespace)` (cluster list
  + claim-namespace filter: free PVs always, bound PVs only for `ns`) and
  `get_persistent_volume(namespace, name)` (0/1-item, 404 → `[]`);
  `_KINDS` + `_GETTERS` rows in `resources.py`. SAR-gated like every other
  kind (ADR-0004). No new API surface — the generic route plugs in.
- **Frontend:** `views/Storage/Pv.tsx` (list; 4.1 columns; the
  StorageClass/VolumeClaim cells are ADR-0040 object refs — cross-kind
  opens, the claim ref carries the claim's namespace per R8) and
  `views/Storage/PvData.tsx` (4.1 row set + full-object JSON block;
  annotations rendered with 4.1's `trimAnnotations` — see below).
  `PersistentVolumeItem` type in `lib/types.ts`.
- **Wiring:** `App.tsx` `ObjectRoute` at `/storage/pv` (cluster-scoped; the
  kind was a stub — no legacy `/data` route, no R7 redirect); the stub
  entry leaves `views/Stub/routes.ts`; `Stub.test.tsx` viewPaths gains
  `/storage/pv`; `ui-smoke.spec.ts` moves `/storage/pv` from
  SMOKE_STUB_ROUTES to REAL_ROUTES.
- **No demo-fixture change:** the dev cluster already has real PVs
  (local-path PVs for the bound PVCs; `demo-pvc`'s PV is in
  `kubedash-demo`).

## Companion fix (same batch, separate commit)

User request (2026-11-05): filter `kubectl.kubernetes.io/last-applied-configuration`
from the annotation tables. 4.1's shared `trimAnnotations`
(`lib/helper_functions.py`) drops exactly two keys:
`kubectl.kubernetes.io/last-applied-configuration` and
`autoscaling.alpha.kubernetes.io/conditions`. The 5.0 storage data views
currently render annotations verbatim — a RECORDED deviation in all five
storage specs' adr.md — and yesterday's HPA fix (46929a10) already
replicated the trim there per the same user decision. This batch applies
the identical trim to the five storage data views
(StorageClassData, SnapshotClassData, VolumeSnapshotData, PvcData,
ConfigMapData); PvData is built with it from the start. The raw JSON block
is untouched (it renders the full object, noise included).

## Out of scope

- PV mutations (bind/delete) — read-only parity, like every other view.
- PV usage metrics — 4.1 has none for PV (only PVC, which landed in
  2026-10-28-pvc-views).
- Non-storage annotation trims (other data views keep their current
  behavior; HPA already trims).

## Acceptance

See `acceptance.feature`.
