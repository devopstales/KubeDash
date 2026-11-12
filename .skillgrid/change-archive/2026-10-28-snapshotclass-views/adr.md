# SnapshotClass Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `volumesnapshotclasses`, group `snapshot.storage.k8s.io`, namespace `None` (cluster-scoped); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as the Cilium CRD kinds (full custom object, CRD-served version as authority, CRD-absent → `[]`) and the RuntimeClass cluster-scoped pattern; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client's `CustomObjectsApi` is already used by the CRD + Cilium + VPA kinds (no new attribute — `self._custom()` / `self._api_client` already exist); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own template lived in `storage/`. (ADR-0022's "other-resources" clause is for 4.1's `other-resources` API grouping; Storage is the analogous placement for 4.1's `storage` grouping.) |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows established, ratified in-repo
patterns (the Cilium CRD kinds = the full-custom-object read seam +
CRD-absent-degrades-to-empty; the RuntimeClass = the cluster-scoped kind
pattern; the same `_KINDS` + `_GETTERS` wiring, the same list+data view pair).

## Recorded deviations from 4.1

- **`?name=` navigation, not 4.1's hidden form + `session['ns_select']`.**
  4.1's list page POSTed a hidden form per row (`sc_name`) and the data page
  re-listed the whole cluster then filtered in Python (`for sc in
  snapshot_classes: if sc["name"] == sc_name`). 5.0 reaches the data page by
  query param and does a single `?name=` read (the PriorityClassData contract
  — the kind is cluster-scoped, so NO `namespace` param).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the custom object — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **The read is a FULL custom object, not the `list_crd_instances`
  projection.** 5.0's `list_crd_instances` projects to
  `{name, namespace, status, type, reason, message, created}` — it drops
  `driver`/`deletionPolicy`/`parameters` entirely. The SnapshotClass pages
  need those, so the kind reads the raw custom object (the Cilium precedent:
  `list_cilium_clusterwide_network_policies` / `get_cilium_network_policy`
  return the full `to_dict`). The object stays camelCase (the custom-object
  wire form, like the Cilium CRDs) — NOT snake_case (it is not a generated
  core-API model).
- **The CRD version is resolved, not hardcoded.** 4.1's
  `k8sSnapshotClassListGet` calls
  `list_cluster_custom_object("snapshot.storage.k8s.io", "v1",
  "volumesnapshotclasses")` — a hardcoded `v1`. 5.0 resolves the served
  version via `get_crd_served` (the CRD's OWN spec is the authority — the
  same seam the Cilium + VPA kinds use), so a cluster serving a different
  version is handled correctly.
- **CRD-absent degrades to `[]`, not an error.** 4.1's
  `k8sSnapshotClassListGet` swallows the `ApiException` (any status) and
  returns `[]` — the snapshot operator is optional, so a cluster without it
  is a first-class empty state. 5.0 keeps this via the Cilium
  `get_crd_served` contract: CRD 404 → `served is None` → `[]`; any other
  read failure → `ClusterUnreachableError` (502). (4.1's blanket swallow
  masked transport failures as empty; 5.0 distinguishes absent-CRD from
  unreachable-cluster.)
- **The cluster-scoped getter is new in 5.0.** The `_GETTERS` call
  convention passes `(namespace, name)`; the existing CRD getters
  (`get_cilium_network_policy`) are namespaced. This kind is cluster-scoped,
  so `get_volume_snapshot_class(_namespace, name)` ignores the namespace and
  calls `get_cluster_custom_object` (the `list_crds` / `get_crd` pattern,
  which use the cluster-scoped custom-object reads). The `?name=` branch's
  `namespace = "default"` fallback is irrelevant (the read ignores it).
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
