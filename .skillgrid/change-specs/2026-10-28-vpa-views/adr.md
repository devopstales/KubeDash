# VPAs (Vertical Pod Autoscaler) Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `verticalpodautoscalers`, group `autoscaling.k8s.io`, namespace = the query namespace or `None` (all-namespaces); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as the Cilium CRD kinds (full custom object, CRD-served version as authority, CRD-absent → `[]`); no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client's `CustomObjectsApi` is already used by the CRD + Cilium kinds (no new attribute — `self._custom()` / `self._api_client` already exist); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path, and 4.1's own template lived in `other-resources/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (the Cilium CRD kinds = the same full-custom-object read seam, same
CRD-served-version authority, same CRD-absent-degrades-to-empty contract,
same `_KINDS` + `_GETTERS` wiring, same list+data view pair).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`vpa_name`) and the data page re-listed the whole namespace then filtered
  in Python (`for vpa in vpas: if vpa["name"] == vpa_name`). 5.0 reaches the
  data page by query params (the Namespaces/Nodes/CRDs/ResourceQuota
  decision) and does a single `?name=` read (the SecretData/NetworkPolicyData/
  ResourceQuotaData contract).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the custom object — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **The read is a FULL custom object, not the `list_crd_instances`
  projection.** 5.0's `list_crd_instances` projects to
  `{name, namespace, status, type, reason, message, created}` — it drops
  `spec`/`status` entirely. The VPA pages need `spec.resourcePolicy
  .containerPolicies` and `status.conditions`, so the kind reads the raw
  custom object (the Cilium precedent: `list_cilium_network_policies` /
  `get_cilium_network_policy` return the full `to_dict`). The object stays
  camelCase (the custom-object wire form, like the Cilium CRDs) — NOT
  snake_case (it is not a generated core-API model).
- **CRD-absent degrades to `[]`, not an error.** 4.1's `get_vpa_crd_version`
  returns `None` when the CRD read fails and `k8sVPAListGet` returns `[]` —
  the VPA operator is optional, so a cluster without it is a first-class
  empty state. 5.0 keeps this via the Cilium `get_crd_served` contract: CRD
  404 → `served is None` → `[]`; any other read failure →
  `ClusterUnreachableError` (502). The list and data pages render the
  empty/`[]` as their not-found / empty states (no special "CRD absent"
  copy).
- **The Conditions table reads `status.conditions`, not 4.1's top-level
  `conditions`.** 4.1's `vpa-data.html.j2` iterates `vpa_data.conditions`,
  but `k8sVPAListGet` populates `metadata`/`spec`/`status` only — it never
  sets a top-level `conditions` key. So 4.1's Conditions table was dead
  (always rendered `None`); the conditions actually live at
  `status.conditions`. 5.0 reads `status.conditions` (the real location) and
  renders the typed `Type / Status / Last Transition Time / Reason / Message`
  table with `No conditions` when empty.
- **The Target Name link is dropped.** 4.1's list + data pages made Target
  Name a hidden-form link to `/workload/<kind-lower>s` (with `ns_select` +
  `selected`); 5.0 has no workload-page destination yet, so the target name
  renders as plain text (the kind is still shown in the Target Kind column;
  the full `targetRef` is in the JSON block).
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
