# HPAs (Horizontal Pod Autoscaler) Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `horizontalpodautoscalers`, core group (`""`), namespace = the query namespace or `None` (all-namespaces); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/networkpolicies for a namespaced kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `AutoscalingV1Api` (the 4.1 code used it; one new attribute `self._autoscaling` in the 5.0 client); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path, and 4.1's own template lived in `other-resources/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (Secrets / NetworkPolicies / ResourceQuota / PDB = the same
namespaced-kind family, same `_KINDS` + `_GETTERS` wiring, same list+data view
pair).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`hpa_name`) and the data page re-listed the whole namespace then filtered
  in Python (`for hpa in hpas: if hpa["name"] == hpa_name`). 5.0 reaches the
  data page by query params (the Namespaces/Nodes/CRDs/ResourceQuota/PDB
  decision) and does a single `?name=` read (the SecretData/NetworkPolicyData/
  ResourceQuotaData contract).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the `to_dict` item — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **The list MinReplicas/MaxReplicas header-cell swap is corrected.** 4.1's
  `hpa.html.j2` declares `<th>MinReplicas</th><th>MaxReplicas</th>` but
  renders `<td>{{ hpa.spec.max_replicas }}</td><td>{{ hpa.spec.min_replicas
  }}</td>` — the `MinReplicas` column shows the MAX value and the `MaxReplicas`
  column shows the MIN value (a latent 4.1 bug). 5.0 renders the matching
  value under each header (`Min Replicas` = `spec.min_replicas`, `Max Replicas`
  = `spec.max_replicas`). The data template read the correct fields (no swap
  there); the correction is list-only.
- **The Conditions table is typed, sourced from `status.conditions` with a
  legacy-annotation fallback.** 4.1's `hpa-data.html.j2` Conditions table is
  dynamic-key (header `Type/Status/lastTransitionTime/Reason/Message` but the
  body iterates `condition.items()` in the raw key order — a malformed table
  when keys differ, and a `<th>` row nested in an extra `<tr>`). More
  load-bearing: 4.1's `k8sHPAListGet` populates `HPA_DATA["conditions"]` ONLY
  from the legacy `autoscaling.alpha.kubernetes.io/conditions` ANNOTATION
  (a `json.loads` of the annotation value), NOT from `status.conditions`. So
  a modern HPA (no legacy annotation) had an EMPTY conditions table in 4.1.
  5.0 reads `status.conditions` (the real location, present on modern HPAs)
  and falls back to the legacy annotation when `status.conditions` is absent
  (4.1's source, for legacy HPAs). The typed shape is `Type / Status / Last
  Transition Time / Reason / Message` with `No conditions` when empty.
- **The Targets/Metrics display keeps 4.1's legacy v1 CPU-only field.** 4.1
  renders `status.current_cpu_utilization_percentage` /
  `spec.target_cpu_utilization_percentage` (the `UNKNOWN` literal when the
  current is absent). These are legacy `autoscaling/v1` fields, only
  populated for CPU-based HPAs. 5.0 keeps them (certainty: render what the
  object has; `UNKNOWN` / `—` when absent). The modern v2 multi-metric
  `spec.metrics` / `status.conditions` metric kinds are NOT rendered
  first-class — the raw spec/status is in the JSON block. Recorded as a
  non-goal (see `briefing.md`).
- **The Target/Owner link is dropped.** 4.1's list + data pages made Owner a
  hidden-form link to `/workload/<kind-lower>s` (with `ns_select` +
  `selected`); 5.0 has no workload-page destination yet, so the owner renders
  as plain text (the full `scale_target_ref` is in the JSON block).
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).
  **OVERRIDDEN (2026-11-04):** the data view now applies 4.1's trim
  (user-requested format fix, commit `46929a10`) —
  `kubectl.kubernetes.io/last-applied-configuration` AND
  `autoscaling.alpha.kubernetes.io/conditions` are dropped from the
  annotations table; the JSON block still carries the full object.

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
