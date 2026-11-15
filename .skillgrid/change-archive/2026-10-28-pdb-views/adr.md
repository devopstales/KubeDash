# PodDisruptionBudget Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `poddisruptionbudgets`, group `policy` (v1), namespace = the query namespace or `None` (all-namespaces); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/networkpolicies/resourcequotas for a namespaced kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `PolicyV1Api` (the 4.1 code used it; the 5.0 client instantiates one new attribute); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path, and 4.1's own template lived in `other-resources/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (Secrets / NetworkPolicies / ResourceQuota = the same namespaced-kind
family, same `_KINDS` + `_GETTERS` wiring, same list+data view pair).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`pdp_name`) and the data page re-listed the whole namespace then filtered
  in Python (`for pdp in pdps: if pdp["name"] == pdp_name`). 5.0 reaches the
  data page by query params (the Namespaces/Nodes/CRDs/ResourceQuota
  decision) and does a single `?name=` read (the SecretData/NetworkPolicyData/
  ResourceQuotaData contract).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the `to_dict` item — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **Missing spec/status values render `—`, not blank / `UndefinedError`.**
  4.1's list row renders `{{ pdp.min_available }}` / `{{ pdp.max_unavailable }}`
  / `{{ pdp.status.disruptions_allowed }}` unguarded. The k8s API enforces
  exactly one of `min_available`/`max_unavailable`, so the absent one renders
  blank in 4.1; and `status` is **absent** on a freshly-created PDB (the
  controller fills it), where 4.1's Jinja 3.1.6 raises
  `UndefinedError: 'V1PodDisruptionBudget' object has no attribute 'status'`
  (verified against the 4.1 venv's jinja2 3.1.6 with plain `Undefined` —
  Flask's default). 5.0 renders `—` for absent keys (the certainty rule:
  never guess, never crash the row).
- **`spec.unhealthy_pod_eviction_policy` is a list, not 4.1's 1-tuple.**
  4.1's `k8sPodDisruptionBudgetListGet` sets
  `PDB_DATA["unhealthy_pod_eviction_policy"] = pdb.spec.unhealthy_pod_eviction_policy,`
  — the trailing comma makes a **1-element tuple** containing the list
  (a latent 4.1 bug: the data template's `for policy in pdp_data.unhealthy_pod_eviction_policy`
  iterates the tuple, so it renders the whole list as ONE line, or `None`).
  5.0 reads the field from `to_dict` as a proper list and renders one line
  per entry.
- **The Conditions table is typed, not dynamic-key.** 4.1's Conditions table
  builds its `<thead>` by iterating `condition.items()` across ALL conditions
  (every key becomes a header cell, in the first condition's key order) and
  its `<tbody>` the same way — a malformed table when conditions have
  differing key sets, and a `<th>` row nested inside an extra `<tr>`. The k8s
  condition shape is fixed (`type`, `status`, `reason`, `message`); 5.0
  renders a typed `Type / Status / Reason / Message` table with `No
  conditions` when empty. The raw list is in the JSON block.
- **The duplicate Creation row is collapsed.** 4.1's data table showed both
  `Created` (formatted `created`) and `Creation` (raw `creation_timestamp`)
  from the same field; 5.0 shows one `Created` row via `formatTimestamp`.
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
