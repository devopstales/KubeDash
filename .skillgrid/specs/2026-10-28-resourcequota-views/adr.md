# ResourceQuota Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `resourcequotas`, core group (`''`), namespace = the query namespace or `None` (all-namespaces); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/networkpolicies for a namespaced kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api` (used for pods/secrets/namespaces); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path, and 4.1's own template lived in `other-resources/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (Secrets / NetworkPolicies = the same namespaced-kind family, same
`_KINDS` + `_GETTERS` wiring, same list+data view pair).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row and
  the data page re-listed the whole namespace then filtered in Python. 5.0
  reaches the data page by query params (the Namespaces/Nodes/CRDs decision)
  and does a single `?name=` read (the SecretData/NetworkPolicyData
  contract).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the `to_dict` item — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **Missing status keys render `—`, not a KeyError.** 4.1's templates index
  `quota.status.used["requests.cpu"]` unguarded; a quota without that
  dimension (e.g. `countsTowardsIndividualLimits`-only or object-count
  quotas) would 500 the template. 5.0 renders `—` for absent keys (the
  certainty rule: never guess).
- **`spec.scope_selector` is not rendered as its own table.** 4.1's
  Selectors row fed `PQ_DATA["selectors"]` from the LAST match expression
  only (`for expressions in ...: PQ_DATA["selectors"] = expressions.to_dict()`
  — overwrite per iteration: a latent bug for multi-expression selectors).
  5.0 renders `spec.scopes` (the scope names) first-class and leaves the raw
  `scope_selector` in the full-object JSON block.
- **The duplicate Creation row is collapsed.** 4.1's data table showed both
  `Created` and `Creation` from the same `creation_timestamp`; 5.0 shows one
  `Created` row.
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).
