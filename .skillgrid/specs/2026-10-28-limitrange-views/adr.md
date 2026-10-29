# LimitRange Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `limitranges`, group `""` (core), namespace = the `?namespace=` param (namespaced kind); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/networkpolicies (namespaced kinds) and priorityclasses; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api.list_namespaced_limit_range`; the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating, placement,
air-gap, read path) and follows an established, ratified in-repo pattern
(PriorityClass = the view-pair precedent; Secret = the namespaced-kind
precedent; the `_KINDS`/`_GETTERS` table is additive).

## Recorded deviations from 4.1

- **`?name=` navigation, not 4.1's hidden-form POST.** The detail page is
  reached by query params (the Namespaces/Nodes/CRDs/PriorityClass
  decision); 4.1's `limit_range/data` consumed a `POST` with a hidden
  `limit_name` field and re-listed the whole namespace
  (`k8sLimitRangeListGet`) before matching in Python.
- **The limits table iterates `spec.limits[]` by the entry's `type` field.**
  4.1 hardcoded exactly two rows per entry (cpu, memory) and read
  `item.min.cpu` / `item.max.memory` / … directly. The kubernetes
  `LimitRangeItem` API models each entry with a `type` (e.g. `Container`,
  `Pod`), and 4.1's hardcoded field reads assume the standard cpu/memory
  shape. 5.0 renders each entry's `type` as the Resource value (falling back
  to cpu+memory rows when `type` is absent, which reproduces 4.1's output
  for standard LimitRanges). For the objects 4.1 displayed, the rendered
  table is identical.
- **Full-object block is JSON, highlighted as `json`.** 4.1's data page
  rendered annotations/labels as Bootstrap badges and had no full-object
  block. The ratified 5.0 rule (PriorityClassData final review, 2026-10-28)
  is that the block is `JSON.stringify` of the `to_dict` item — JSON is a
  YAML subset, and the `json` grammar is the truthful classifier for the
  exact text rendered.
- **The list uses the header-selected namespace (5.0 cluster store), not
  4.1's per-page `ns_select` hidden form.** The 4.1 template carried its own
  namespace form; in 5.0 the namespace selector is the cluster header, so
  the list view reads `selectedNamespace` from the store and the namespace
  travels in the query string (the Secret/NetworkPolicy contract).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
