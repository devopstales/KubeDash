# RuntimeClass Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `runtimeclasses`, group `node.k8s.io`, namespace `None` (cluster-scoped); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as priorityclasses/crds; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `NodeV1Api`; the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Other Resources — the ratified deviation for 4.1's `other-resources` API grouping. The nav leaf already exists at this path. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating, placement,
air-gap, read path) and follows an established, ratified in-repo pattern
(PriorityClass = the same kind family, same group scope, same view pair).

## Recorded deviations from 4.1

- **4.1 had no RuntimeClass page at all.** Its `other-resources` nav carried a
  `Runtime Class` leaf, but `templates/other-resources/` has no
  `runtimeclass.html.j2` — the link was dead (Jinja template 404). The kind
  exists in 4.1 only as an RBAC-template resource (`runtimeclasses` in the
  reader/admin ClusterRoles). The 5.0 list+data shape is therefore modeled on
  the 5.0 PriorityClass precedent, not on a 4.1 template.
- **`?name=` navigation, not 4.1's sessionStorage/hidden-form.** The detail
  page is reached by a query param (the Namespaces/Nodes/CRDs decision); the
  4.1 hidden-form + sessionStorage workaround does not carry over.
- **Full-object block is JSON, highlighted as `json`.** 4.1's data pages
  rendered YAML; the ratified 5.0 rule (PriorityClassData final review,
  2026-10-28) is that the block is `JSON.stringify` of the `to_dict` item —
  JSON is a YAML subset, and the `json` grammar is the truthful classifier
  for the exact text rendered.

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
