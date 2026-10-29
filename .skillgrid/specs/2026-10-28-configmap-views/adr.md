# ConfigMap Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `configmaps`, core group (`""`), namespace = the query namespace or `None` (all-namespaces branch); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/resourcequotas/networkpolicies for a namespaced core kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api` as the existing `self._v1` attribute (NO new `__init__` attribute needed); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by `SecretData.tsx`). |
| ADR-0022 (other-resources placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own templates lived in `storage/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (the namespaced core-kind family — secrets/resourcequotas/
networkpolicies — same `_KINDS` + `_GETTERS` wiring, same list+data view
pair). The ONE deviation — the list's `Data Keys` column over 4.1's
Name/Created-only list — is a ratified, documented addition (briefing R3):
the count is free (a ConfigMap's `data` is public, so `list_configmaps`
does NOT strip it, unlike `list_secrets`) and it is the one field that
distinguishes an empty ConfigMap from a populated one without a per-row
payload read.

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`configmap_name`) and the data page re-listed the whole namespace then
  filtered in Python (`for configmap in configmaps: if configmap["name"] ==
  configmap_name`). 5.0 reaches the data page by query param and does a
  single `?name=&namespace=` read.
- **The list gains a `Data Keys` column.** 4.1's list showed Name / Created
  only. 5.0 adds the `data` key count (free — `data` is on the list read,
  NOT stripped, because a ConfigMap's `data` is public config unlike a
  Secret's credentials) so an empty ConfigMap is distinguishable from a
  populated one. `binaryData` is NOT counted (4.1's list read projected
  only `data`).
- **`list_configmaps` does NOT strip `data`.** `list_secrets` pops
  `data`/`string_data` because a Secret's values are sensitive; a ConfigMap's
  `data` is public, so the full `to_dict` goes to the view and the list's
  Data Keys column is computed from it. Stripping it (copying `list_secrets`)
  would silently break that column.
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  `list_namespaced_config_map`; 5.0's client uses the pool's configured
  timeout (a 1 s list read on a large namespace is a spurious-failure
  source, and the 5.0 client's contract is the pool timeout, not a per-call
  override).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data page
  renders `JSON.stringify` of the `to_dict` item — JSON is a YAML subset,
  and the `json` grammar is the truthful classifier for the exact text
  rendered (ratified rule, PriorityClassData final review 2026-10-28). 4.1's
  data page had NO full-object block at all.
- **The per-key `data` value is a plain `<pre><code>` block, NOT the
  Secret view's base64-decode-with-eye.** ConfigMap `data` values are plain
  strings (NOT base64, unlike a Secret's `data`), so the `SecretValue`
  component's base64 decode + eye toggle + `secretLanguage` heuristic are
  all Secret-only and NOT applied here — the value renders verbatim in a
  `<pre><code>` with `pre-wrap` + `break-word` (4.1's `<pre><code>` block,
  re-implemented; 4.1's manual `<`/`>` escaping is implicit in React's text
  rendering).
- **`trimAnnotations` is NOT replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper). NOTE: this is a deviation
  from the in-repo `SecretData.tsx` view (which DOES filter
  last-applied-configuration) — ConfigMap data is lower-sensitivity than a
  Secret, and the brief's certainty rule is "render verbatim, the JSON block
  has the full object."
- **The data page's "Lables" typo is not replicated** — 4.1's
  `configmap-data.html.j2` line 70 says `Lables:`; 5.0 renders `Labels`.

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
