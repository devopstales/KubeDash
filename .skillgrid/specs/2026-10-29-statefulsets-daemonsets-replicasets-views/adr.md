# StatefulSets + DaemonSets + ReplicaSets Views — ADR

## Decision Summary

Port 4.1's StatefulSet views (`/workload/statefulsets`), DaemonSet views
(`/workload/daemonsets`), and ReplicaSet views (`/workload/replicasets`) as
three SAR-gated, read-only, **namespaced** list + data pairs on the existing
generic resource route. All three are `apps/v1` kinds (group `apps`), all on
the shared `self._apps` (`AppsV1Api`) — the same attribute the companion
`pods-deployments-views` change adds (deduped, not re-added). Each kind gains
two `K8sClient` methods (list + get, `to_dict` form, `[]` on 404) + two
`_KINDS`/`_GETTERS` rows. The data pages follow the ratified 5.0 shape: 4.1's
curated multi-tab tables (StatefulSet/DaemonSet: 5 tabs; ReplicaSet: the
Deployment-tab shape, a **5.0 addition** — 4.1 was list-only) + the full-object
`JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
truthful-classifier rule). **The 4.1 data-page title bugs are FIXED**
(ratified 2026-10-29) — StatefulSet data is `StatefulSet Data` (not 4.1's copy-
paste `Deployment Data`), DaemonSet data is `DaemonSet Data` (not 4.1's
`Daemonset Data`), the first-tab labels are `StatefulSet` / `DaemonSet` /
`ReplicaSet` (not 4.1's mislabeled `Deployment`). The LIST card titles are kept
verbatim (the e2e-smoke contract; the 4.1 `Statefullset` list-title typo is NOT
replicated — 5.0 renders `Statefulset List`). The ReplicaSet owner deep-link is
**deferred** to the Deployments view (the not-yet-landed
`pods-deployments-views` spec) — plain text until it lands.

## Decision Context

- **Three `apps/v1` kinds, one shared `self._apps`.** All three kinds use
  `AppsV1Api`, which requires the `self._apps` attribute. The companion
  `pods-deployments-views` change (adds `list_deployments` / `get_deployment`)
  ALSO adds `self._apps` and has NOT landed. This change adds `self._apps` if
  absent (with a WHY-comment noting the shared ownership); when the
  deployments change lands, the attribute is deduplicated (not re-added) — the
  same ownership/dedupe pattern as the GatewayClass seam. The three kinds are
  self-contained on it (they work whether the deployments change lands before
  or after).
- **The `spec.template.spec` is the same for all three.** The Containers /
  Variables / Security Contexts / Related Resources tabs are IDENTICAL across
  StatefulSet / DaemonSet / ReplicaSet (the `apps/v1` workload template is the
  same). Only the first tab differs (the metadata row set: Replicas vs Desired
  vs Desired+Owner). This is a deliberate DRY opportunity — the three data
  views share a common `WorkloadTemplateTabs` component (the template tabs)
  parameterized by the first tab's content.
- **The status fields differ per kind** (the 4.1 mapping, kept): StatefulSet
  Desired/Current/Ready = `status.replicas` / `current_replicas` /
  `ready_replicas`; DaemonSet = `status.desired_number_scheduled` /
  `current_number_scheduled` / `number_ready`; ReplicaSet = `status.
  fully_labeled_replicas` / `available_replicas` / `ready_replicas`. These are
  the 4.1 mappings (the ReplicaSet `fully_labeled_replicas` as "Desired" is a
  4.1 choice — 5.0 keeps it verbatim for parity; it's the closest k8s status
  field to "desired" for a ReplicaSet).
- **The 4.1 data-page title bugs are fixed (ratified 2026-10-29).** 4.1's
  StatefulSet data page card title is `Deployment Data` (a copy-paste from the
  Deployment template) and its first tab is labeled `Deployment`; 4.1's
  DaemonSet data page first tab is also labeled `Deployment`. These are copy-
  paste artifacts, not intentional. 5.0 renders `StatefulSet Data` /
  `DaemonSet Data` / `ReplicaSet Data` and the first-tab labels `StatefulSet`
  / `DaemonSet` / `ReplicaSet`. The LIST card titles are kept verbatim (the
  e2e-smoke contract) — only the 4.1 data-page title bugs are fixed, plus the
  4.1 `Statefullset` list-title casing typo (the `ll` is a 4.1 artifact).
- **The ReplicaSet data page is a 5.0 addition (ratified 2026-10-29).** 4.1
  had a list-only ReplicaSet view (no `replicaset-data.html.j2`, the Name cell
  was not a link). 5.0 adds a data page (the Deployment-tab shape + the JSON
  block) for consistency with every other 5.0 data page, and the list Name cell
  gains a link to it.
- **The ReplicaSet owner deep-link is deferred.** The owner (almost always a
  Deployment) deep-links to `/workload/deployments/data` only when the
  deployments view is landed (the not-yet-landed `pods-deployments-views`
  spec); until then it is plain text (the "deep-link to landed kinds" pattern
  from `pods-deployments-views`).
- **The Replicas / Desired is plain text.** 4.1's Admin-only replica spinners
  (StatefulSet + DaemonSet) are WRITE paths (a patch); these views are read-
  only, so the spinners are not replicated — the value renders as plain text.
- **`trimAnnotations` not replicated; the 4.1 StatefulSet annotations bug is
  fixed.** 4.1's `k8sStatefulSetsGet` has a latent bug — it sets `annotations`
  to `trimAnnotations(sfs.metadata.labels)` (passing the LABELS). 5.0 renders
  `metadata.annotations` verbatim (the truthful field), no `trimAnnotations`.
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  every read; 5.0's client uses the pool's configured timeout (the house rule).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | Per-object SAR (`list` / `get` on the kind, the namespace, group `apps`) gates all three reads; deny → 403 `RBAC_DENIED`, the SAR before the K8s call, the client call never made on deny. |
| 0009 | SSE is the push channel — not used by these read-only views (the list/data fetches are TanStack Query polls). |
| 0010 | Read path — the list/data fetches are per-request REST (these are the resource views; the informer-cache read path applies to the watch-driven surfaces, not this generic route). |
| 0020 | Air-gap — no new npm/Python dependency; the views reuse `KubeDataTable` + `CTabs` + CoreUI + `react-syntax-highlighter` (the `json` grammar already registered). |
| 0021 | The cluster binding gate (404 unbound) and the local-admin/cluster model the SAR reads assume. |
| 0022 | The Workloads group nav shape the three leaves already occupy (4.1 parity structure; the leaves are promoted from stubs, NOT added — no nav change). |

## Deviations (from 4.1)

1. **`?name=` + `?namespace=` query-param navigation**; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page (a
   single `?name=` request).
2. **The 4.1 data-page title bugs are FIXED** (ratified 2026-10-29) —
   StatefulSet data is `StatefulSet Data` (not 4.1's copy-paste `Deployment
   Data`); DaemonSet data is `DaemonSet Data` (not 4.1's `Daemonset Data`);
   the first-tab labels are `StatefulSet` / `DaemonSet` / `ReplicaSet` (not
   4.1's mislabeled `Deployment`). The LIST card titles are kept verbatim (the
   e2e-smoke contract).
3. **The 4.1 `Statefullset List` list-title typo is NOT replicated** — 5.0
   renders `Statefulset List` (the correct casing; the `ll` is a 4.1 artifact).
4. **ReplicaSets GAINS a data page** (ratified 2026-10-29 — 4.1 was list-only,
   no `replicaset-data.html.j2`; the data page follows the Deployment-tab shape
   + the JSON block). The ReplicaSet list Name cell GAINS a link (4.1's was not
   a link).
5. **All three data pages GAIN the full-object JSON block** (4.1's data pages
   had none — only the curated tab tables).
6. **The Replicas / Desired is plain text** (4.1's Admin-only replica spinners
   are write paths, NOT replicated — mutation is out of scope).
7. **`trimAnnotations` is NOT replicated** — annotations render verbatim; the
   4.1 StatefulSet annotations bug (`trimAnnotations(labels)` passed the
   LABELS) is fixed — 5.0 renders `metadata.annotations`.
8. **The Related Resources tab deep-links to LANDED kinds only** (Secrets →
   the landed Secret data view); ConfigMap / PVC / ServiceAccount /
   ImagePullSecret → **plain text** (their views are not yet landed — the same
   pattern as `pods-deployments-views`).
9. **The ReplicaSet owner deep-link is deferred** — the owner links to the
   Deployments view only when that view is landed (the not-yet-landed
   `pods-deployments-views` spec); until then it is plain text.
10. **No per-request `_request_timeout=1`.** 5.0's client uses the pool's
    configured timeout.

## Out of Scope

- Create / edit / delete / scale for StatefulSets, DaemonSets, or ReplicaSets
  (read-only; 4.1's Admin replica spinners and the patch functions are NOT
  replicated).
- `?labelSelector=` on any of these routes (the pods-route concern, the not-
  yet-landed service-views spec).
- The deep-link of the ReplicaSet owner to the Deployments view in THIS change
  (the deployments view is the not-yet-landed `pods-deployments-views` spec —
  the deep-link is added when it lands).
- The vuln-report columns (4.1's `has_report` block is commented out; not
  ported).
- The DaemonSet "Replicas" scale (a DaemonSet has no `spec.replicas` — 4.1's
  Admin spinner bound to `desired` was a copy-paste artifact; not replicated).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
