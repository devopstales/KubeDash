# LimitRange Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.
>
> **Target home:** `.skillgrid/specs/2026-10-28-limitrange-views/` (written
> here because Plan mode is read-only on the repo).

**Topic:** `2026-10-28-limitrange-views`
**Date:** 2026-10-28
**Backlog:** TASK-054
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `Limit Range` leaf (`/other-resource/limit-range`,
`_nav.tsx:115`) that currently renders the placeholder stub
(`views/Stub/routes.ts:27`). The 4.1 codebase HAS both templates —
`limit_range.html.j2` (list: Name / Namespace / Creation, header-selected
namespace) and `limit_range-data.html.j2` (detail: metadata card + a
"Container Limits" table with Min / Max / Default Limit / Default Request /
Max Limit Request Ratio columns for cpu and memory).

"Based on 4.1" therefore means: 4.1's **placement** (Other Resources — the
ratified deviation, ADR-0022, 2026-10-27), 4.1's **RBAC treatment**
(`limitranges` is namespaced, core group `""`), and 4.1's **data-page
content** (the limits table is the substance of the kind — keep its five
columns). The page **shape** follows the ratified 5.0 precedents, not 4.1's
Jinja mechanics: PriorityClass (list + data views, `?name=` single fetch,
NOT_FOUND as a first-class state, full-object JSON block) for the view pair,
Secret (namespaced kind, `selectedNamespace` from the store, namespace on the
URL) for the namespace handling, and TASK-032 (CRDs) for the
`_KINDS`/SAR wiring pattern.

Deliver: a real list page and a real detail page at
`/other-resource/limit-range` and `/other-resource/limit-range/data`,
removing the stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated LimitRange list endpoint

`GET /api/v1/clusters/<id>/resources/limitranges` MUST return the LimitRange
list (`kind: "limitranges"`, items in kubernetes `to_dict` snake_case form)
from the cluster's client. The read is SAR-gated per ADR-0004: `list` on
`limitranges`, group `""` (core), namespace = the `?namespace=` query param
(namespaced kind); on deny the response is 403 `RBAC_DENIED` naming the
resource, and the SAR is asked BEFORE any K8s client call. An unbound user is
404 from the binding gate (the existing `_cluster_for` behavior). The kind
identifier is the plural `limitranges`; the singular `limitrange` is rejected
with `RESOURCE_KIND_NOT_SUPPORTED` (mirrors
`test_priorityclass_kind_singular_rejected`).

### R2 — A `?name=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/limitranges?namespace=<ns>&name=<name>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` (namespace-aware). No new HTTP route is
added: the kind is wired through `_KINDS` + `_GETTERS` only.

### R3 — The list page

`/other-resource/limit-range` MUST render a `KubeDataTable` with columns
**Name / Namespace / Created** — 4.1's exact list column set
(`limit_range.html.j2` shows Name / Namespace / Creation; no limits summary
on the list, that is the data page's job in 4.1). The card title is EXACTLY
`Limit Ranges` (the e2e smoke convention from the PriorityClass precedent —
the e2e smoke asserts card titles with `exact: true`). The list reads the
header-selected namespace from the cluster store
(`selectedNamespace ?? 'default'` — the Secret/NetworkPolicy pattern for
namespaced kinds) and passes it as `?namespace=`. The Name cell links to
`/other-resource/limit-range/data?name=<name>&namespace=<namespace>` — the
list view is the sole producer of those query strings. States: no cluster
selected → `No cluster selected.`; loading → `Loading limit ranges...`;
error → red error line; empty list → `No limit ranges found` (first-class,
not an error).

### R4 — The detail page

`/other-resource/limit-range/data?name=<name>&namespace=<ns>` MUST fetch the
object with a **single `?name=` request** (not 4.1's list-then-filter; 4.1's
`limit_range/data` re-listed the namespace and matched in Python — the same
wart 4.1 had for other kinds, already replaced in 5.0 by the single-fetch
contract). The namespace is `?namespace=` from the URL, falling back to
`selectedNamespace`, falling back to `default` (the SecretData pattern).
Empty `items` is a not-found **STATE** — pinned copy
`No LimitRange '<name>' found`, muted, not an error. The page renders:

1. a metadata CTable: **Name / Namespace / Kind (`LimitRange`) / Created /
   Annotations / Labels** (sub-tables, SecretData shape);
2. a **Container Limits** CTable (4.1 parity): one row per
   `spec.limits[]` entry × resource, columns **Resource / Minimum / Maximum /
   Default Limit / Default Request / Minimum Limit Request Ratio**. Each
   entry's `type` field names the resource (4.1 hardcoded cpu+memory; 5.0
   iterates the entries and renders each `type` — cpu and memory when the
   type is absent, matching 4.1's output for standard LimitRanges). Absent
   fields render `None` (4.1's pinned copy).
3. the full object as a syntax-highlighted block:
   `JSON.stringify(item, null, 2)` with the `json` hljs grammar (JSON is a
   YAML subset; the truthful-classifier rule ratified for PriorityClassData
   in the final review 2026-10-28), style `anOldHope`.

Missing `name` param → `Error: limit range name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/limit-range` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data).

## Non-goals

- No create/edit/delete for LimitRanges (read-only, as in 4.1 and as in
  every other 5.0 resource view to date).
- No new API path beyond the kind wiring — no sub-route (LimitRange has no
  children).
- No pod→limitrange linkage (which pods a LimitRange constrains) — out of
  scope.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Limit Ranges` is the only smoke-relevant contract.
- No RBAC **template** change: the built-in ClusterRole templates already
  carry `limitranges` (4.1 parity); no migration, no seed change.

## Ratified deviations (recorded; see `adr.md` → Deviations)

1. **`?name=` single fetch, not 4.1's list-then-filter.** 4.1's data route
   re-listed the namespace and matched in Python; the 5.0 contract is one
   `get` SAR + one read (the Namespaces/Nodes/CRDs/PriorityClass decision).
2. **List navigation is a router `Link` with query params**, not 4.1's
   hidden-form POST (sessionStorage/hidden-form workarounds do not carry
   over — same decision).
3. **The limits table iterates `spec.limits[]` by the entry's `type` field**
   instead of 4.1's hardcoded cpu/memory rows (the API models `type`; for
   standard LimitRanges the rendered output is identical).
4. **The full-object block is JSON** text with the `json` hljs grammar
   (truthful classifier), not 4.1's badges/YAML treatment.
5. **The list reads the header-selected namespace** (5.0 cluster store)
   instead of 4.1's per-page namespace form (`ns_select` hidden form);
   the columns keep 4.1's Name / Namespace / Created set.
