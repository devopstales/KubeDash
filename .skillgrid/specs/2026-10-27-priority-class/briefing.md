# Priority Classes — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-27-priority-class`
**Date:** 2026-10-27

**Tier:** T2 — multi-file backend + frontend change; touches the cluster
resource-read contract (SAR gating) but adds no new trust boundary, no
migration, no new dependency.

## Intent

Replace the `/security/priorityclass` stub (ADR-0022 parity row, `stub`
column) with the 4.1 feature: a **Priority Classes** list page plus a
**detail page** for a single PriorityClass. `PriorityClass` is
cluster-scoped — the page shows the cluster's priority classes
unconditionally, no namespace involvement. 4.1 is the behavioral reference
(what to show); the current architecture (R4 resource table,
`K8sClientPool` seam, SAR gating) is the structural authority (how to get
the data).

Two deliberate deltas from 4.1 (ratified in planning, 2026-10-27):

1. **SAR gating.** 4.1's only gate was the app-level role. This build gates
   on a SubjectAccessReview BEFORE the read (ADR-0004) — a user without
   `list priorityclasses` on `scheduling.k8s.io` gets 403, not an empty list.
2. **Nav placement under Other Resources.** 4.1's API lived in
   `other_resources.py` and its pages under Security; the two disagree. The
   user resolves the delta in the API's favor: the nav leaf and the route
   move from Security to the **Other Resources** group
   (`/security/priorityclass` → `/other-resource/priorityclass`). This is a
   ratified deliberate deviation, recorded in the ADR-0022 parity row — the
   first real (non-stub) page in the Other Resources group, and the template
   for the five remaining stubs (HPAs, VPAs, PDB, Resource Quota, Limit
   Range, Runtime Class) whose 4.1 reference is the same `other_resources.py`
   API.

## Reference

4.1 branch (pre-rewrite, session + Jinja):

- `4.1:src/kubedash/blueprint/api/other_resources.py` — `GET
  /api/v1/other-resources/priority-classes[/<name>]`. The detail endpoint is
  list-then-filter in Python (one list call, loop for the name).
- `4.1:src/kubedash/lib/k8s/other.py` — `k8sPriorityClassList`: cluster-scoped
  `SchedulingV1Api().list_priority_class()`; each item carries `name`,
  `annotations`, `labels`, `created`, `preemption_policy`, `value`,
  `description`, `global_default`.
- `4.1:src/kubedash/blueprint/security/security.py` +
  `templates/security/priority-class[-data].html.j2` — the two pages: list
  (name links to detail) and detail (metadata).

Deliberately NOT carried over from 4.1:

- the standalone `/api/v1/other-resources/...` endpoint shape — this
  codebase's reads all route through
  `/api/v1/clusters/<id>/resources/<kind>` (the R4 table);
- the list-then-filter detail endpoint — this build reads one object via
  `?name=` (the `get_secret` contract);
- `@cache.memoize` on the read — ADR-0010's informer cache interposes at the
  pool seam later; per-function memoization keyed on user_token is 4.1's
  shape, not this codebase's;
- the session-based `ns_select` and the Security nav placement — neither
  applies to a cluster-scoped kind, and the placement moves (delta 2).

## Requirements

### R1 — `priorityclasses` kind (R4 table)

`GET /api/v1/clusters/<id>/resources/priorityclasses` returns the
cluster's `PriorityClass` objects in the standard kubernetes `to_dict`
shape, through the R4 resource table:

- Binding gate: 404 `CLUSTER_NOT_FOUND` (unbound user or unknown cluster id).
- SAR gate BEFORE the read: `list` on `priorityclasses` /
  `scheduling.k8s.io` → 403 `RBAC_DENIED` naming the denied resource
  (ADR-0004; cluster-scoped — namespace `None`).
- `?name=` lookup: SAR `get` on that object; items holds zero or one entry
  (`[]` when the class does not exist — the `get_secret` contract).
- `namespace` query, if present, is accepted and ignored — the kind is
  cluster-scoped (the `list_nodes` pattern).

### R2 — List view

`/other-resource/priorityclass` renders a `KubeDataTable` of the
cluster's priority classes: columns **Name** (link to detail),
**Value** (`spec.value`), **Preemption Policy**
(`spec.preemption_policy`), **Global Default** (`spec.global_default`),
**Description** (`spec.description`), **Created** (`metadata.creation_timestamp`
rendered in the browser's local time via `formatTimestamp` — same decision
as the network-policy build, same shared helper).

- No cluster selected → "No cluster selected." (the `Secret.tsx` pattern).
- Errors surface as the standard error line (query.error.message), never a
  blank page.
- The card/section title text is EXACTLY `Priority Classes` — the e2e smoke
  (`frontend/e2e/ui-smoke.spec.ts:46`) asserts that string with `exact: true`.

### R3 — Detail view

`/other-resource/priorityclass/data?name=<name>` shows one
PriorityClass. No `namespace` param (the kind is cluster-scoped).

- Data via the `?name=` endpoint (single K8s read — NOT 4.1's
  list-then-filter).
- Content: metadata block (name, value, preemption policy, global default,
  description, created, labels, annotations) + the full object rendered as
  syntax-highlighted YAML (the `SecretData.tsx` highlighter wiring, `yaml`
  language registered at the view's own module scope).
- `items` empty (404 upstream) → "not found" state, not an error.

### R4 — Nav move + stub retirement

- `_nav.tsx`: the leaf moves from the Security group to the Other Resources
  group at `/other-resource/priorityclass` (title unchanged: "Priority
  Classes"); the Security group keeps its other leaves.
- `views/Stub/routes.ts`: the `/security/priorityclass` entry is replaced
  by the new path (stubbed until the views land, removed in the same change
  as the real routes).
- `App.tsx`: real lazy routes at `/other-resource/priorityclass` and
  `/other-resource/priorityclass/data`.
- The e2e smoke entry moves to the new path; its `title` assertion is
  unchanged.
- ADR-0022 parity row (line 88): path → `/other-resource/priorityclass`,
  group Interface/Security → Interface/Other Resources, column `stub` →
  implemented, with a note that the placement is a ratified deviation from
  4.1 (4.1's own API lived in `other-resources`).

## Success criteria

- A cluster with PriorityClasses: the list shows every class with
  value/preemption/default/description; clicking a name opens the detail
  with the full object as YAML.
- A user denied `list priorityclasses` by SAR: 403 with the resource named;
  no class data in the response; the list is never attempted.
- The old path `/security/priorityclass` renders nothing (no route, no stub)
  and the nav no longer offers it under Security.
- `task fe-check` stays green (air gap); the full unit suites pass.
