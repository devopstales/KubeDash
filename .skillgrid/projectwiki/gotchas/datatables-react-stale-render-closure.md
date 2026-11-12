---
type: Reference
title: "KubeDataTable render closures go stale — join late data into the row, not the render fn"
description: "datatables.net-react binds Column render fns to the table instance only at initialisation and re-renders cells only when the data prop changes; a closure over a late-resolving query Map sticks at its init-time (empty) value until remount. Join the late data into the row array per render (Nodes.tsx pattern) so the fresh array changes the data prop. (500e13e4, 2026-11-05.)"
tags: [frontend, gotcha, datatables, react, stale-closure, observed-tier]
status: stable
generated: { by: skillgrid/kb-maintenance, at: 2026-11-06 }
verification:
  engine: ripgrep
  anchors:
    - path: frontend/src/views/Storage/Pv.tsx
      all_of: ['render fns', 'data prop', 'usage: string | null']
    - path: frontend/src/components/KubeDataTable.tsx
      all_of: ['datatables']
---

# KubeDataTable render closures go stale — join into the row

**The trap.** `datatables.net-react` binds a `Column` render function to
the table instance **only at initialisation** and re-renders a cell only
when the `data` prop changes. A render fn that closes over a React-query
`Map` (or any other reference) therefore captures the Map **as it was at
table init** — if the query resolves later (the observed-tier metrics
fan-out always lands after the informer-cached list read), the cell
sticks at its init-time value (`—` / empty) until the table remounts,
because the query data's *reference* never changed in a way the wrapper
sees.

**The shape that works (the Nodes.tsx pattern).** Do not let the render
fn reach for the query. Join the late data **into the row array on every
render** — `type PvTableRow = PvRow & { usage: string | null }` — so:

- the render fn is a pure function of the row (no external closure);
- the freshly joined array is a new `data` prop each render, which is
  what triggers the wrapper's redraw.

**Bite marks** (2026-11-05, storage batch review):

- PVC/PV list Usage column stuck at `—` after the kubelet stats
  resolved (fixed `500e13e4`); the test fake had previously *masked*
  the bug by re-rendering cells from current children — the local
  `KubeDataTable` fake now replicates init-time capture, and
  `list-usage-late-resolution-updates-in-place` regression tests fail
  against the old code.
- The sibling class is **memo deps over router location**:
  `NetworkPolicyRoute`'s active-ref memo listed `location` in its deps
  but the component never called `useLocation()`, so `location`
  silently resolved to the stable global `window.location` — the dep
  was inert and the detail rendered only after a full reload
  (`d75d6f1f`, then `813b9026`). Rule: a router dep must be the value
  from `useLocation()`, not an unqualified identifier.

**Rule for the agent.** When a KubeDataTable cell must reflect
data that can resolve after the list: join it into the row. If you
write a render fn that touches anything outside its row, it is stale
by construction.

**Related.** ADR-0010 (the read path: list from the cache resolves
first, observed-tier metrics are the late tier — ADR-0003's
degrade-don't-fail two-tier), `invariants/object-view-annotation-trim.md`
(another data-view contract), `frontend/src/views/Cluster/Nodes.tsx`
(the reference implementation of the join pattern).
