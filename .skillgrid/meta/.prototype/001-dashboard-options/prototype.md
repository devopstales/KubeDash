---
prototype: 001
name: dashboard-options
type: comparison
topic: 2026-10-21-dashboard-options
verdict: VALIDATED
tags: [dashboard, ui, coreui, air-gap, dark-mode]
---

# Prototype 001: Opening Dashboard Options (3-way)

## What This Validates

> Given the CoreUI shell, the DESIGN.md decisions, and the frontend/STYLEGUIDE.md pieces,
> when three opening-dashboard layouts are rendered as static HTML against the **installed**
> CoreUI CSS (no CDN, no build), then each renders as a coherent, themeable (light + dark),
> air-gapped operator screen that obeys the style guide — proving the three directions are
> all *buildable* before committing to one.

This is a **comparison** prototype: one question ("which opening dashboard do we build?")
answered by three variants built back-to-back. The real risk is not "does React render a
table" (known) but whether each *information layout* works inside the locked constraints —
one shadowed card per page, status as badges, color from CoreUI only, no second accent,
air-gapped (ADR-0020), and the two-row header with the page action in TopMenu.

## Research

No new dependency. The constraint set is local and already locked:

| Source | Constraint it enforces |
|--------|------------------------|
| `DESIGN.md` | CoreUI shell; one card + one title per page; status = badge; no second accent/font/marketing layout; 4.1 screens are the visual reference |
| `frontend/STYLEGUIDE.md` | Two-row header (page action in row 2 / `TopMenu`); `CCard shadow mb-4`; icon-only header action with `aria-label`+`title`; row action = icon with verb tooltip; loading/empty/error inline in card body; `text-primary fw-bold` card title |
| ADR-0005 / ADR-0020 / ADR-0023 | CoreUI stack; air-gap (no CDN); DataTables for lists |
| ADR-0009 | SSE is the push channel (feeds the "Live" option) |

**Chosen approach:** three static HTML files using the *installed* CoreUI CSS via a relative
`<link>` — identical to how `frontend/style-guide.html` is already rendered. No bundler, no
React, hardcoded sample data. This is the shortest path to something the user can open, feel,
and compare, and it is exactly the reference the style guide already uses.

## How to Run

Open each file directly in a browser (the CSS is local, so no server is required):

```bash
open .skillgrid/prototypes/001-dashboard-options/dashboard-1-41.html
open .skillgrid/prototypes/001-dashboard-options/dashboard-2-watch.html
open .skillgrid/prototypes/001-dashboard-options/dashboard-3-atlas.html
```

Toggle Light/Dark with the buttons in the top-right of each page. The stylesheet resolves to
`frontend/node_modules/@coreui/coreui/dist/css/coreui.min.css` (CoreUI 5.9.1).

## What to Expect

Each page shows the KubeDash shell: a two-row header (shared row with namespace/cluster
selector + theme toggle; page row with breadcrumb + an icon-only Refresh), then one shadowed
card with a `text-primary fw-bold` title.

- **dashboard-1-41.html** — "Cluster Metrics": a quiet cluster-status strip above 4.1's metric
  tiles (CPU / Memory / Storage / Pods) and a node table. Expect status badges, a progress
  bar per tile, and a NotReady node flagged `secondary`.
- **dashboard-2-watch.html** — "Watchboard": a live SSE event feed, newest first. Expect
  severity badges (`danger`/`warning`/`secondary`), a "Live · SSE" badge, and a footer count.
- **dashboard-3-atlas.html** — "Cluster Atlas": a namespace × resource-kind matrix. Expect
  subtle colored cell fills as a heat map, link cells to the list pages, and a "Problems" column.

A failure would be: transparent/missing badges, no card shadow, a second accent color, a CDN
request, or a page that breaks in dark mode.

## Variants (head-to-head)

| # | File | Concept | Data shape | Best for | Risk |
|---|------|---------|------------|----------|------|
| 1 | `dashboard-1-41.html` | 4.1 Cluster Metrics (tiles + node table) | per-node utilization | the "what's the cluster doing" operator | lowest — closest to the locked reference |
| 2 | `dashboard-2-watch.html` | Watchboard (live event feed) | recent k8s events, newest first | the "what just broke" operator | medium — leans on SSE (ADR-0009); needs an events source |
| 3 | `dashboard-3-atlas.html` | Cluster Atlas (namespace × kind matrix) | counts per namespace per kind | the "where should I look" operator | low-medium — matrix density; needs a summary endpoint |

## Investigation Trail

- **Attempt 1 — first render (files under `frontend/mockups/`):** opened in Chromium. Computed
  styles showed `cardShadow: true`, `titleColor: rgb(88,86,214)` (CoreUI primary), badge
  `rgb(27,158,62)` (CoreUI success). Looked correct. **But this was misleading** — see Attempt 3.
- **Attempt 2 — air-gap check:** `performance.getEntriesByType('resource')` → **0 external
  requests** on all three pages (everything `file://`). ADR-0020 holds.
- **Attempt 3 — the real bug (relative CSS path):** after moving the files to
  `.skillgrid/prototypes/001-dashboard-options/`, the `<link href="../node_modules/...">` path
  resolved to `.skillgrid/prototypes/node_modules/...` — a **nonexistent** CoreUI. The page
  silently fell back to browser defaults: badges `rgba(0,0,0,0)`, no card shadow, black title.
  Cross-check against `frontend/style-guide.html` (same browser, same CSS) returned green
  `rgb(34,151,65)` badges — proving the file was right and the *path* was wrong.
- **Attempt 4 — path fix, first try (`../../frontend/...`):** still unstyled. `ls` showed the
  path was one level short — from `001-dashboard-options/` you must go up **three** levels to
  reach `frontend/`. Corrected to `../../../frontend/node_modules/...`.
- **Attempt 5 — final verification (all three, light + dark):**
  - Option 1: badge `rgb(27,158,62)`, card shadow present, title `rgb(88,86,214)`.
  - Option 2: danger `rgb(229,83,83)`, warning `rgb(249,177,21)`, card shadow present, 8 rows.
  - Option 3: heat fills `rgba(229,83,83,0.1)` / `rgba(249,177,21,0.1)` / `rgba(27,158,62,0.1)`,
    card shadow present. Dark mode: body `rgb(29,34,43)`, card `rgb(33,38,49)`, title
    `rgb(94,92,208)`, heat fill `rgba(222,90,90,0.1)` — **all recompute correctly via the
    `--cui-*-rgb` tokens**, no one-off hex.
- **Edge case exercised (dark mode):** Option 3's `!important` subtle fills still compute from
  the CoreUI tokens in dark (not frozen light values), so the heat map adapts. The `!important`
  is required because CoreUI's `.table>:not(caption)>*>*` sets `--cui-table-bg` on every cell.

## Results

**Verdict:** VALIDATED ✓ (comparison — winner is the user's call; all three are buildable)

**Evidence:** Computed-style captures above (light + dark) from Chromium against the installed
CoreUI 5.9.1. Air-gap: 0 external resource requests per page. The "transparent badge" failure
was caught by computed-style inspection, not by looking — which is exactly why the path bug was
real and is now fixed.

**Surprises:**
1. A relative CSS path that "works" in one directory can silently break in another, and the
   page degrades to *unstyled* (not an error) — the symptom is subtle (white cards, black text),
   easy to miss in a screenshot-only review. Verified via `document.styleSheets[0].href`.
2. CoreUI's `text-bg-*` badge classes are real fills here (5.9.1) — the earlier "ghost badge"
   reading was an artifact of the broken path, not the library. No change needed to the badge
   markup.

**Constraints for the build (when one option is chosen):**
- The stylesheet is loaded from `frontend/node_modules/...` for the mockup only. The real view
  is a React component under `frontend/src/views/`, so the CSS is already part of the bundle —
  no CDN, and the mockup's `<link>` does not carry over.
- Option 2 needs an **events source**. There is no events endpoint in `backend/app/api/` yet
  (only the stub `metrics.py`). It must either read the informer cache (ADR-0010) or add an
  events API. The "Live · SSE" badge is aspirational until SSE events are wired.
- Option 3 needs a **per-namespace, per-kind count** summary. The generic
  `GET /clusters/<id>/resources/<kind>` exists (`resources.py`) but there is no one-call
  matrix endpoint; the build either fans out N queries or adds a summary route.
- Option 1's metric tiles need the **metrics query** endpoint, which is still
  `501 NOT_IMPLEMENTED` (`metrics.py`, ADR-0003). The node table can be backed by the existing
  resources endpoint.

## Signal for the Build

- **What to use:** the three HTML files as visual/structural reference; the two-row header and
  single-shadowed-card layout are already correct in all of them.
- **What to avoid:** a relative CSS `<link>` in the final view (it's bundled). Don't add a
  second accent color or a marketing hero — all three variants keep chrome quiet per DESIGN.md.
- **What to watch out for:** whichever option is picked, the *data source* is the real work,
  not the layout. Options 2 and 3 each imply a new backend surface (events / summary matrix);
  Option 1 is the cheapest to stand up because the node list already exists.
- **Decision needed:** the prototype proves all three are buildable; it does **not** pick the
  winner. The user must choose a direction (or a mix, e.g. Option 1 + Option 2 as tabs) before
  `skillgrid:writing-blueprints`.
