---
prototype: 002
name: cluster-dashboard
type: comparison
topic: 2026-10-21-cluster-dashboard
verdict: VALIDATED
tags: [dashboard, cluster-metrics, events, chartjs, coreui, air-gap, dark-mode]
---

# Prototype 002: Cluster Dashboard (metrics + events) — 3-way

## What This Validates

> Given the CoreUI shell, the STYLEGUIDE pieces, the vendored Chart.js UMD (air-gapped), and
> the certainty rule, when three "cluster dashboard" layouts (cluster metrics + events) are
> rendered as static HTML against the **installed** CoreUI CSS, then each renders as a coherent,
> themeable (light + dark), air-gapped operator screen — proving all three directions are
> buildable before committing to one.

This is a **comparison** prototype answering one question ("which cluster-dashboard layout do we
build?"). The three variants differ only in the *metrics* visualization:

| # | File | Metrics viz | Events viz | Chart.js | Best for |
|---|------|-------------|------------|----------|----------|
| A | `dashboard-a-coreui.html` | CoreUI built-in (border tiles + `progress` bars) | bordered table | **none** | minimal dependency; fastest to ship |
| B | `dashboard-b-chartjs-41.html` | 4.1 tiles + a **line chart** (CPU/Mem, 1h) | bordered table | UMD | the 4.1 look with real trend history |
| C | `dashboard-c-41-donut.html` | **donut** charts (CPU / Memory / Pods) with center % (4.1 donut style) | bordered table (same as A/B) | UMD | the 4.1 donut look, most faithful to the original |

> **Revision (2026-10-22):** C was originally a "mission control" layout (half-gauges + a pods
> donut + an events **timeline**). The user judged that the *most similar to the 4.1 original* is
> the donut style, so C was revised: gauges → **donut** charts (CPU/Mem/Pods, center % label, the
> 4.1 donut idiom), and the events **timeline** → the **same bordered table** used by A/B. The
> revised file is `dashboard-c-41-donut.html` (the old `dashboard-c-mission-control.html` was
> removed). A and B are unchanged.

The real risk is not "does a canvas draw" but whether each layout holds inside the locked
constraints: one shadowed card per *task* (metrics and events are two tasks → two cards is legal),
status as badges, color from CoreUI tokens only, air-gap (ADR-0020), and — critically — the
**certainty rule** (a metric with no source renders `unknown`, never `0`/healthy tone).

## Research

- **Chart.js is already vendored** (no new dependency): `chart.js@^4.5.1`, `@coreui/react-chartjs`,
  `@coreui/chartjs` are in `frontend/package.json`. The UMD build
  (`node_modules/chart.js/dist/chart.umd.min.js`) loads via a plain `<script>` for the mockups —
  the same library `react-chartjs-2` wraps in the real build.
- **`@coreui/chartjs` is ESM-only** (no UMD global), so it cannot be used in a static `<script>`
  mockup. That is why **Option A** uses CoreUI's *native* primitives (border + `progress`), which is
  the honest "built-in CoreUI" interpretation. (In the real React build, A could use `CWidget*`
  from `@coreui/react`; the mockup just can't load that via script tag.)
- **CoreUI 5.9 has no `c-widget`/`c-statistic` components** (that was the CoreUI 4 widget kit).
  Verified by scanning the installed CSS — so the stat tiles are built from `border` + `progress`
  divs, not a named widget.

**Chosen approach:** three static HTML files, local CoreUI CSS + local Chart.js UMD (B, C), hardcoded
sample data. Shortest path to something the user can open, feel, and compare — identical to how
`frontend/style-guide.html` and prototype 001 render.

## How to Run

```bash
open .skillgrid/prototypes/002-cluster-dashboard/dashboard-a-coreui.html
open .skillgrid/prototypes/002-cluster-dashboard/dashboard-b-chartjs-41.html
open .skillgrid/prototypes/002-cluster-dashboard/dashboard-c-mission-control.html
```

Toggle Light/Dark top-right. CSS/JS resolve to `frontend/node_modules/...` (CoreUI 5.9.1,
Chart.js 4.5.1). No server required.

## What to Expect

Each page: two-row header (page action in row 2), a quiet cluster-status strip, then:
- **A** — one metrics card (four `border` tiles + progress; Storage = **unknown**) + one events
  card (bordered table, severity badges, "Live · SSE"). No canvas.
- **B** — four 4.1 tiles + a **line chart** (CPU % + Memory % over 1h) + events table.
- **C** — three **donut** cards (CPU / Memory / Pods, each with a center % label — the 4.1 donut
  idiom) + the **same bordered events table** as A/B. Most faithful to the 4.1 original.

A failure would be: a canvas that doesn't draw, a chart that breaks in dark mode, a second accent
color, a CDN request, or a metric with no source shown as `0`.

## Investigation Trail

- **Attempt 1 — render check (light):** all three load CoreUI (card shadow present, title
  `rgb(88,86,214)` primary, success badge `rgb(27,158,62)`). A: `canvasCount: 0`, `unknownShown:
  true`, 0 external requests. B: 1 canvas, `chartDrew: true`, `Chart` defined. C: 3 canvases,
  `allDrew: true`, 5 timeline items. **All air-gapped** (0 external resource requests per page —
  the Chart.js UMD is `file://`).
- **Attempt 2 — air-gap + dependency check:** `performance.getEntriesByType('resource')` filtered
  to non-`file://` → **0** on all three. Confirmed `chart.js` + `@coreui/react-chartjs` already in
  `package.json` (no new dependency, ADR-gate not triggered).
- **Edge case — dark mode (B):** toggled dark → `bodyBg rgb(29,34,43)`, chart redraws with
  theme-aware grid/tick colors, still drawn. ✔
- **Edge case — dark mode (C, revised):** toggled dark → all 3 donuts still drawn; the center %
  text color follows `getComputedStyle(document.body).color` (light→dark), so "41%"/"63%" stay
  legible; events table + `text-bg-danger` badge recompute to the dark danger tone
  (`rgb(222,90,90)`). ✔
- **Edge case — C revision (2026-10-22):** gauges replaced by donuts (same center-text plugin,
  `cutout:'68%'`), events timeline replaced by the A/B bordered table. Verified: `canvasCount:3`,
  `allDrew:true`, `eventsIsTable:true`, `timelineGone:true`, 0 external requests — light **and** dark.
- **Surprise:** `@coreui/chartjs` ships **ESM only** — no `window.` global — so it can't back a
  static mockup. Option A therefore uses CoreUI *native* primitives, which is exactly what
  "built-in CoreUI" means. (The real build can use `CWidget*`; the mockup can't via script tag.)
- **Surprise:** CoreUI 5.9 dropped the v4 `c-widget`/`c-statistic` component classes (CSS scan:
  absent). Stat tiles are built from `border` + `progress`, not a named widget.

## Results

**Verdict:** VALIDATED ✓ (comparison — all three buildable; winner is the user's call)

**Evidence:** computed-style + canvas-draw captures (light + dark) from Chromium against installed
CoreUI 5.9.1 + Chart.js 4.5.1. Air-gap: 0 external requests per page. Certainty rule honored:
Storage tile shows the word **unknown** (no source), never `0`.

**Surprises:** ESM-only `@coreui/chartjs`; CoreUI 5.9 has no v4 widget classes (both recorded above).

**Constraints for the build:**
- The mockups' `<link>`/`<script>` to `frontend/node_modules/...` do **not** carry into the real
  view (it's a bundled React component). In the build, B/C use `react-chartjs-2` (already a dep) or
  `@coreui/react-chartjs`; A uses CoreUI primitives / `CWidget*`.
- **Events need a source.** There is no events endpoint in `backend/app/api/` yet — it must read the
  informer cache (ADR-0010) or add an events API. "Live · SSE" (ADR-0009) is aspirational until SSE
  events are wired.
- **Metrics source** is the ratified `metrics.k8s.io` (query-only, ADR-0003) — see the cluster-node
  change's `adr.md`. Storage has **no** metrics.k8s.io source → stays `unknown`.
- Charts must be **theme-aware**: register grid/tick/legend colors from CoreUI tokens and
  redraw on color-mode change (the mockups do this; the real build must too, or charts go gray-on-gray
  in dark mode).

## Signal for the Build

- **What to use:** the three HTML files as visual/structural reference. All three already respect the
  two-row header, single-shadowed-card-per-task, badge status, and the certainty rule. C (revised) is
  the 4.1-faithful donut layout; its center-text donut pattern (the `centerText` Chart.js plugin +
  `cutout:'68%'`) is the reusable idiom for the real build.
- **What to avoid:** a relative CSS/JS `<link>`/`<script>` in the final view (bundled). Don't add a
  second accent color or a marketing hero.
- **What to watch out for:** (1) events endpoint is the real work, not the layout; (2) charts must
  redraw on theme change; (3) `@coreui/chartjs` is ESM-only — import it, don't script-tag it.
- **Decision needed:** the prototype does not pick the winner. Choose A (minimal, CoreUI-only) /
  B (4.1 + line trend) / C (mission control) before `skillgrid:writing-blueprints`.
