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
| C | `dashboard-c-41-donut.html` | **donut** charts (CPU / Memory / Pods) + **capacity/requests/limits bars** + **overcommit flag** + allocation summary table | bordered table (same as A/B) | UMD | the 4.1 donut look, most faithful to the original |

> **Revision 1 (2026-10-22):** C was originally a "mission control" layout (half-gauges + a pods
> donut + an events **timeline**). The user judged that the *most similar to the 4.1 original* is
> the donut style, so C was revised: gauges → **donut** charts (CPU/Mem/Pods, center % label, the
> 4.1 donut idiom), and the events **timeline** → the **same bordered table** used by A/B. The
> revised file is `dashboard-c-41-donut.html` (the old `dashboard-c-mission-control.html` was
> removed). A and B are unchanged.
>
> **Revision 2 (2026-10-22):** the user wanted more than used/free on CPU and Memory — **requests
> and limits**, and a way to see **overcommit**. First cut added bars + an allocation table.
>
> **Revision 3 (2026-10-22):** the user wanted **only two rows** — row 1 charts, row 2
> events — and **multi-line donut charts** (not bars). First cut used *stacked segments in one
> ring*; the user said that was **not** the 4.1 look.
>
> **Revision 4 (2026-10-22):** "multi-line" = **concentric rings** (the 4.1 radial-gauge idiom).
> First cut used `data.flat()` in ONE dataset — that draws **stacked arcs in a single ring**, not
> parallel rings. Wrong.
>
> **Revision 5 (2026-10-22, final C):** true concentric multi-line donut = **three datasets** (one
> per ring) in a single Chart.js doughnut, same center, **different radii** (verified
> `outerRadius` 110/92/73). C is now: **row 1** = CPU / Memory as **three parallel rings** on ONE
> capacity scale — outer = **limits**, middle = **requests**, inner = **used** (each ring = that
> value's % of capacity; a ring filled to 100% = at/past capacity). Plus the **Pods** donut
> (running / pending / completed / free). **Row 2** = the same bordered events table. The overcommit
> signal is the **requests ring**: when requests exceed capacity that ring is fully filled and the
> legend/badge carry the over-capacity amount (Memory requests 150% → overbooked). Encoded
> distinction holds: **overcommit = requests vs capacity** (the real risk); **limits > 100% is burst
> headroom**, not overcommit. Sample: CPU requests 98% (ok), Memory requests **150% (overbooked)**.
> Reusable idiom for the build: 3-dataset doughnut + a `centerText` plugin for the center label.
>
> **Revision 6 (2026-10-22, final C):** overcommit color model. One base hue per resource —
> **CPU = blue**, **Memory = amber** (a different hue) — and **Used / Requests / Limits are
> progressively darker tones** of that hue (alpha 1.0 / 0.7 / 0.45) on a gray track. Because a
> donut ring's full 360° **is** 100% of capacity, the part of a value **over 100% cannot be drawn
> in the ring** (the user picked "donut + separate red overflow bar"): a thin **red bar** under each
> donut is filled proportionally to the amount over capacity (e.g. Memory requests +50% → red bar 50%;
> limits +80%). The bar uses the CoreUI danger token (no new color). The ring arcs cap at 100%
> (at/past capacity = full ring). Sample: CPU requests 98% (ok, limits +15% red), Memory requests
> **150%** (overbooked, requests +50% / limits +80% red).

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
- **C** — **two rows**: row 1 = CPU / Memory as **concentric multi-line donuts** (three rings on one
  capacity scale: **limits / requests / used**, the 4.1 radial-gauge idiom — overcommit = the
  requests ring exceeding capacity) + a **Pods** donut (running/pending/completed/free); row 2 = the
  **same bordered events table** as A/B. Most faithful to the 4.1 original.

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
- **Edge case — C revision 3 (2026-10-22):** collapsed to two rows (charts / events); donuts became
  **multi-segment** (used/requests/limits stacked; Pods = running/pending/completed/free). Verified:
  `canvasCount:3`, `allDrew:true`, events is the bordered table, overcommit badges render
  ("Requests 98% · ok" / "Requests 150% · overbooked"), 0 external requests — light **and** dark.
- **Edge case — C revision 4 (2026-10-22):** first concentric attempt used `data.flat()` in one
  dataset — rendered as **stacked arcs in a single ring** (6 segments), not parallel rings. The user
  correctly rejected it ("still not parallel donuts with the same center").
- **Edge case — C revision 5 (2026-10-22):** switched to **3 datasets** (one per ring).
  Verified via `Chart.getChart('donut-cpu')`: `datasetCount:3`, per-ring `outerRadius` = **110 / 92 /
  73** (three distinct radii, same center — true concentric); `allDrew:true`; events is the bordered
  table; 0 external requests — light **and** dark.
- **Edge case — C revision 6 (2026-10-22, final):** overcommit color model. CPU = blue, Memory =
  amber; Used/Requests/Limits = darker tones (alpha 1.0/0.7/0.45) of the resource hue. The ring caps
  at 100% of capacity (360°), so the **over-100% part is a separate RED overflow bar** (proportional
  to the amount over capacity), CoreUI danger token. Verified via `Chart.getChart`: `cpuRadii
  [100,83,67]`, `cpuUsedFill rgba(22,92,255,1)` vs `cpuLimFill rgba(22,92,255,0.45)` (blue tones),
  `memLimFill rgba(249,177,21,0.45)` (amber — distinct hue), `cpuOverflowBar 15%`
  (`limits +15%`), `memOverflowLabel "requests +50% · limits +80%"`, overflow bar `rgb(222,90,90)`
  (danger) — light **and** dark.
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
  redraw on theme change; (3) `@coreui/chartjs` is ESM-only — import it, don't script-tag it;
  (4) the overcommit math (Σ requests ÷ capacity) needs a **new backend aggregate** — the
  `resources/<kind>` endpoint lists objects but does not sum `spec.containers[].resources.requests/limits`
  against `status.capacity`; the build must add a cluster-allocation rollup (and the certainty rule
  applies: if a pod has no requests, it contributes 0 to the requests sum, and a metric with no
  source renders unknown, not 0).
- **Decision needed:** the prototype does not pick the winner. Choose A (minimal, CoreUI-only) /
  B (4.1 + line trend) / C (mission control) before `skillgrid:writing-blueprints`.
