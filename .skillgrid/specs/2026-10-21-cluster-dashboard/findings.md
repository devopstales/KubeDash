# Findings — cluster-dashboard

Consolidated contract for `skillgrid:writing-blueprints`. Each section is a prototype or sketch
verdict; the blueprint reads this file, it does not re-run the experiment.

## Prototype: 002-cluster-dashboard

- **Verdict:** VALIDATED ✓ (comparison — 3 variants, all buildable; winner is the user's call)
- **What we learned:**
  - All three cluster-dashboard layouts (CoreUI built-in / Chart.js 4.1 + line trend / 4.1-faithful
    donuts + events table) render correctly inside the locked CoreUI constraints — one shadowed card
    per task, status as badges, CoreUI tokens only, air-gapped, light + dark.
  - **C revised (2026-10-22):** the user judged the donut style most similar to the 4.1 original.
    C's gauges → **donut** charts (CPU/Mem/Pods, center % label), events timeline → the **same
    bordered table** as A/B. File renamed `dashboard-c-mission-control.html` →
    `dashboard-c-41-donut.html`. The center-text donut idiom (`centerText` Chart.js plugin +
    `cutout:'68%'`) is the reusable pattern for the real build.
  - **C revised again (2026-10-22, final):** the user wanted **requests + limits + overcommit**,
    rendered as **concentric multi-line donuts** (the 4.1 radial-gauge idiom — three parallel rings),
    in a **two-row** layout (row 1 charts, row 2 events). CPU/Memory = 3 rings on ONE capacity scale
    (outer limits / middle requests / inner used); Pods = a single multi-segment donut. Overcommit =
    the **requests ring** exceeding capacity. Encoded distinction: **overcommit = requests ratio**
    (the real risk); **limits > 100% is expected burst headroom, not overcommit**. The real build
    needs a **new cluster-allocation rollup** endpoint (sum `spec.containers[].resources.requests/limits`
    vs `status.capacity`) — the current `resources/<kind>` endpoint does not aggregate.
  - **Chart.js is already vendored** (`chart.js`, `@coreui/react-chartjs`, `@coreui/chartjs` in
    `package.json`) — no new dependency, ADR gate not triggered. The UMD build loads via script tag
    for mockups; the real build uses `react-chartjs-2` / `@coreui/react-chartjs`.
  - **Gotcha:** `@coreui/chartjs` is **ESM-only** (no UMD global) — it cannot back a static
    `<script>` mockup. The "built-in CoreUI" option (A) therefore uses CoreUI *native* primitives
    (border + `progress`), which is the honest interpretation.
  - **Gotcha:** CoreUI 5.9 has **no** `c-widget`/`c-statistic` classes (v4-only). Stat tiles are
    built from `border` + `progress` divs.
  - **Gotcha:** charts must be **theme-aware** — grid/tick/legend colors from CoreUI tokens and a
    redraw on color-mode change, or they go gray-on-gray in dark mode.
  - Certainty rule honored in all three: the Storage tile shows **unknown** (no metrics.k8s.io
    source), never `0`.
- **What's liftable:** the three HTML files at `prototypes/002-cluster-dashboard/` as
  visual/structural reference. No pure module (layout comparison, not a state machine).
- **Constraints for the build:**
  - Mockup `<link>`/`<script>` to `frontend/node_modules/...` does not carry into the real (bundled)
    view. No CDN.
  - **Events need a source** — no events endpoint exists yet; read the informer cache (ADR-0010) or
    add an events API. "Live · SSE" (ADR-0009) aspirational until wired.
  - **Metrics source** = ratified `metrics.k8s.io` (query-only, ADR-0003; see
    `../2026-10-21-cluster-node/adr.md`). Storage has no source → stays `unknown`.
- **Decision needed:** the prototype does not pick the winner. Choose A / B / C before authoring
  the blueprint.
