# Findings — dashboard-options

Consolidated contract for `skillgrid:writing-blueprints`. Each section is a prototype or
sketch verdict; the blueprint reads this file, it does not re-run the experiment.

## Prototype: 001-dashboard-options

- **Verdict:** VALIDATED ✓ (comparison — 3 variants, all buildable; winner is the user's call)
- **What we learned:**
  - All three opening-dashboard layouts (4.1 Cluster Metrics / Watchboard event feed /
    Cluster Atlas matrix) render correctly inside the locked CoreUI constraints — one shadowed
    card, status as badges, color from CoreUI tokens only, air-gapped, light + dark.
  - **Gotcha:** a relative CSS `<link>` path that works in one directory silently breaks in
    another and degrades the page to *unstyled* (white cards, black text) with no error.
    Always verify `document.styleSheets[0].href` points at the installed CoreUI.
  - CoreUI 5.9.1 `text-bg-*` badge classes are real fills (not ghost). Subtle heat-map cell
    fills need `!important` because CoreUI's `.table>:not(caption)>*>*` sets `--cui-table-bg`.
- **What's liftable:** the three HTML files at `prototypes/001-dashboard-options/` as
  visual/structural reference. No pure module to lift — this is a layout comparison, not a
  state machine.
- **Constraints for the build:**
  - The mockup's `<link>` to `frontend/node_modules/...` does **not** carry into the real view
    (it's a bundled React component under `frontend/src/views/`). No CDN.
  - **Option 1 (4.1 metrics):** cheapest — node list exists via `resources.py`. Metric tiles
    need `metrics.py`, still `501 NOT_IMPLEMENTED` (ADR-0003).
  - **Option 2 (Watchboard):** needs an **events source** — no events endpoint exists yet.
    Must read the informer cache (ADR-0010) or add an events API. "Live · SSE" (ADR-0009) is
    aspirational until SSE events are wired.
  - **Option 3 (Atlas):** needs a **per-namespace × per-kind count** summary. Generic
    `resources/<kind>` exists but there is no one-call matrix endpoint.
- **Decision needed:** the prototype does not pick the winner. Choose a direction (or a mix,
  e.g. Option 1 + Option 2 as tabs) before authoring the blueprint.
