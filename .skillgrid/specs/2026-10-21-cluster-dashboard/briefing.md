# Cluster Dashboard — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-21-cluster-dashboard`
**Date:** 2026-10-22
**Winner:** **Option C** from `../../prototypes/002-cluster-dashboard/` (concentric multi-line
donuts + overcommit color model + events table). A and B are rejected.

## Intent

Operators open KubeDash and need to answer, in seconds, **"is this cluster healthy, and is it
overcommitted?"** — before they click into any resource list. The dashboard is the first screen;
it must show cluster-wide **metrics** (CPU, Memory, Pods) with an explicit **overcommit** signal,
plus a live **events** feed of what just went wrong. It is a *read* surface: no create, no mutation.

## Reference

The visual reference is the prototype `../../prototypes/002-cluster-dashboard/dashboard-c-41-donut.html`
(Option C, final revision 6). The blueprint cites it; it does not restate the look. Key properties of
the winner (all carried into the build):

- **Two rows.** Row 1 = charts (CPU / Memory / Pods). Row 2 = events.
- **Concentric multi-line donuts** for CPU and Memory: three rings of different radius sharing one
  center — outer = **Limits**, middle = **Requests**, inner = **Used** — all on one capacity scale.
- **One hue per resource** (CPU = blue, Memory = amber). Used/Requests/Limits are **progressively
  darker tones** of that hue on a gray track.
- **Overcommit = the over-100% part, in red.** A donut ring's 360° is 100% of capacity, so a value
  over capacity caps the ring at full and the **over-capacity amount is a red overflow bar**
  (proportional to `max(0, value − capacity)/capacity`). The bar uses the CoreUI danger token — no
  new color.
- **Pods** is a single multi-segment donut (running / pending / completed / free).
- **Events** is a bordered table (Time / Severity / Object / Namespace / Reason / Message / Count),
  newest first, with a "Live · SSE" badge.
- **Certainty rule (AGENTS.md):** a value KubeDash cannot read is never `0` or a healthy tone — it
  is **unknown** and says why. Declared (requests/limits) vs observed (used) get distinct labels.

## Requirements

### R1 — Cluster metrics (CPU, Memory, Pods)
For the selected cluster, show, for CPU and Memory: **capacity**, **used** (observed),
**requests** (declared), **limits** (declared). For Pods: **capacity**, **running**, **pending**,
**completed**. Data comes from the K8s API through the registry credentials (query-only, ADR-0003):
capacity from node `status.capacity`, used from the **Metrics API** (`metrics.k8s.io`), requests and
limits summed from pod `spec.containers[].resources`. This requires a **new cluster-allocation
rollup** the current `resources/<kind>` endpoint does not provide.

### R2 — Overcommit visualization
Render requests and limits as overcommit signals. **Overcommit = Σ requests ÷ capacity** (the real
risk). Limits over 100% is burst headroom, *not* overcommit — label them distinctly. The over-capacity
amount is shown in red (overflow bar + badge). A metric with no source (e.g. metrics-server absent,
or no storage source) renders **unknown**, never `0`.

### R3 — Events
Show recent cluster events, newest first, with severity, object, namespace, reason, message, and
count. Backed by the informer cache (ADR-0010) or a new events source; "Live · SSE" (ADR-0009) is the
push channel. An event source does not exist yet — this is part of the build.

### R4 — Layout & shell
Two-row dashboard (charts / events) inside the CoreUI shell: two-row header (page action in `TopMenu`
row), cluster selector, theme toggle. One shadowed card per task; status as badges; color from CoreUI
tokens only. No second accent, no webfont, no CDN (air gap, ADR-0020).

### R5 — Themes
Light + dark must both work, including the charts (Chart.js grid/tick/legend colors from CoreUI
tokens; redraw on color-mode change) and the red overflow bar (CoreUI danger token).

## Non-goals (this change)
- No per-node drill-down table (that is the separate `2026-10-21-cluster-node` change).
- No storage metric (no metrics.k8s.io source → **unknown**).
- No mutation actions on the dashboard (read surface).
- No per-namespace breakdown (cluster-wide only; that is a future option).

## Success criteria
- An operator can see, at a glance, whether the cluster is overcommitted (requests vs capacity) and
  what just went wrong (events) — without opening any resource list.
- A cluster with no metrics-server still renders (used = unknown, requests/limits still shown from
  declared specs) — no red error, no `0`.
- Both themes render correctly.
