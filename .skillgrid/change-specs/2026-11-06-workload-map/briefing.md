# Briefing — Workload Map 5.0 (4.1 base + connections + network policies)

> **STATUS:** `draft` (2026-11-06)

**Change:** `2026-11-06-workload-map`
**Date:** 2026-11-06
**Trigger:** user request (2026-11-06) — "create a new spec for
`/dashboard/workload-map` [with] the 4.1 for as the base but propose update
on it based on radar. I want it to show not just components but there
connections and network policies." Named sources: the networkpolicy.io
editor example (`?id=RgXOI5C6IaJEVe4l`), `oslabs-beta/navigate`,
`alfiyansys/scope`. Research evidence: `findings.md` in this folder.

## What 4.1 has (the base)

Verified against branch `4.1` (findings.md [1]):

- **Chrome (carried over):** card + filter menu (item `edge`/`node` →
  property → multi-value TomSelect → Filter/Reset highlight), vis.js
  hierarchical graph (UD, per-kind levels, kind-icon SVG nodes), rich
  hover tooltip (kind badge, name, namespace, Ready/Partial/Not Ready
  `ready/desired` badge, available, age, image, owner), legend footer,
  dark/light theming, CSP nonces.
- **Interaction (carried over, 5.0-adapted):** namespace-scoped via the
  topbar selector (reload on change); click → object navigation (4.1:
  kind list routes; 5.0: ADR-0040 object ref → the object's data view).
- **Data (the gap):** `k8sGetPodMap` returns workload nodes
  (Deployment/StatefulSet/DaemonSet/ReplicaSet, `desired != 0` only) and
  **one edge class — ownership (workload→ReplicaSet)**. Pod layer
  commented out. **No Services, no connections, no NetworkPolicies.**

## Proposed update (radar-informed)

The 4.1 page and rendering base stay; the data model becomes three layers
(findings.md, Cross-Dimension Insights):

- **L0 — Ownership** (4.1, carried over): workloads → ReplicaSets, node
  status fields as in 4.1. Pods stay **badges on nodes** (pod count /
  ready), not nodes — 4.1 itself disabled the pod layer (scale).
- **L1 — Connections** (new): Service nodes in the namespace;
  workload→Service edges derived by **selector matching** (Service
  `spec.selector` ⊆ workload pod-template labels — navigate's
  `findSelectorMatch` core [findings.md 2]); Service→Service edges from
  **NetworkPolicy peer declarations** (the declared-intent view).
- **L2 — Network-policy overlay** (new, the user's ask): each L1 edge gets
  a policy state — `allowed` (an explicit permit matches), `denied`
  (namespace default-deny present, no permit matches), `unknown`
  (heuristic boundary: mixed policies / insufficient visibility);
  namespace badges for default-deny ingress/egress; **issues strip**:
  Service whose selector matches no pods ("no endpoints" — radar's issue
  [findings.md 5]), policy whose podSelector matches no pods (orphan),
  workload whose declared peer is denied. Clicking a policy reference
  opens the existing network-policy data view (ADR-0040 object ref;
  2026-10-26 surface).
- **Two view modes** (radar's split): **Resources** (L0+L1) and
  **Traffic** (L1+L2). Grouping: namespace (cluster-wide view) or app
  label (`app.kubernetes.io/name`, fallback `app`); filter by kind.
- **Focus** (radar's `get_neighborhood` pattern): click a node →
  2-hop neighborhood around it; click background/Reset → full graph.
  Under ADR-0040 the focus is session state (object ref), not URL —
  radar's shareable-focus is dropped, recorded.
- **Observed traffic: banner, not yet.** No Hubble/Istio/Beyla
  integration in v1 — the Traffic view shows declared edges and an
  explicit banner: "Observed traffic not available — requires a network
  observation source (phase 2)." Radar's principle: say so rather than
  show partial edges silently [findings.md 5].
- **Live:** SSE (ADR-0009) pushes graph-refresh on cache updates
  (throttled, e.g. 2s debounce; the read path never re-queries K8s).
- **Read path + API contract:** graph builder is a **pure service over
  the informer cache** (ADR-0010) — no per-request K8s calls; the service
  is the one the future MCP `get_topology`/`get_neighborhood` tools will
  share (2026-11-06-mcp-server findings). Endpoint response carries the
  evidence contract: `{nodes, edges, policyFindings, coverage:
  {missingInputs, truncated, degraded[]}}`; before initial sync it
  returns the `cluster_connecting`-equivalent error, not an empty graph
  (ADR-0003 degrade-never-500).

## Scope

- **Backend:** `app/services/workload_map.py` (pure, no Flask imports):
  node/edge assembly from the cluster informer cache — workloads
  (deployment/statefulset/daemonset/replicaset), services, ownership
  edges, selector-matched edges, core-`NetworkPolicy` evaluation
  (default-deny detection, permit matching, orphan detection), issues;
  node/edge cap with `truncated` marker. New Smorest route on the cluster
  domain: `GET /api/v1/clusters/<cluster_id>/workload-map?namespace=&mode=`
  — SAR-gated per kind (ADR-0004), scoped to the **selected cluster**
  (multi-cluster ADR-0002; 4.1's single-cluster assumption retired),
  per-user SAR via the existing permission layer. SSE topic for
  graph-invalidation on watched changes.
- **Frontend:** `views/Dashboard/WorkloadMap/` (view-folder convention):
  map canvas (vis-network via React integration — new dependency, own
  ADR), mode toggle (Resources/Traffic), filter menu (4.1 shape, extended
  to `service`/`networkpolicy` node kinds and `policyState`/`protocol`
  edge properties), node tooltip (4.1 field set + policy state on
  edges), issues strip, traffic-source banner, namespace/cluster
  switching from the existing topbar selectors. `_nav.tsx` entry stays
  (Beta badge until GA decision — user call, default: keep Beta); stub
  entry leaves `views/Stub/routes.ts`.
- **Wiring:** `App.tsx` route swap (stub → view); `Stub.test.tsx`
  viewPaths; `ui-smoke.spec.ts` moves the route from
  SMOKE_STUB_ROUTES to REAL_ROUTES; e2e smoke of both modes on the dev
  cluster.
- **Dev fixtures:** `dev/` demo-data gains a demonstrable policy set for
  the kind cluster: a default-deny ingress policy + permit rule (so the
  overlay shows allowed+denied+badges), one orphan policy (selector
  matches no pods), one no-endpoint Service — without them the overlay
  has nothing to say.

## Out of scope

- **Observed traffic sources** (Hubble/Istio/Caretta/Beyla integration,
  animated flow edges, req/s) — phase 2; v1 ships the banner.
- **CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy** in the
  overlay — phase 2 (the views exist; v1 evaluates core `NetworkPolicy`
  only, stated in the UI when Cilium kinds are present but unevaluated).
- **Policy authoring** (the networkpolicy.io editor is a *builder*;
  KubeDash's map is read-only — a builder is a separate future feature).
- **Pod-level nodes**, per-port evaluation (ports shown on edges, not
  evaluated), config/env-reference edge inference (v2), mutations of any
  kind.

## ADR gates (pre-code)

- **New frontend dependency** (map renderer — vis-network recommended for
  4.1 parity; MIT; must bundle for air-gap ADR-0020) → own ADR (next free
  number; 0041 if the mcp-server change takes it).
- No locked-ADR changes: ADR-0009 (SSE reused), ADR-0010 (cache read),
  ADR-0040 (object nav for click-through + focus), ADR-0020 (bundle only).

## Acceptance (falsifiable; BDD `acceptance.feature` authored at the acceptance-test-authoring phase)

- **R1 (route):** `/dashboard/workload-map` renders the map view, not the
  Stub; the nav entry (Beta badge) is unchanged; the stub route list and
  ui-smoke stub/real partitions are updated; e2e smoke passes for the
  route.
- **R2 (Resources mode):** for the selected cluster + namespace the map
  shows Deployment/StatefulSet/DaemonSet/ReplicaSet nodes with the 4.1
  tooltip fields (kind, name, namespace, Ready/Partial/Not Ready, image,
  owner) and workload→RS ownership edges; pod counts are node badges;
  clicking a node opens that object's data view via the ADR-0040 object
  ref — no object identity in the URL (referer/URL assertion in e2e).
- **R3 (Connections):** Traffic mode shows Service nodes and
  workload→Service edges **iff** the service selector matches the
  workload's pod-template labels; the negative case is asserted: a
  service with a non-matching selector gets no edge; a service whose
  selector matches no pods appears in the issues strip as "no
  endpoints".
- **R4 (Policy overlay):** a namespace with a default-deny ingress policy
  carries the badge; an edge to a denied peer renders state `denied` and
  a permitted one `allowed` (fixture-driven, both asserted); an orphan
  policy is listed; clicking a policy reference opens the
  network-policy data view.
- **R5 (Multi-cluster):** the map reflects the cluster switcher's
  selection; switching clusters reloads the graph (fixture: the dev kind
  cluster + a second registered cluster or the SAR-degraded path).
- **R6 (Coverage):** a kind the user cannot read (SAR-denied) is absent
  with its name in `coverage.missingInputs` — no 500; before initial sync
  the API returns the `cluster_connecting`-equivalent error; the view
  renders both degraded states.
- **R7 (Live):** scaling a workload on the dev cluster updates the map
  within the throttle window without a manual reload (SSE assertion in
  e2e or ui-smoke).
- **R8 (Scale cap):** exceeding the node/edge cap returns `truncated:
  true` and the view shows the count + reason (unit test on the builder
  with an over-cap fixture).
- **R9 (Air-gap):** `task fe-check` green; the renderer ships in the
  bundle (no external URLs).
- **R10 (Read path):** the endpoint is served from the informer cache —
  no direct K8s list calls per request (unit test with the fake cache;
  ADR-0010 invariant).
