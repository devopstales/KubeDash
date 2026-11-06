# Findings — workload-map

## Research: What do the reference visualizers (navigate, scope, the networkpolicy.io editor example, radar) do for connections and network policies that KubeDash 4.1's workload map lacks — and what is the 4.1 baseline itself?

> **Decision this serves:** The new 5.0 spec for
> `/dashboard/workload-map` — 4.1's map as the base, with proposed updates
> (connections + network-policy overlay) informed by radar and the three
> user-named sources.
>
> **Type:** technical + competitive
> **Mode:** research (single pass)
> **Date:** 2026-11-06 · **Status:** complete

## Executive Summary

The 4.1 workload map (verified against branch `4.1`) is not a network map:
`k8sGetPodMap` emits workload nodes (Deployment / StatefulSet / DaemonSet /
ReplicaSet, only `desired != 0`) and exactly one edge class — **ownership**,
workload→ReplicaSet. The pod layer exists in the template but is commented
out in the API; there are no Services, no NetworkPolicies, no traffic [1].
The map's *chrome* — vis.js hierarchical rendering, the
item/property/value filter menu, rich hover tooltip (kind badge, name,
namespace, Ready/Partial/Not Ready status, image, owner), legend,
namespace scoping via the topbar selector, click-to-navigate, dark/light
theming — is the part to carry forward [1].

The four references agree on a **three-layer model** KubeDash should adopt:

1. **Declarative structure** — workload↔service graph by *selector
   matching*; navigate builds exactly this from YAML upload *before the
   cluster exists* [2].
2. **Policy layer** — NetworkPolicies as first-class objects. The
   referenced networkpolicy.io example models a policy as a pod selector +
   ingress/egress **peer-scope blocks** (outside cluster / any endpoint /
   in namespace / everything in the namespace / in cluster / rest of the
   traffic / Kubernetes DNS), with live YAML and dual Kubernetes/Cilium
   output [4].
3. **Observed flows** — live connections: scope via eBPF host probes [3],
   radar via Hubble/Istio/Caretta/Beyla auto-detection [5]. For KubeDash
   (single container, air-gap ADR-0020, no host agents) this is phase 2 via
   an existing CNI/exporter — and radar's principle applies in the
   meantime: the UI "says so rather than showing partial edges silently"
   [5].

## Findings

### The 4.1 baseline (verified, branch `4.1` [1])

- **Page** `templates/dashboards/workload-map.html.j2`: card with filter
  menu (item: `edge`/`node` → property → multi-value via TomSelect →
  Filter/Reset highlight buttons), vis.js `Network` container
  (min-height 600px), node tooltip div, legend footer (kind icons +
  "hover for info / click to view details"), full dark/light theme
  handling (MutationObserver on `data-coreui-theme`), CSP nonces.
- **Graph options**: hierarchical layout (UD), levels — deployment 1,
  daemonset/statefulset/replicaset 2, pod 3; kind icons from static SVGs;
  directed smooth edges with arrows; physics off; stabilization 1000
  iterations.
- **Data** `GET /api/v1/cluster/workload-map?namespace=` (cluster.py
  `WorkloadMapResource`): calls `k8sGetPodMap`; returns
  `{data: {nodes, edges}, metadata: {namespace, nodes_count,
  edges_count}}`; namespace from query arg else session
  `ns_select` (default `default`); on namespace-list error returns empty
  nodes/edges.
- **`k8sGetPodMap`** (lib/k8s/metrics.py): pyvis `Network(directed=True,
  layout=True)`; nodes for StatefulSet/DaemonSet/Deployment/ReplicaSet
  with `desired/ready/available/age` (+ `containerImage` for deployments,
  `owner` for RS); **edges: workload→ReplicaSet only**; the Pod node/edge
  block is **commented out** (along with a Trivy-vulns lookup).
- **Frontend behavior**: click maps kind → list route
  (`/workload/deployments` etc.); hover builds the rich tooltip; reload on
  topbar namespace change; error state rendered in-graph.

### navigate (oslabs-beta/navigate [2])

- "A Kubernetes cluster visualizer … network policies, aggregated scheduler
  logs, deployments and pods **before your cluster is running**" — YAML
  upload mode computes the graph declaratively; live mode adds cluster
  data [2].
- Graph spans "stateful sets, deployments, services, and other Kubernetes
  objects"; "click on the deployment nodes … to zoom into the Node View,
  seeing the various containers and **connections** each deployment
  brings" [2].
- **Network Policies as first-class objects**: a dedicated "Network
  Policies" tab shows "all, one at a time" with a per-policy dropdown;
  `kObjects/` models `ingressPolicy.ts`, `egressPolicy.ts`,
  `kNetworkPolicy.ts` alongside the workload objects [2].
- `component_data/findSelectorMatch.ts` — selector matching is a named
  core utility [2].
- Live extras: "etcd/node scheduler decisions, aggregated across many
  different logs", live deployment statuses/conditions, live pod data [2].
- Stack: TypeScript/React + Node server, Electron packaging; MIT; 165★;
  OS Labs Beta 2021 capstone — concepts over code [2].

### scope (alfiyansys/scope, modernized Weave Scope fork [3])

- Architecture: **per-host probe agents** (docker, kubernetes, endpoint,
  host, process) report to a central app that "merges them into a live,
  interactive map"; drill into a container/process, metrics,
  pause/stop/restart/exec from the page [3].
- The connections layer is **observed**: `probe/endpoint` is "the eBPF
  connection tracer" (fallback conntrack/proc), needing host net/PID +
  `/sys/kernel/debug` [3].
- `render/` turns raw `report/` data into topologies — a clean
  data-model→topology seam [3].
- Provenance caveat: **personal fork** of upstream unmaintained since
  2023-06-13; Kubernetes client modernization "mostly done" but
  live-cluster validation still open; no e2e suite for the paths that
  matter [3].

### networkpolicy.io editor — the referenced example [4]

- Site meta-description: "makes it easy to build, visualize, and make
  sense of Network Policies, which can then be downloaded as YAML and run
  in any Kubernetes cluster with a Network Policy-aware CNI" [4].
- The shared example `?id=RgXOI5C6IaJEVe4l` (rendered in-browser this
  run) is the editor's rule-building canvas for an `untitled-policy`
  (`podSelector: {}`, `policyTypes: []`): **ingress/egress peer-scope
  blocks** — Outside Cluster / Any endpoint / In Namespace / Everything in
  the namespace / In Cluster — plus "Rest of the traffic" and
  "Kubernetes DNS" (egress), a "Pod selector: All pods" control, and
  **dual-flavor output**: a Kubernetes | Cilium toggle generating
  `networking.k8s.io/v1` NetworkPolicy or CiliumNetworkPolicy YAML, with
  Download and Share (the share link is the `?id=` URL) [4].
- The `id` decodes to a 12-byte binary document id (stored example), not
  an inline payload — the content is fetched by the SPA by id [4].

### radar (fetched earlier this session, 2026-11-06 [5])

- **Topology view: two modes** — "Resources (full hierarchy)" and
  "Traffic (network flow path)"; group by namespace, app label, or
  ungrouped; filter by kind; ELK.js auto-layout; live updates via SSE [5].
- **Traffic mode**: auto-detects Hubble (Cilium), Istio, Caretta, or
  Grafana Beyla, "with a setup wizard to install one if none is detected";
  "per-port edges additionally need `dst.port` and `transport` named in
  `attributes.select` — both are off by default, and **Radar says so in
  the Traffic view rather than showing partial edges silently**"; animated
  flow graph with req/s, filterable by namespace/protocol/status; "focus
  on a workload to see only it and what it talks to; the focus is in the
  URL, so it can be shared" [5].
- **NetworkPolicies**: `issues` includes "NetworkPolicies that leave a
  Service's pods with no allowed inbound traffic"; Network Path Diagnose
  answers "does it reach a healthy process, and if not which hop breaks
  first?", "predicts NetworkPolicy blocks", and names the first broken hop
  with a kubectl reproducer [5].
- MCP `get_topology` (graph or `summary` text) and `get_neighborhood`
  (BFS, max 2 hops) expose the same model to agents [5].

### KubeDash 5.0 constraints the design must respect (this repo [6])

- Read path from the informer cache (ADR-0010); SSE push (ADR-0009);
  SAR-gated reads (ADR-0004); degrade-never-500 (ADR-0003); air-gap —
  everything bundled (ADR-0020); no object identity in URLs (ADR-0040 —
  radar's "focus in the URL" needs adaptation); multi-cluster registry
  (ADR-0002) — 4.1's single-cluster assumption does not carry over.
- A Network Policy view already exists (`/security/network-policy`,
  networkpolicies + ciliumnetworkpolicies +
  ciliumclusterwidenetworkpolicies, SAR-gated, 2026-10-26) — the overlay's
  click-through target [6].
- The map is a stub today: `_nav.tsx` "Workload" (Beta badge) →
  `/dashboard/workload-map`; `views/Stub/routes.ts` entry [6].
- The mcp-server research (2026-11-06) already plans `get_topology` /
  `get_neighborhood` over a graph builder service — the map's builder
  should be that shared service [6].

## Cross-Dimension Insights

- **The three layers are the product.** Every reference decomposes the
  same way: structure (ownership + selector) / policy (permitted + denied
  flows) / observed (actual flows). KubeDash's v1 can credibly ship
  layers 1+2 declaratively from the cache; layer 3 needs a data source
  (CNI/exporter) and is a clean phase 2 — but v1 must *say* it's absent
  (radar's explicit-degradation principle) rather than render a
  structure-only graph and let users assume it's complete.
- **Selector matching is the shared core computation** (navigate's
  `findSelectorMatch`, radar's neighborhood building, the networkpolicy.io
  pod-selector model). One well-tested pure function powers workload↔
  service edges, orphan-policy detection, and "no endpoints" issues.
- **Scope's eBPF layer validates the end goal but its architecture is the
  wrong one for KubeDash** (host probes with privileged mounts vs a
  single air-gapped container). The right shape is radar's: consume an
  existing observation source (Beyla/Istio/Hubble) when present.
- **The networkpolicy.io example shows the policy mental model to copy**:
  policies are not list rows, they are *scopes* (peer categories +
  selector + ingress/egress), and "rest of the traffic" (default-allow vs
  default-deny semantics) is a first-class concept. The map's overlay
  should render the same model: per-namespace default posture + explicit
  permits + the remainder.

## Contrary Evidence

- The networkpolicy.io shared example is the editor's **default canvas**
  (untitled policy, empty `policyTypes`) — it demonstrates the editor's
  model, not a populated real-world policy; treat its specifics as the
  tool's vocabulary, not an example of typical policy shape [4].
- Scope is a one-person fork of a project unmaintained since 2023; its
  Kubernetes support is "mostly done" with live validation outstanding —
  cite its architecture, not its maturity [3].
- Navigate is a 2021 capstone (165★) — its graph/policy concepts are
  sound, but do not plan to import code [2].
- 4.1's own pod layer was **disabled** (commented out, alongside a Trivy
  lookup) — a scale hint: pod-level nodes explode on real clusters. v1
  should keep pods as node badges (count/ready), not nodes [1].
- radar's "focus in the URL" conflicts with ADR-0040 (no object identity
  in URLs) — the interaction must use the session object-ref mechanism
  instead, losing radar's shareable-focus property [5][6].

## Recommendations

1. **Adopt the three-layer data model** — L0 ownership (4.1, carried over),
   L1 connections (service nodes + selector-matched edges + declared
   service→service peers from NetworkPolicy peers), L2 policy overlay
   (edge state allowed/denied/unknown, default-deny namespace badges,
   issues). Confidence: high (all four references converge [1][2][3][4][5]).
2. **Two view modes, Resources / Traffic** (radar's split), Resources =
   L0+L1, Traffic = L1+L2. Confidence: high [5].
3. **Honest partiality on the API and in the UI** — `coverage`
   (missingInputs / truncated / degraded) per the evidence contract from
   the 2026-11-06-mcp-server findings; an in-view banner when no observed
   traffic source exists. Confidence: high [5][6].
4. **Graph builder as a pure service over the informer cache**, shared by
   the REST endpoint and the future MCP `get_topology`/`get_neighborhood`.
   Confidence: high (ADR-0010 + mcp-server findings [6]).
5. **Renderer: vis-network (4.1 parity)** as the recommended candidate —
   4.1 already proved the layout/interaction; it is MIT and bundles
   (air-gap). New dependency → its own ADR before code. Confidence: medium
   (parity argument is strong; React-integration ergonomics unverified
   this run).
6. **Observed flows = phase 2** via an existing observation source
   (Beyla/Istio/Hubble, radar's set); no host agents. Confidence: high
   (ADR-0020 + single-container ADR-0006 rule out scope's probe model
   [3][6]).

## Open Questions

1. **Renderer choice** — vis-network vs React Flow vs SVG+ELK (radar uses
   ELK.js [5]). Needs a dependency ADR; decide in the blueprint with a
   spike if the vis-network React integration is uncertain.
2. **Policy evaluation depth** — v1 conservative: default-deny detection
   + explicit-permit matching → allowed/denied/unknown per edge. Full
   multi-policy interaction semantics (additive allows, namespace
   isolation, port sets) may overstate accuracy; state the heuristic
   boundary in the UI. Decide how conservative in the blueprint.
3. **Service→service edges** — from NetworkPolicy peer declarations only
   (v1) vs also config/env references (radar's `search` covers env refs;
   a `DB_HOST=orders-db` style inference is powerful but heuristic).
   Probably: NP peers in v1, env-ref inference v2.
4. **Focus/neighborhood under ADR-0040** — session object-ref for focus
   (no URL identity); confirm the interaction (click node → 2-hop
   neighborhood) and whether "all" resets.
5. **Scale caps** — node/edge count cap + `truncated` marker (4.1 had
   none; radar claims tens-of-thousands-of-pods tolerance [5]). Set the
   cap in the blueprint (suggested: namespace-scoped default, cap for
   cluster-wide).
6. **Dev fixtures** — the demo cluster needs a meaningful policy set
   (default-deny + permit + an orphan + a no-endpoint service) for the
   overlay to be demonstrable; extend `dev/` fixtures.

## Source Appendix

| [n] | Claim/finding it supports | Publisher | Pub date | Accessed | Confidence |
|-----|---------------------------|-----------|----------|----------|------------|
| [1] | 4.1 map: template chrome, vis.js options, filter/tooltip/click behavior, API shape, `k8sGetPodMap` ownership-only edges, commented-out pod layer | [kubedash branch `4.1`: `templates/dashboards/workload-map.html.j2`, `blueprint/api/cluster.py`, `lib/k8s/metrics.py`](../../../../) (git show 4.1:…) | branch `4.1` | 2026-11-06 | high (primary, this repo) |
| [2] | Declarative pre-cluster graph; services in graph; node zoom-in with connections; Network Policies tab one-at-a-time; ingress/egress policy objects; findSelectorMatch; live scheduler/pod data; MIT/165★/2021 provenance | [oslabs-beta/navigate README](https://github.com/oslabs-beta/navigate) | repo main (2021-era) | 2026-11-06 | high (primary) |
| [3] | Probe-agent architecture; eBPF connection tracer (host net/PID + debugfs); render→topology seam; personal-fork status, upstream unmaintained since 2023-06-13, K8s validation outstanding | [alfiyansys/scope README](https://github.com/alfiyansys/scope) | main (fork active 2026) | 2026-11-06 | high (primary) |
| [4] | Editor purpose (build/visualize/understand policies → YAML, any NP-aware CNI); example `RgXOI5C6IaJEVe4l` = peer-scope rule blocks (outside cluster / any endpoint / in namespace / everything in namespace / in cluster / rest of the traffic / DNS), pod selector control, dual Kubernetes/Cilium output, Download/Share; `id` is a stored document id (12-byte binary) | [editor.networkpolicy.io/?id=RgXOI5C6IaJEVe4l](https://editor.networkpolicy.io/?id=RgXOI5C6IaJEVe4l) (SPA, rendered in-browser) | live site | 2026-11-06 | high (primary; the shared example is the editor's default canvas — untitled policy, empty `policyTypes`) |
| [5] | Radar topology two modes (Resources/Traffic), grouping/filters, ELK.js, SSE; traffic source auto-detection + setup wizard + explicit-degradation principle; focus in URL; NP issues (no allowed inbound) + network-path diagnosis predicting NP blocks; `get_topology`/`get_neighborhood` | [skyhook-io/radar README (main) + docs](https://github.com/skyhook-io/radar) | main; releases through v1.18.3 (2026-10-28) | 2026-11-06 (fetched earlier this session) | high (primary) |
| [6] | KubeDash constraints and existing surfaces: ADR-0002/0003/0004/0009/0010/0020/0040, the 2026-10-26 network-policy view, stub route + nav entry, 2026-11-06-mcp-server findings (evidence contract, future topology tools) | [kubedash repo: AGENTS.md, .skillgrid/knowledge/, .skillgrid/specs/2026-11-06-mcp-server/findings.md](../../../../AGENTS.md) | this repo | 2026-11-06 | high (repo) |
