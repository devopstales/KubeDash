# Cluster Node View — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. The blueprint
> (`blueprint.md`) follows every in-force ADR it names. This change adds no new ADR beyond
> the metrics-source decision below, which **implements** the in-force ADR-0003 (no body on
> disk yet) rather than superseding it.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0003 (observability query-only) | The node-metrics endpoint **reads** metrics.k8s.io live and never writes to it. |
| ADR-0004 (SAR cache key carries every attribute) | `rbac.can` is asked before the node list **and** before the metrics rollup (a derived count), so a verdict for one ns/object never answers for another. |
| ADR-0005 (CoreUI) | The view uses CoreUI `CCard`/`CBadge`/`progress` + `KubeDataTable`; no second accent, no webfont. |
| ADR-0010 (informer cache read path) | The node list goes through the existing `K8sClient` pool seam (consistent with `list_pods`); no new per-request ad-hoc pattern. |
| ADR-0020 (air gap) | metrics.k8s.io is an in-cluster endpoint; no external/CDN dependency added. |
| ADR-0023 (DataTables) | The node table uses `KubeDataTable`. |

## Decision: metrics data source for the node tiles

**Status:** accepted (ratified at the blueprint gate, paladm, 2026-10-21)
**Deciders:** the change's blueprint gate
**Date:** 2026-10-21

### Context

The `/cluster/node` view (Option 1) shows four metric tiles (CPU usage, Memory usage, Pods,
Storage). `metrics.py` is a 501 stub and ADR-0003 ("Observability as query-only") has **no body
on disk**, so the metrics *source* was an owed decision. A source must be named before the
blueprint can be executed (Owed-Decision Gate).

### Options considered

1. **Kubernetes Metrics API (`metrics.k8s.io/v1beta1`) via the python client** — the standard
   in-cluster metrics-server; no new dependency; degrades to "unknown" when the metrics-server
   is absent (satisfies the certainty rule). *Chosen.*
2. **Prometheus (PromQL)** — richer history and `query_range`, but adds a Prometheus client
   dependency (would need its own ADR) and assumes Prometheus is deployed in the target cluster.
3. **Node status only (no live usage)** — drops live CPU/Mem usage; tiles become capacity-only.

### Decision

Use **metrics.k8s.io** as the query-only metrics source for the node tiles, read live through the
registry credentials. This **implements** ADR-0003 (query-only) and does not supersede it. A
missing metrics-server or a node without a sample renders that metric **unknown**, never `0`.

### Consequences

- Adds `K8sClient.node_metrics` + a `MetricsV1beta1Api` on the existing `ApiClient` (no new
  dependency — the `kubernetes` client already ships the metrics API).
- The `storage` tile has **no** source in metrics.k8s.io and renders "unknown" until a source is
  named (a future decision, not owed by this change).
- If a different source (e.g. Prometheus) is later required, `node_metrics` + the tile wiring
  rework — the seam is `k8s_client.node_metrics`, so the blast radius is bounded.
