# Cluster Dashboard — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. The blueprint
> (`blueprint.md`) follows every in-force ADR it names. ADR bodies 0001–0013 have index entries
> but **no bodies on disk** (per AGENTS.md); the index in `ASSUMPTIONS.md` is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0003 (observability query-only) | Metrics usage + the rollup **read** the cluster; they never write to it. |
| ADR-0004 (SAR cache key carries every attribute) | The derived rollup is gated **two-tier**: cluster-wide `list pods` + `list nodes` (whole summary) and `get nodes` on `metrics.k8s.io` (used only) — a count never leaks for a user who can't read the underlying resources. |
| ADR-0005 (CoreUI) | `ConcentricDonut` uses `@coreui/react-chartjs`; the red overflow bar uses `--cui-danger`; no second accent, no webfont. |
| ADR-0010 (informer cache read path) | **Forward reference, not yet built.** All reads go through `K8sClientPool` (the documented seam where the cache interposes later); events use `K8sClient.list_events` through the pool. The blueprint cites the pool, not a cache that doesn't exist yet. |
| ADR-0020 (air gap) | `@coreui/react-chartjs` is bundled (already a dep); no CDN; metrics.k8s.io is in-cluster. |
| ADR-0023 (DataTables) | The events table uses `KubeDataTable`. |

## Decision: metrics usage source + how it's read

**Status:** accepted (ratified at the sibling node change's gate, paladm, 2026-10-22)
**Deciders:** the blueprint gate
**Date:** 2026-10-22

### Context

The dashboard's "used" values need a metrics source. `metrics.py` is a 501 stub and ADR-0003 has
no body on disk. The sibling `2026-10-21-cluster-node` change ratified **metrics.k8s.io** as the
usage source; this change reuses that decision (no new ADR).

**Verified constraint (2026-10-22):** the vendored client is **kubernetes 37.0.1**, whose generated
client has **no `MetricsV1beta1Api`** (`from kubernetes.client import MetricsV1beta1Api` →
ImportError; `kubernetes.utils.metrics` is the client's own Prometheus instrumentation). So the
metrics read is `api_client.call_api(['/apis/metrics.k8s.io/v1beta1/nodes'], 'GET', ...)` — a
concrete, named mechanism, not an assumption.

### Decision

Read usage from `metrics.k8s.io/v1beta1` via `api_client.call_api`, query-only, through the registry
credentials. A missing metrics-server (404) → `metrics_available:false` + `used:null` (never `0`).

### Consequences

- No new dependency (the `kubernetes` client's `ApiClient.call_api` is sufficient).
- The `used` fields are **separately RBAC-gated** on `get nodes`/`metrics.k8s.io` — a user without
  metrics read sees used = unknown but still sees declared requests/limits.
