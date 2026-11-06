# Observability as query-only (no ingest)

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

Most K8s dashboards assume (or run) their own metrics/log/trace
stack. KubeDash targets environments that already operate Prometheus,
Loki/ES, and Tempo/Jaeger per cluster or globally. The question: does
KubeDash ingest and store observability data, or only query and display?

#### Decision Drivers

- **No extra infrastructure in the user's cluster.** KubeDash is one
  container; running a scrape pipeline or log ingester inside it
  re-creates the backends it is meant to display.
- **Backends differ per cluster.** Each cluster may have its own
  Prometheus; the global config must be overridable per cluster.
- **Degrade, don't fail.** An absent or slow backend must degrade that
  pane (honest "—"), never fail the cluster view.
- **Air-gap (ADR-0020).** Backends are internal endpoints; KubeDash makes
  no external call for them.

#### Considered Options

- **Full ingest stack** (sidecar scrapers + storage). Rejected: new
  infrastructure, new data lifecycle, duplicates the backends.
- **Query-only (CHOSEN).** KubeDash is a query + display layer: thin
  `httpx` clients per backend (`prometheus`, `loki`, `tempo`, `grafana`
  services), per-backend timeouts and retries, shared
  `observability.<signal>` config (base URL, auth, tenant).
- **Hybrid** (ingest alerts only). Rejected: alert evaluation still
  queries Prometheus rules; no storage beyond the dedup state in the
  `alerts` table is needed.

#### Decision Outcome

**Chosen option: query-only over user-supplied backends.**

- `backend/app/services/prometheus.py` / `loki.py` / `tempo.py` /
  `grafana.py` — thin clients; metrics query + range + recording rules,
  log search + tail + pod-level filter, trace search + waterfall, Grafana
  dashboard embed.
- Global observability config with per-cluster override
  (a cluster can point at its own Prometheus).
- Degrade contract: missing/failed backend → that signal's pane degrades
  (empty result / honest "—"), the cluster view stays usable. E.g. PVC
  usage from kubelet `stats/summary` renders "—" when the kubelet reports
  no pvcRef stats.

##### Consequences

- Good: KubeDash stays one container; no second source of truth; works
  against any conforming backend.
- Bad: KubeDash inherits the backends' availability and latency
  (mitigated by per-backend timeouts + degrade).
- Confirmation: `backend/tests/api/test_metrics_pvcs.py`,
  `test_metrics_summary.py`; the service modules in
  `backend/app/services/`.

#### Linking Decisions and Constraints

- ADR-0006 — single container: no scrape/ingest sidecar possible.
- ADR-0020 — backends are internal endpoints (air-gap).
- ADR-0002 — per-cluster override rides the cluster registry.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §6; verified against
`backend/app/services/{prometheus,loki,tempo,grafana}.py` and the metrics
tests on 2026-11-06.
