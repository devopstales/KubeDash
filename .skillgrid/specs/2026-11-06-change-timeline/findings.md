# Findings — change-timeline

## Research: What should KubeDash's change timeline record, where store it, and what are its semantics?

> **Decision this serves:** Scoping the change-timeline feature —
> watch-recorded resource changes with diffs, persisted across restarts,
> surfaced in a UI view and (later) to agents via an MCP `get_changes`
> tool. Input to a future briefing.
>
> **Type:** technical + competitive
> **Mode:** research (single pass)
> **Date:** 2026-11-06 · **Status:** complete

## Executive Summary

Radar "records resource changes while it watches the cluster; history is in
memory by default, and `--timeline-storage=sqlite` or `postgres` keeps it
across restarts" [1]. The UI is a unified timeline of Kubernetes **events
and resource changes** with change diffs ("what changed (replicas, images,
etc.)") and real-time updates [1]; the MCP `get_changes` tool exposes the
same data to agents, with explicit partiality semantics (`sourcesErrored`,
`cluster_connecting`, `clusterScopedChanges`) [2]. KubeDash already watches
every registered cluster via informers (ADR-0010) and has Postgres; the
increment is a **leader-gated recorder**, one table + migration, a
field-policy for "meaningful" changes, retention, and a UI view. The
radar-verified detail that KubeDash's REST already matches: until initial
sync, `get_changes` "returns a `cluster_connecting` error rather than an
empty list, as the REST API does" [2].

Findings that drive the decision:

1. **The recorder is a consumer of existing watch traffic**, not a new
   watch — both at Radar (it records "while it watches") and at KubeDash
   (informers per ADR-0010) [1][3].
2. **Partiality is explicit at every boundary** — `sourcesErrored` per
   source, `cluster_connecting` before sync, `clusterScopedChanges`
   attached to namespace queries [2].
3. **KubeDash's storage answer is forced by existing architecture** —
   Postgres + leader-only writer (ADR-0008) + Alembic; no new
   infrastructure [3].

Biggest caveat: Radar's "meaningful change" field policy and its retention
semantics (`--timeline-max-size`, `--history-limit`) are named in its flag
list but not specified in the sources read this run — the field policy is
KubeDash's own decision to make [1].

## Findings

### Radar's timeline design (verified in [1])

- "Radar records resource changes while it watches the cluster; history is
  in memory by default, and `--timeline-storage=sqlite` or `postgres` keeps
  it across restarts." [1]
- UI: "Unified timeline of Kubernetes events and resource changes" —
  filter by event type (all or warnings only), "resource change diffs
  showing what changed (replicas, images, etc.)", real-time updates as new
  events occur [1].
- Related flags exist: `--timeline-db`, `--timeline-max-size`,
  `--history-limit` [1]. (Semantics of the size/limit flags not specified
  in the sources read this run — see Open Questions.)

### `get_changes` semantics (verified in [2])

- "Recent meaningful changes from the Kubernetes cluster timeline plus
  native Helm release deployment/operation history (`source: helm`). Use to
  investigate what changed before an incident, including failed upgrades,
  rollbacks, and current Helm revisions."
- "If the response includes `sourcesErrored`, treat it as partial data for
  those sources."
- "A namespace query without `kind` or `name` adds
  `clusterScopedChanges`" — cluster-scoped admission changes are visible in
  a namespace view, not silently dropped.
- "Until Radar has connected to the cluster it returns a
  `cluster_connecting` error rather than an empty list, **as the REST API
  does**." — the timeline surface degrades the same way the REST surface
  does (KubeDash's ADR-0003 convention already behaves this way [3]).
- The full Helm revision trail lives in `get_helm_release
  include=history,operations`; `get_changes` carries the incident-relevant
  subset [2].

### Mapping to KubeDash (this repo, [3])

- **Recorder = consumer of existing watches.** ADR-0010 informers already
  stream every registered cluster; the recorder subscribes to the same
  events, no new K8s watches.
- **Leader-gated writes.** ADR-0008: RQ/background work runs only on the
  leader (PG advisory lock + `leader_lease`). With N replicas all watching,
  only the leader may persist change records; non-leaders serve reads from
  PG. (Leader failover must not double-record — idempotent inserts keyed
  by object identity + resourceVersion.)
- **Storage.** Postgres already required; one new table + Alembic migration
  (dev DB is migration-managed — never hand-edit schema). Radar offers
  sqlite as the light option, but KubeDash's single-container + PG shape
  makes PG the boring choice.
- **Push.** ADR-0009 SSE is the existing server→client channel for live
  timeline updates.
- **Multi-cluster.** Each registered cluster has its own timeline; the UI
  view is scoped by the selected cluster. (Radar precedent is
  single-cluster [1].)
- **No backfill.** History starts when the recorder starts — same as Radar's
  in-memory default. Document it.
- **Degrade, never 500** (ADR-0003): recorder down → timeline view
  degrades with a stated cause; REST/MCP surfaces return the
  `cluster_connecting`-equivalent before initial sync [2][3].

## Cross-Dimension Insights

- The timeline is the **shared substrate** for the other two specs: the MCP
  `get_changes` tool (mcp-server spec) and incident investigation
  ("what changed before X failed" is the first question in
  ai-investigations) both read it. Scoping the recorder well now shapes
  both downstream specs.
- Radar's `source:` field (k8s watch vs helm operation) anticipates that
  "changes" will come from multiple producers; KubeDash's schema should
  carry a `source` column from day one even if v1 has a single producer.

## Contrary Evidence

- In-memory-first (Radar's default) is simpler and cheaper, and persistence
  is opt-in at Radar [1]. KubeDash's counter-consideration: it is a shared,
  in-cluster team product — restarts are normal operations (deploys,
  scaling), and losing the incident window on restart defeats the feature's
  core use case. PG persistence from v1 is the safer default for KubeDash's
  audience; the trade is one table + a leader-gated write path.
- A unified events+changes timeline (Radar's UI) mixes two data types with
  different cardinality (events are far chattier). KubeDash could start
  with changes-only and add events in the same view later; the unified
  view is the end state, not a v1 requirement.

## Recommendations

1. **v1: leader-gated PG recorder over existing informer traffic,
   changes-only, per-cluster.** No new watches, no new infrastructure
   beyond one table + migration. Confidence: high (forced by
   ADR-0008/0010/0028 [3]).
2. **Carry `source` in the schema from day one** (v1 value:
   `k8s-watch`), anticipating multi-producer (Helm operations later).
   Confidence: high (pattern verified in [2]).
3. **Degrade semantics: `cluster_connecting`-equivalent before initial
   sync; `sourcesErrored`/partial markers after.** Confidence: high
   ([2]; matches ADR-0003 [3]).
4. **Define the "meaningful change" field policy explicitly in the
   briefing** — which fields produce a record (spec changes: replicas,
   images, selectors, env…; exclude: resourceVersion, managedFields,
   label/annotation churn policy, status-only transitions). Radar names
   "replicas, images, etc." but does not specify the full policy in the
   sources read. Confidence: high that a policy is needed; the policy
   itself is open (Q1).
5. **Idempotent recording keyed by (cluster, group, kind, ns, name,
   resourceVersion)** so leader failover cannot double-record.
   Confidence: high (direct consequence of ADR-0008 [3]).

## Open Questions

1. **"Meaningful" field policy** — exact field set per kind (or a generic
   spec-diff rule); how to treat label/annotation churn and status
   transitions (record, summarize, or drop). Requires: a spec-level
   decision; Radar's full policy was not specified in the sources read.
2. **Retention** — row cap and/or TTL (Radar has `--timeline-max-size` /
   `--history-limit` flags; semantics not read this run). Requires: sizing
   analysis for a chatty cluster (thousands of pods; Radar claims to be
  "tested on tens of thousands of pods" [1] — volume numbers unverified).
3. **Kind scope** — all watched kinds incl. CRDs, or built-in kinds in v1?
   Radar watches large CRDs only on demand [2]; the recorder must decide
   whether it follows on-demand watches.
4. **Event dedup / incarnation** — the same UID-incarnation problem Radar
   applies to `get_events` (events from earlier incarnations excluded,
   exclusion count reported [2]) applies to the change stream.
5. **Helm source** — KubeDash has no Helm domain yet; v1 is K8s-watch
   changes only, Helm operation history a separate change (the `source:`
   column keeps the door open) [2].
6. **Diff granularity** — field-level JSON diff (storage cost) vs
   per-field summary (`replicas: 3→2`, storage-cheap, agent-readable);
   what the UI shows vs what the future MCP tool returns.
7. **UI shape v1** — changes-only list with diff drawer, or unified
   events+changes timeline from the start (see Contrary Evidence).

## Source Appendix

| [n] | Claim/finding it supports | Publisher | Pub date | Accessed | Confidence |
|-----|---------------------------|-----------|----------|----------|------------|
| [1] | Timeline recording (in-memory default, sqlite/postgres), unified UI timeline with change diffs, related flags, large-cluster claim | [skyhook-io/radar README (main)](https://github.com/skyhook-io/radar) | main; releases through v1.18.3 (2026-10-28) | 2026-11-06 | high (primary) |
| [2] | `get_changes` semantics: `source: helm`, `sourcesErrored`, `cluster_connecting`, `clusterScopedChanges`; event incarnation filtering; on-demand CRD watches | [radar docs/mcp.md (main)](https://raw.githubusercontent.com/skyhook-io/radar/main/docs/mcp.md) | main | 2026-11-06 | high (primary) |
| [3] | KubeDash constraints: ADR-0003 (degrade never 500), ADR-0008 (leader-only RQ, `leader_lease`), ADR-0009 (SSE), ADR-0010 (informer read path), ADR-0028 (config/migration discipline), Postgres, multi-cluster registry | [kubedash AGENTS.md + .skillgrid/knowledge/ASSUMPTIONS.md](../../../../AGENTS.md) | this repo | 2026-11-06 | high (repo) |
