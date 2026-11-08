---
id: decision-010
title: "ADR-0010 Informer-based in-memory cache (read path)"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0010-informer-cache.md`

# Informer-based in-memory cache (read path)

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

On large clusters, a dashboard that issues a fresh K8s API call per
render (per row, per detail pane, per SSE tick) saturates the API
server and degrades every user. The initial architecture chose the
read pattern: per-request REST, or a per-cluster in-memory cache
maintained by long-lived watches?

#### Decision Drivers

- **The UI is chatty by design.** List + detail + charts + events
  re-query the same objects many times per second.
- **Mutations are rare and already API-mediated.** The write path goes
  through the K8s API either way; the cache only needs to track watch
  events.
- **Memory is the price.** The cache is per-cluster in the replica's
  process; large clusters bound memory (mitigated by namespace scoping
  and a first-paint backstop).

#### Considered Options

- **Per-request REST.** Rejected as the target read pattern: unbounded
  API load, no shared view across panes.
- **Shared Redis-backed cache.** Rejected: serialization cost and a
  second consistency story; the chatty consumers are the same process
  that can hold the dict.
- **Informer-style per-cluster watches (CHOSEN).** One long-lived watch
  per cluster per kind; an in-memory dict keyed
  `(cluster, kind, namespace, name)`; UI and read services read the
  dict; mutations go through the API and the cache updates on the watch
  event; reconnect + backoff on disconnect.

#### Decision Outcome

**Chosen option: informer-based in-memory cache as the read path.**

- Target shape: `K8sClientPool` (per-cluster cached clients,
  `backend/app/services/k8s_client.py`) interposes the watch-maintained
  dict between the UI/read services and the API.
- Tuning knobs (Helm → env): `KUBEDASH_FIRST_PAINT_BACKSTOP` (default
  5 m — after it, the UI renders partial data with a "syncing…"
  indicator), `KUBEDASH_NAMESPACE_SCOPE` (pin the cache to one
  namespace for 10k+ namespace clusters), `KUBEDASH_LIST_PAGE_SIZE`
  (paginate initial LIST of high-cardinality kinds).

##### Consequences

- Good: bounded API load; panes share one view; watch-driven freshness
  with no polling.
- Bad: per-replica memory; reads are as fresh as the watch gap; cache
  warm-up on first paint (backstop mitigates).
- Confirmation: the seam docstrings in `backend/app/services/`
  (`"informer cache will interpose HERE later"`); `K8sClientPool` in
  `k8s_client.py`.

#### Implementation status (recorded at backfill)

The base-structure change (2026-10-17,
`.skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md`)
**deferred** the informer cache: the spine uses direct per-request API
calls, and the seam is left in `k8s_client.py` ("for now this is a live
read"). As of the 2026-11-06 backfill no `watch` import exists in
`backend/`; the decision stands as the target read pattern, the
deferral stands as the execution record.

#### Linking Decisions and Constraints

- ADR-0002 — the cache is per registry cluster.
- ADR-0009 — SSE streams read cache changes, not per-event API calls.
- ADR-0004 — reads stay SAR-gated; the cache holds data, not verdicts.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §3.3/§7.5; the
deferral record and the absence of any watch-based module were verified
by grep of `backend/app/` on 2026-11-06.
