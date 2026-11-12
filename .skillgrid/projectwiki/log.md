# KubeDash — Knowledge Base Log

> Journal of knowledge-base writes, newest last. Every write appends here in
> the same edit as the concept + `index.md`.

## 2026-10-27

- Authored three ADRs (decision record + `.backlog/decisions/` copy each):
  - **ADR-0029** Queue on Postgres — `tasks` table + `SELECT ... FOR UPDATE
    SKIP LOCKED` poll worker (reaper + 3× exponential-backoff retry +
    dead-letter), replacing RQ/Redis as the task broker. Supersedes ADR-0007
    (which was index-only, no body file).
  - **ADR-0030** Session revocation on Postgres — `revoked_jtis` deny-list
    table (PK hot-path lookup + leader reaper), replacing the Redis `jti` set.
    Supersedes ADR-0014 (file retained, IRON RULE). With ADR-0029 this removes
    Redis's last two consumers → Redis dropped from the stack.
  - **ADR-0031** Active-active Postgres via pgEdge/Spock —
    `ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal`, thin operator-less
    Helm chart + run-once init `Job`, `dev/` docker-compose, `autoddl` for
    one-shot migrations, + a **strict fencing token** on `leader_lease`.
    Supersedes ADR-0008 (index-only, no body file).
- `ASSUMPTIONS.md` § LOCKED: flipped ADR-0007 / ADR-0008 / ADR-0014 rows to
  "In force: no"; added rows for 0029 / 0030 / 0031; highest sequence 0028 →
  0031.
- `config.yaml` `adr.highest_sequence` 25 → 31 (was stale).
- `index.md` (this bundle): added 0029 / 0030 / 0031 rows (and the missing
  0027 / 0028 rows); marked ADR-0014 superseded; noted 0007 / 0008 were
  index-only.
- `ARCHITECTURE.md` § 3.7 rewritten: Postgres queue + leader election with the
  `fence` token, active-active pgEdge, Redis removed from the task path.
  (Remaining RQ/Redis references in other § are carried to the implementation
  phase, not part of the ADR-first record.)

## 2026-11-07 — decisions/04-adr-0041-kind-catalog.md added; glossary +3 terms

- ADR-0041 accepted (user decision, architecture review 2026-11-07):
  resource kinds are declared in a typed catalog — backend kind catalog +
  generic `list(kind, ns)`/`get(kind, ns, name)` engine on `K8sClient` at
  the existing `K8sClientPool.factory` seam, `ResourceApi` dispatch
  derived from the registry (`_KINDS`/`_GETTERS` deleted), per-kind
  methods only as named overrides, one shared `FakeK8s` + fixture module
  replacing the 8 doubles; frontend `lib/kinds.ts` registry drives shared
  list/data View modules + the generated App.tsx route table. Kind-by-kind
  cutover, no facade.
- `glossary/02-technical-terms.md`: +**Kind**, +**Kind catalog**,
  +**Registry kind** — the three naming spaces (API plural / registry
  kind / route path) named once.
- `index.md`: ADR-0041 row added. (Rows for ADR-0029..0039 remain open —
  pre-existing gap, not backfilled here.)
- `.backlog/decisions/decision-041` copy created.
## 2026-10-26

- Bundle restructured: `.skillgrid/artifacts/` → `.skillgrid/knowledge/`.
  - 13 ADR files (0014..0026) → `decisions/`
  - `01-business-terms.md`, `02-technical-terms.md` → `glossary/`
  - Created `invariants/`, `workflows/`, `reference/` (empty)
  - Created `index.md`, `log.md`, `reverse-index.md`
  - `config.yaml` `conventions.artifacts` → `.skillgrid/knowledge`
  - Path references updated: `AGENTS.md`, `ARCHITECTURE.md` (§2 tree, §12, §13, header), `ASSUMPTIONS.md` (header + LOCKED paths). Archive/spec/backlog files kept as history.

## 2026-11-04 — decisions/04-adr-0040-session-object-navigation.md amended

- ADR-0040 amended (user decision): the cross-tab deep-link token is now
  delivered through the server session (SPA-fallback 303 POST bounce +
  `obj_incoming:<sub>` Redis TTL-60s stash + one-shot
  `<meta name="kd-object-incoming">` injection) instead of `?o=` in the
  document URL — proven non-functional in a real browser by the QA gate
  (2026-11-03, FAIL). R10 carved to "no new API endpoint / migration /
  cookie"; token entropy 32 → 64 bits.
- New module: `app/core/object_handoff.py` (SPA-fallback handoff plumbing).
- `index.md`: ADR-0040 row added (index rows for ADR-0027..0039 remain
  open — pre-existing gap, not backfilled here).

## 2026-11-06 — bundle initialized from current source and tests

- **Restored** the working-tree deletion of `.skillgrid/knowledge/`
  (`git restore` — all 24 tracked files returned; content unchanged).
- **Backfilled ADR-0001..0013** (13 new files in `decisions/`, open
  task per the 2026-10-17 onboarding notes): authored from
  `ARCHITECTURE.md` §12 + §3–§7, verified against current source
  2026-11-06 (`backfilled: 2026-11-06` in each status block). Notable
  records inside: ADR-0004 carries the 2026-10-21 cache-key amendment;
  ADR-0010 records the base-structure deferral (no watch-based module
  exists yet — reads are per-request REST; the seam docstring is the
  pin); ADR-0013 records `rbac_drift.py` as a stub no-op.
- **Tracker copies** (`.backlog/decisions/`): created
  `decision-001..013` + `decision-040`; recopied the three drifted
  copies (0022, 0024, 0028 — artifacts were newer: implementation
  status, H1 heading, KUBEDASH_HOME contract) and fixed 10 stale
  `Source:` paths (`.skillgrid/artifacts/` → `.skillgrid/knowledge/`).
  All 29 artifacts now have in-sync copies.
- **Invariants** (8 new, `invariants/`): session-cookie-transport,
  leader-only-rq-worker, config-fail-fast, services-integration-boundary
  (records the one function-local `from flask import g` carve-out),
  sar-verdict-cache-key, air-gap-bundle, object-nav-no-url-identity,
  security-header-layer. Every claim literal grep-verified 2026-11-06.
- **Workflows** (4 new, `workflows/`): oidc-login-session,
  object-deep-link, leader-task-execution, frontend-build-serve.
- **Reference** (2 new, `reference/`): live-architecture (pointer +
  known-staleness notes: ARCHITECTURE.md header still says PROPOSED /
  React 18, §3.8 still env-driven config), feature-roadmap (pointer).
- **Glossary**: 4 terms added to `02-technical-terms.md` (object ref,
  deep link, object handoff, SPA fallback — ADR-0040 vocabulary).
- **Reverse index** populated (first pinned concepts).
- `ASSUMPTIONS.md`: the "0001..0013 files not yet authored" note marked
  done.

## 2026-11-06 — KB updated for 235aa001..547fd93f (storage + network + PV batches, SSO login fix)

- **Invariants** (1 new): `object-view-annotation-trim.md` — the 4.1
  `trimAnnotations` shape is now the contract for every object data
  view (overrides the 2026-10-28 "render annotations verbatim"
  deviation; HPA 2026-11-04 `46929a10`, storage 2026-11-05 `f7c8223d`,
  network 2026-11-06). Claim literals grep-verified 2026-11-06.
- **Gotchas** (2 new, folder was scaffolded-empty):
  `datatables-react-stale-render-closure.md` (datatables.net-react
  binds Column render fns at init only — join late query data into the
  row, the Nodes.tsx pattern; the `window.location`-as-inert-memo-dep
  sibling class; `500e13e4` / `d75d6f1f` / `813b9026`) and
  `kube-pvc-bounded-phase-not-condition.md` (`--for=condition=Bound`
  can never pass on a PVC — wait on
  `jsonpath='{.status.phase}'=Bound`; `ce6d0b19`, QA gate F1).
- **Reference** (1 revised): `feature-roadmap.md` — recorded the
  four 2026-11-06 research-only spec folders
  (`2026-11-06-mcp-server`, `-ai-investigations`, `-change-timeline`,
  `-workload-map` — the latter with a draft briefing) as in-flight
  roadmap research; roadmap items themselves unchanged.
- **Glossary**: `observed tier` term added to
  `02-technical-terms.md` (late-resolving metrics view; ADR-0003
  degrade-don't-fail).
- **Recorded, no concept needed:** the SSO login flow completion
  (`c59dd4a9`) — the six breaks (GET-vs-POST `/auth/login`, IdP
  authorize redirect, `redirect_uri`, exchange kwargs, mock IdP gaps,
  e2e localStorage poll) were pre-QA implementation gaps inside the
  existing ADR-0025 flow, fixed with 2 regression tests; no new
  invariant (the contract already held). The PV consumer-side
  ref/SAR-group review fixes (`feb36175`) are test/edge corrections,
  not contract changes. No ADRs were minted in the window (next
  number remains 0041; the 2026-11-06 research findings feed it).
- `index.md` + `reverse-index.md` updated in the same edit
  (same-edit rule). `kb index` (scanned=46) + `kb lint: clean` after
  the writes.
- **Engine note:** `kb validate` reports `unresolved` for *every*
  ripgrep-anchored page in this project (pre-existing pages included,
  e.g. `invariants/session-cookie-transport.md`); `config.json`
  carries `anchor_engine: ""` (engine field empty in the scaffold), so
  the pin-check resolves no anchors here. The new pages' claim
  literals were grep-verified against the working tree by hand
  instead (each literal above appears in its anchor file). If the
  engine's anchor resolver is ever wired for this project, re-run
  `kb validate` on the three new pages to confirm.

## 2026-11-07 — decisions/04-adr-0022-sidebar-nav-4-1-parity.md amended

- **ADR-0022 amendment (menu merge, owner decision):** the Network
  sidebar group is consolidated to three leaves (Services, Ingress,
  Ingress Class). The standalone Gateway API and Gateway Class leaves
  (added by the 2026-10-28 specs) are absorbed into the 4.1 tab
  pattern: the Gateway API kinds (Gateway, HTTPRoute, ReferenceGrant)
  are tabs of the Ingress page, GatewayClasses is a tab of the Ingress
  Class page. The old URLs `/network/gateway-api` and
  `/network/gateway-class` one-shot redirect to their merged pages
  (ADR-0040 pattern; an active ref survives the redirect — the ref is
  session-scoped, not URL-bound). The ADR table Network rows are
  updated (Ingress + Ingress Class now implemented, tabbed). The
  `.backlog/decisions/decision-022` copy is regenerated from the ADR
  (same edit). Confirming tests: `nav.test.tsx` (labels, `Gateway API`
  banned again), `App.test.tsx` (dispatchers: gateway row → gateway
  detail on `/network/ingress`; gatewayclass row → gatewayclass detail
  on `/network/ingress-class`), ported list tests in
  `ingress.test.tsx` / `gatewayclasses.test.tsx`.

## 2026-11-08 — reference/06-research-findings.md added (change D close-out)

- New durable-findings concept (append-only, cross-change): jscpd dead-code
  detection characteristics from the 2026-11-07-dead-code-cleanup sweep —
  (1) false positives in JSX value/member position (2/187 findings;
  repairs 7a55bde3 Fragment, 17425c2f CIcon), (2) `index.*` entry-point
  heuristic blind spot masking barrel-only chains (views/icons barrel
  c40d4c49; components/header/ still open, TASK-099), (3) string-based
  wiring invisible to import analysis (wsgi spawn string, scheduler,
  test_file_map.py string pins — 23 backend files kept). Plus tooling note:
  `tsc --noEmit` is blind to .jsx without checkJs.
- `index.md`: reference/ row added.
- Source: `.skillgrid/xarchive/2026-11-07-dead-code-cleanup/report.md`
  (Surprises/Lessons), whole-branch review ReviewBranchD, per-task reviews.

## 2026-11-09 — 04-adr-0022 amendment corrected (network views review)
- In-place amendment fix: the 2026-11-07 menu-merge amendment said the
  Network group is "exactly Services, Ingress, Ingress Class" — factually
  wrong, the delivered nav also carries the two certmanager-external-
  loadbalancer Beta leaves (Cert-Manager, Load Balancer). Reworded to
  scope the "exactly" to the 4.1-parity leaves. Review fix from the
  three-axis review of the four archived network-view changes
  (`.skillgrid/xarchive/2026-10-28-{service-views,ingress-gateway-api-views,ingressclass-gatewayclass-views}/`
  + `2026-10-29-certmanager-external-loadbalancer-views`).
- `index.md`: unchanged (in-place amendment, no new concept row).

## 2026-11-09 — Redis removal: ADRs + corpus aligned on Postgres as the sole stateful dependency

- Continues TASK-109's docs work (DoD#5): the code carries no live Redis
  references (ADR-0029/0030/0031), but the ADR corpus still described Redis
  as the live mechanism in six in-force ADRs + five concept files.
- ADR bodies updated (in-force ADRs amended in place; superseded bodies
  retained per IRON RULE):
  - **ADR-0004** — SAR verdict cache: "cached in Redis" → Postgres `kv`
    table; new 2026-10-28 amendment (store moved off Redis; same key/TTL).
  - **ADR-0006** — RQ worker wording → pgqueue worker thread (claims on
    every replica, enqueue leader-gated); "docker run + PG + Redis" → PG
    sole stateful dependency; linking re-pointed to ADR-0029/0031.
  - **ADR-0019** — `/auth/verify` checks the Postgres `revoked_jtis`
    deny-list (ADR-0030; formerly a Redis set per ADR-0014).
  - **ADR-0025** — decision driver: session state now Postgres (`kv` +
    `revoked_jtis`) after the Redis removal.
  - **ADR-0028** — `[remote_cache]` mapping row: `redis_url` no longer in
    Settings; section not parsed (inert, retained for 4.1 format parity).
  - **ADR-0040** — object-handoff stash: Redis → Postgres `kv` table
    (three mechanism mentions).
- Not deleted, flipped/annotated (IRON RULE): ADR-0007 (superseded by
  ADR-0029) and ADR-0014 (superseded by ADR-0030) bodies retained as
  history; `index.md` status column now reads `superseded (by ADR-0029)` /
  `superseded (by ADR-0031)` for 0007/0008, matching `ASSUMPTIONS.md` § LOCKED.
- Concept files: `glossary/02-technical-terms.md` (RQ, Leader, Follower,
  Drift detection, Session revocation propagation, Deep link, Object
  handoff), `invariants/sar-verdict-cache-key.md`,
  `invariants/object-nav-no-url-identity.md`, `workflows/object-deep-link.md`.
- `ARCHITECTURE.md`: container diagram redrawn (no Redis box; single PG box
  carrying tasks queue + `kv` + `revoked_jtis`), worker bullet, external
  dependencies, service lines (timeline/audit/tls), §3.8 env table
  (`REDIS_URL` row dropped; `KUBEDASH_ROLE` semantics corrected), §3.9
  `/readyz` (database probe only), §5B.1 revocation (deny-list + leader
  reaper; ADR pointer → ADR-0030), §7.1/§7.2 (pgqueue worker; no redis
  subchart), §6.1 ingress revocation row, air-gap bundle (3 lines), §10
  security table (rate limiting), test tiers (Testcontainers PG only), §11
  Celery exit note.
- `.backlog/decisions/decision-004/-006/-019/-025/-028/-040` copies
  mirrored (same edit).
- Verified: `grep -ri redis .skillgrid` — remaining mentions are historical
  only (superseded ADR bodies 0007/0014, rejected options, "replacing
  RQ/Redis" phrasing, this log's history).
- Same sweep: `invariants/leader-only-rq-worker.md` +
  `workflows/leader-task-execution.md` rewritten (the leader-only-RQ-worker
  model → pgqueue: thread on every candidate, enqueue + reaper
  leader-gated, claims on every replica via SKIP LOCKED; anchors
  re-pinned to current code, verified 2026-11-09);
  `invariants/services-integration-boundary.md`, ADR-0013/0015/0016 task
  refs, `reference/feature-roadmap.md` + `reference/live-architecture.md`.

## 2026-11-10 — Leader election: advisory lock is PER-REPLICA, not the arbiter

- Corrected two pages written 2026-11-09 that called the advisory lock
  "the arbiter, so two replicas can never both hold it". Per
  `backend/app/core/leader.py` (`_binds()` → `{"rid": self.replica_id}`;
  module docstring, ADR-0031): the key is `hashtext(<own replica_id>)`
  — per-replica and session-local, deliberately NOT a cross-node mutex
  (a fixed key would let a second Leader object on the same engine
  report spuriously non-leader). The cross-replica/cross-node
  arbitration is the `leader_lease` row (1 s poll / 5 s beat / 10 s
  stale) + the `fence` LWW upsert (`WHERE fence = :f`, 0 rows →
  demote). Steady state: exactly ONE granted advisory lock (the
  leader's); followers hold none (they return before the lock attempt
  while the lease is fresh). The lock's role: session-death liveness
  marker, observable via
  `pg_locks.objid = hashtext(rid)::oid` (`classid = 4294967295`) ×
  `pg_stat_activity` (holder pid/state; `backend_start` ≈
  `leader_lease.acquired_at`).
- Files: `invariants/leader-only-rq-worker.md` (description + contract
  bullet + why), `workflows/leader-task-execution.md` (startup step 1 +
  failure behavior), `index.md` invariants row. Anchors/claims
  unchanged (`pg_try_advisory_lock`, `leader_lease` still in
  `leader.py`).
- Context: planned during the 2026-11-10-ha-status-page spec (the HA
  Status page's leader-election section — per-node lock cross-check +
  fence as election count; see
  `.skillgrid/specs/2026-11-10-ha-status-page/findings.md` F12–F14).

## 2026-11-10

- Added `gotchas/leader-fence-must-increment-in-upsert.md` (reflect of the
  2026-10-27-postgres-queue-revocation-active-active change). Lifts the one
  durable, non-obvious finding from that change's review: the leader fence is
  a per-acquire counter, so a SELECT-then-bind increment lets two peers hold
  an equal fence and voids ADR-0031's fencing. Pins three anchors in
  `backend/app/core/leader.py` (in-upsert increment, `RETURNING fence`, the
  heartbeat's `WHERE ... fence = :f`). Fixed in `da790985`; QA had passed the
  read-then-bind form, so the page is also the "green suite cannot see this"
  lesson. `index.md` gotchas row updated in the same edit.
- Deliberately *not* lifted: `tasks` retention for `done` rows (W035) — it is
  an open ADR-0029 amendment, not settled behavior, so the page only points
  at the window rather than documenting a rule.

## 2026-11-12 — 04-adr-0022 parity row corrected (runtimeclass views review)
- In-place amendment fix: the Other Resources → Runtime Class row still
  said `stub` for the 5.0 route although the stub route was removed and the
  real list + data views wired (2026-10-28, TASK-046). Amended to
  `implemented (feature)` per the priorityclass-row precedent (1bd5afab);
  the 4.1 route column notes the dead nav link (4.1 had no runtimeclass
  template). Review fix from the three-axis review of
  `2026-10-28-runtimeclass-views` (review.md in that folder).
- `index.md`: unchanged (in-place amendment, no new concept row).
