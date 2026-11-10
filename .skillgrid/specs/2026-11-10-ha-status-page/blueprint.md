# HA Status page — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution (recommended) or skillgrid:simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2 (read-only admin API + new page; no schema change)

**Build shape:** Tracer thread (Task 1: probe seam + assembly against fakes, endpoint live with one node's data → Task 2: per-node probes + derivation → Task 3: INI override → Task 4: frontend)

**Goal:** An admin-only `GET /api/v1/admin/ha-status` endpoint that reports the pgEdge active-active cluster's health (both replication directions, per-node reachability/lag/apply-workers/conflicts, leader lease, task queue, derived status + reasons) and a real `/settings/ha-status` page that renders it.

**Architecture:** A Flask-free `app/services/ha_status.py` with one seam — `probe_node(dsn) -> NodeProbe` — that opens a short-lived read-only SQLAlchemy engine per node DSN and runs a fixed set of spock read-only queries. The endpoint (`app/api/admin.py`) reads the cluster catalog from the app's engine, merges the optional INI DSN overrides, probes every node, assembles the report, and derives the overall status. The frontend gets a view folder (`src/views/HaStatus/`) with a TanStack Query 5 s poll; the route moves out of the Stub router.

**Tech Stack:** Flask 3 + Smorest, SQLAlchemy 2.0 (raw SQL via `text()`), PostgreSQL 17 (pgEdge/Spock 5.0.1). Frontend: React 19 + TS + Vite (CoreUI), TanStack Query, Vitest + RTL + MSW.

**Spec:** `.skillgrid/specs/2026-11-10-ha-status-page/briefing.md` (this change). Findings: `.skillgrid/specs/2026-11-10-ha-status-page/findings.md` — every spock object/behavior below was live-probed on the dev cluster (F1–F10).

## Terms

- **spock** — the pgEdge multi-primary replication extension (v5.0.1 here); its catalog lives in the `spock` schema. `.skillgrid/knowledge/glossary/02-technical-terms.md`.
- **per-node probe** — a short-lived read-only connection from the app to ONE cluster node, used to read that node's LOCAL spock state (subscription status, receive lag, apply workers).
- **node DSN override** — the optional INI map (`[ha] node_dsn_overrides`) that replaces a `spock.node_interface` DSN per node name (dev host reachability, findings F8).
- **leader lease** — the single-row `leader_lease` table backing KubeDash leader election (pg advisory lock + fence, ADR-0008/0031).
- **overall status** — the derived `healthy` | `degraded` | `down` verdict with reasons (briefing R4).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- An admin `GET /api/v1/admin/ha-status` → 200 with `spock_version`, `nodes[]` (one entry per `spock.node` member), `leader`, `queue`, `status`, `reasons`. A non-admin → 403 (the existing admin auth hook).
- Against the live dev two-node cluster: both `n1` and `n2` appear, both `reachable: true`, each with its OWN subscription `status: "replicating"` and a `lag` entry — i.e. **both** replication directions are reported, not just the connected node's half. *(F2/F3 — per-node local state)*
- The probed node name is part of each node entry (`node_name`), so a half view is visible, not silent. *(F3)*
- `docker stop kdpg-n2` → the endpoint still returns 200; the n2 entry is `reachable: false` (probe error classified, not raised); `status: "down"` with reason `node_unreachable:n2`.
- A probe's failure is a classification (unreachable), never a 500: a dead node, a timeout, and an auth error all yield `reachable: false` + a short `probe_error`.
- With `[ha] node_dsn_overrides = n2=postgresql://kubedash:kubedash@localhost:16433/kubedash` in the dev INI, the host backend reports n2 reachable even though `kdpg-n2` doesn't resolve on the host. *(F8)*
- The derived status follows the matrix: subscription not `replicating` or node unreachable → `down`; lag > 60 s, exception rows, stale heartbeat (> 10 s) or missing lease → `degraded`; else `healthy` — and every non-healthy verdict lists the matching reason string.
- The service issues **read-only** statements against spock objects (SELECT / function calls) — no INSERT/UPDATE/DELETE anywhere in the probe module. *(briefing R6 — `autoddl` would replicate an app write)*
- Frontend: `/settings/ha-status` renders the banner + per-node cards + leader + queue from the API (MSW fixture: healthy and degraded variants); the entry leaves `stubRoutes` and the nav path is `/settings/ha-status`.
- No new dependency in `pyproject.toml` and no new `values.yaml` key on the chart (the endpoint is in-cluster; the chart's single `DATABASE_URL` already reaches a node).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/ha_status.py` — `probe_node(dsn) -> NodeProbe`, `build_report(engine, dsn_overrides) -> HaReport`, status derivation.
- `backend/app/api/admin.py` — `GET /admin/ha-status` route + Pydantic response schema (added to the existing `AdminApi`).
- `backend/app/core/ini_config.py` + `backend/app/core/config.py` — the optional `ha_node_dsn_overrides` map (default empty).
- `backend/kubedash.ini` + `backend/kubedash.ini.example` — the `[ha]` section (dev value in the gitignored INI; documented optional in the example).
- `frontend/src/views/HaStatus/index.tsx` (+ parts) — the real view; `frontend/src/App.tsx` route; `frontend/src/views/Stub/routes.ts` entry removed.
- `backend/tests/services/test_ha_status.py` (unit, probe seam), `frontend/tests/views/HaStatus.test.tsx` (MSW happy + degraded), `frontend/e2e/ui-smoke.spec.ts` (route moved from the stub smoke list to the real-view list).
- `backend/tests/integration/test_ha_status_pgedge.py` (kind-gated, Testcontainers `pgedge/pgedge:pg17-latest` two-node) — the real-SQL backstop.

**Key links** (critical connections that must work together):
- `AdminApi.ha_status()` → `ha_status.build_report(db.engine, settings.ha_node_dsn_overrides)` → the Pydantic schema (field-for-field; no re-derivation in the API layer).
- `build_report` reads `spock.node` + `spock.node_interface` + `leader_lease` + `tasks` from the app engine, then calls `probe_node` per merged DSN; the probe results are keyed by `node_name` and joined onto the member list (a member whose probe failed is still listed, `reachable: false`).
- The view's query hook (`useQuery`, `refetchInterval: 5000`) → `GET /admin/ha-status` → banner/cards; the nav leaf + the e2e smoke list both point at `/settings/ha-status`.
- The INI override map is parsed once in `ini_config` (same pattern as the other optional keys) and exposed as `Settings.ha_node_dsn_overrides: dict[str, str]`.

**One-way-door decisions** (hard to reverse — explicit approval before implementing):
- None. The INI key is optional/additive; no schema, no dependency, no auth-flow change. (If the `[ha]` section name or the env alias turns out to clash with a future ADR, renaming an unused optional key is cheap.)

## Global Constraints

- Backend layering: `app/services/ha_status.py` is pure Python, **no Flask imports**; engine + overrides arrive as parameters. *(AGENTS.md § Conventions)*
- Read-only against spock: the probe module's SQL is a closed set of SELECTs/function calls; a code comment marks the module read-only-by-contract.
- Timeout budget: per-node `connect_timeout` ≤ 3 s; the endpoint's total wall clock is bounded by `nodes × 3 s + 1 s` (2 nodes → ≤ 7 s worst case) — a diagnostic page may be slow, it must not hang.
- Every per-node engine is created and **disposed in `finally`** (socket leak, dead node).
- Air-gap (ADR-0020): no new egress — probes reach only the cluster's own nodes.
- Config (ADR-0028): `[ha] node_dsn_overrides` is optional, empty default, no credential identity (reuses the app's DB user/password parsed from `DATABASE_URL`).
- No new third-party dependency.
- Frontend follows `frontend/STYLEGUIDE.md`; server state via TanStack Query; no Tailwind.
- Conventional commits; atomic work units; the spec zone (this folder) is committed before the code zone.

## File Structure

- `backend/app/services/ha_status.py` — new: `NodeProbe` dataclass, `probe_node(dsn, timeout)`, `_cluster_catalog(engine)` (node list + interface DSNs + leader_lease + tasks + spock_version), `build_report(engine, dsn_overrides)`, `derive_status(report) -> (status, reasons)`.
- `backend/app/api/admin.py` — add `GET /admin/ha-status` (Pydantic `HaStatusOut` response model).
- `backend/app/core/ini_config.py` — parse `[ha] node_dsn_overrides` (`name=url;name=url` → dict).
- `backend/app/core/config.py` — `Settings.ha_node_dsn_overrides: dict[str, str]` (default `{}`).
- `backend/kubedash.ini` — `[ha]` with the dev `n2=...:16433` override.
- `backend/kubedash.ini.example` — `[ha]` documented as optional.
- `frontend/src/views/HaStatus/index.tsx` (+ `HaStatusCard.tsx`, `types.ts`) — the view.
- `frontend/src/App.tsx` — real route `/settings/ha-status`.
- `frontend/src/views/Stub/routes.ts` — remove the entry.
- `frontend/e2e/ui-smoke.spec.ts` — move the route from the stub smoke list.
- `backend/tests/services/test_ha_status.py`, `frontend/tests/views/HaStatus.test.tsx`, `backend/tests/integration/test_ha_status_pgedge.py` — tests.

---

### Task 1: Probe seam + cluster catalog + report assembly (unit, fakes)

> Tracer: after this task the endpoint exists and renders ONE node's data (the app's own node) end-to-end; per-node fan-out is Task 2.

- [ ] `backend/tests/services/test_ha_status.py` (red): `probe_node` against a fake engine yields a `NodeProbe` (node_name, subscription status, lag, apply workers, conflict count); a raising probe → `reachable: false` + classified `probe_error`, never raises; `build_report` with a fake catalog + fake probe assembles `nodes[]` keyed by `node_name`; the probe SQL set contains no DML (assert on the executed statement texts).
- [ ] `backend/app/services/ha_status.py` (green): `NodeProbe` (dataclass), `probe_node(dsn, timeout_s=3.0)` — `create_engine(dsn, connect_args={"connect_timeout": 3})`, run the closed read-only set (F2/F3/F4/F5/F6: local node name, `sub_show_status` per local subscription, `lag_tracker`, `get_apply_worker_status`, `get_channel_stats` totals, `exception_status` count + last 10), dispose in `finally`; `_cluster_catalog(engine)` — `spock_version()`, `spock.node`, `spock.node_interface` (if_name/if_nodeid/if_dsn), `leader_lease` row, `tasks` counts + oldest pending; `build_report` — merge member list with probe results (unprobed member ⇒ `reachable: false`).
- [ ] `backend/app/api/admin.py`: `GET /admin/ha-status` (admin hook as its siblings), Pydantic `HaStatusOut`; wire `settings.ha_node_dsn_overrides` (empty for now).
- [ ] Verify: `cd backend && uv run pytest tests/services/test_ha_status.py -q && uv run pytest -m "not integration" -q` (unit floor stays green); live curl on the dev stack (admin cookie) returns 200 with both catalog sections.

### Task 2: Per-node fan-out + status derivation

- [ ] Tests (red): derivation matrix — (a) all good → `healthy`, no reasons; (b) one node `reachable: false` → `down` + `node_unreachable:<name>`; (c) a subscription `status != "replicating"` → `down` + `subscription_not_replicating:<node>`; (d) lag 61 s → `degraded` + `lag_exceeded:<node>`; (e) exception rows > 0 → `degraded` + `exceptions_pending:<node>`; (f) heartbeat 11 s old / lease missing → `degraded` + `leader_heartbeat_stale` / `leader_lease_missing`; combinations → all reasons listed, worst wins (`down` > `degraded`).
- [ ] `ha_status.py` (green): `build_report` probes **every** member (DSN = override.get(name) or the node_interface DSN with the app's credentials substituted — parse the keyword DSN, keep host/port/db, swap user + add password); `derive_status(report)`.
- [ ] Verify: unit tests green; dev stack — `docker stop kdpg-n2` → curl shows `down` + `node_unreachable:n2` (200, no 500); `docker start kdpg-n2` → back to `healthy` within one poll.

### Task 3: INI override (`[ha] node_dsn_overrides`)

- [ ] `backend/tests/test_ini_config.py` (red): `[ha] node_dsn_overrides = n2=postgresql://kubedash:kubedash@localhost:16433/kubedash` → `settings.ha_node_dsn_overrides == {"n2": "..."}`; absent section → `{}`; malformed entry → `ConfigError` (fail fast, ADR-0028).
- [ ] `ini_config.py` + `config.py` (green); `kubedash.ini` gets the dev `[ha]` section (n2 → :16433, F8); `kubedash.ini.example` documents it as optional.
- [ ] Verify: `uv run pytest tests/test_ini_config.py -q` green; restart the dev backend — `/api/v1/admin/ha-status` now reports n2 `reachable: true` with its own subscription + lag (the full two-direction view from the host, F2/F3/F8).

### Task 4: Frontend view + route move

- [ ] `frontend/tests/views/HaStatus.test.tsx` (red, MSW): healthy fixture → green banner "HA healthy", one card per node (name, `replicating` chip, lag, conflicts 0), leader section (replica_id, fence, heartbeat age), queue section (counts); degraded fixture (n2 unreachable) → red banner with `node_unreachable:n2` reason, n2 card marked unreachable; error state (500) → banner "status unavailable".
- [ ] `frontend/src/views/HaStatus/` (green): `index.tsx` (useQuery `refetchInterval: 5000`), `HaStatusCard.tsx`, `types.ts` (mirrors `HaStatusOut`); CoreUI styling per STYLEGUIDE.
- [ ] Route move: `App.tsx` real route; `stubRoutes` entry removed; `e2e/ui-smoke.spec.ts` — the route leaves the stub smoke list (the real view is covered by the page test + e2e admin smoke).
- [ ] Verify: `cd frontend && corepack pnpm test -- HaStatus` + `corepack pnpm test -- Stub` green; `task fe-build` + `task fe-sync`; dev-stack browser check as admin: Settings → HA Status renders the live cluster.

### Task 5: Integration backstop (kind-gated)

- [ ] `backend/tests/integration/test_ha_status_pgedge.py`: two `pgedge/pgedge:pg17-latest` Testcontainers (same pattern as the dev db.json: autoddl + `pgedge` internal_admin user), two subscriptions, `build_report` against n1 with the n2 DSN override → asserts both directions `replicating`, both reachable, `healthy`.
- [ ] Verify: `task kind-up && cd backend && uv run pytest -m integration tests/integration/test_ha_status_pgedge.py -q` (or the dev-stack e2e if Testcontainers is env-blocked on the host — F10 note).

## Self-Review

- Every briefing requirement (R1–R6) maps to a Task + a Truth: R1→T1/T4, R2→T2, R3→T3, R4→T2, R5→T4, R6→T1 (read-only assertion) + Global Constraints.
- The seam (`probe_node`) is the single place real spock SQL lives — drift risk (Threat 2) is contained to one module + one integration test.
- No stubs left: the route leaves `stubRoutes` in the same commit as the view lands.

## Owed-Decision Gate

None open. The lag threshold (60 s) and heartbeat staleness (10 s, matching `leader.py`'s existing stale window) are service constants — tunable later without an ADR.

## Threat Matrix

| Threat | Mitigation | Verified by |
|---|---|---|
| Dead node hangs the request | per-node `connect_timeout` 3 s + disposed engine; total budget `nodes×3 s + 1 s` | T2 truth (stop n2 → 200 in < 7 s) |
| spock catalog drift across pgedge releases | closed SQL set in one module; integration test against `pgedge/pgedge:pg17-latest` | T5 |
| Half view (only the connected node's state) reported as full | probe every member; per-entry `node_name`; member-without-probe ⇒ `reachable: false` | T2 truths (both directions present) |
| Socket leak on unreachable nodes | `finally: engine.dispose()` | T1 (disposal asserted with fakes) |
| App writes to `spock.*` get replicated by `autoddl` | read-only-by-contract module; DML-free assertion on the executed statements | T1 truth |
| Override DSN carries credentials → leak in the UI | the response shows host:port + node name, never the DSN string | T4 (types render host/port only) |

## Execution Handoff

Slice with `skillgrid:slicing` into tickets (T1–T5 are natural ticket boundaries; T1+T2+T3 = backend, T4 = frontend, T5 = integration). Execution per `skillgrid:subagent-execution`. Definition of Done: unit floor green, `task fe-build` + `task fe-check` green, dev-stack page verified in the browser as admin, `task e2e` when the SPA surface changed.
