# Review — HA Status page (admin endpoint + settings view)

**Change:** `.skillgrid/change-specs/2026-11-10-ha-status-page`
**Generated:** 2026-11-13 (code-review phase, after the first QA gate PASS — `report.md`)
**Diff:** `1d401eac~1..039f7d89` (branch `rebase`) — the change's 7 commits
(1d401eac route rename · 2e1b76cc route amendment · e00024fc API+service+tests ·
298415df view+tests+stub removal · 6963fc83 probe fix · b2330f69 cards+lease ·
959a3833 `/clusters` 4.1-parity rewrite) + first-gate fix commit 039f7d89 (e2e).
The review-fix gate's changes (31 findings) sat in the working tree at review
time and were re-verified before commit (report.md § Review-fix gate).
**Rigor tier:** T2 · **Independence:** 8 fresh subagent lenses (standards,
security, verification-gaps, performance, edge-cases, accessibility, spec +
red-team last) — no shared session history with the implementer (Grade B
per `_shared/planning/rigor-tiers.md`). Lens transcripts are the raw record
(`history://<Lens>`); this file is the disposition record.

## Findings & disposition

### Standards (11: 7 minor, 1 important, 3 FYI)
| Finding | Disposition |
|---|---|
| `QueueOut` drops pgqueue's terminal `failed` dead-letter status | **Fixed** — schema `failed` (dump_default 0) + UI row + API wire test |
| `probed_at` used process-local `time.strftime` instead of repo `datetime.now(UTC)` | **Fixed** |
| `ConfigError` "missing required config" misdiagnoses a malformed `node_dsn_overrides` | **Fixed** — `reason` param; malformed now says "malformed config …" |
| Probe engines had connect timeout but no statement timeout (wedged node unbounded) | **Fixed** — `statement_timeout` on both probe engine forms |
| `candidates: null` unreachable through the endpoint, yet schema+UI model it | **Fixed (spec)** — feature text + briefing note; schema/UI keep the defensive optional |
| No API-tier test for `GET /admin/ha-status` | **Fixed** — `tests/api/test_ha_status.py` (200+wire, 403) |
| FYI: dead import-check assertion in `test_dsn_overrides_empty_default` | **Fixed** — removed |
| FYI: `_SettingsProxy` return annotation on public `get_settings`; function-level `urllib.parse` import | no-action (style) |
| ha_status.py 581 lines (~300 split signal crossed; admin.py 318 / clusters.py 312 too) | no-action (cohesive module; split speculative) |
| Cluster-admin gate block duplicated between update/delete | no-action (shared `_require_cluster_admin`; messages differ) |

### Security (3: 2 Low, 1 Info)
| Finding | Disposition |
|---|---|
| (Low) `nodes[].dsn` leaked the full keyword DSN (`user=`/`password=`) on the in-cluster default path | **Fixed** — `_dsn_display` keyword handling; test asserts user/password never shown |
| (Low) malformed catalog DSN escaped the degrade-not-fail contract (`_probe_engine` raised before the try → 500) | **Fixed** — parse inside the probe's try; `test_probe_node_malformed_dsn_is_a_result` |
| (Info) `leader.token` (per-process UUID) exposed in the admin response | no-action — intentional (lease-row report per spec; not rendered in UI; no decision path reads it) |

### Verification gaps (9, VG1–VG9)
| Finding | Disposition |
|---|---|
| VG1 no backend test hits the endpoint | **Fixed** (with Standards "no API-tier test") |
| VG2 blueprint-mandated `test_ha_status_pgedge.py` backstop missing | **W043** (open; keyword-DSN unit tests landed this gate) |
| VG3 keyword-DSN branch of `_probe_engine` untested | **Fixed** — credential-substitution + display + statement_timeout tests |
| VG4 `_dsn_display` returned the raw keyword DSN | **Fixed** (with Security Low) |
| VG5 `_interval_to_seconds` timedelta branch untested | **Fixed** |
| VG6 `/settings/cluster-status` route registration unpinned | **Fixed** — ui-smoke sweep else-if (Leader Election heading + API report shape) |
| VG7 PUT platform-admin success branch untested | **Fixed** — `test_platform_admin_updates_unbound_cluster` (update + delete) |
| VG8 PUT kubeconfig 422 weakly pinned (`::not-yaml` is a valid scalar; `{bad` → 500) | **Fixed** — structural validation (`kubeconfig has no clusters`) + parametrized malformed-YAML cases |
| VG9 `KUBEDASH_REPLICA_COUNT` env in deployment.yaml unasserted by test_chart.py | **W046** (open) |

### Performance (5)
| Finding | Disposition |
|---|---|
| Node probes serialized — worst case 6 s > the 5 s poll interval (sync-worker slots) | **Fixed** — `ThreadPoolExecutor` per node; worst case ≈ one node's 3 s budget |
| No `statement_timeout` on probe SQL | **Fixed** (with Standards) |
| `get_pod`/`get_deployment` unbounded (kubernetes 37 sets no default timeout) | **Fixed** — `_request_timeout=2` on both reads (repo precedent: stats/summary) |
| Admin K8s client rebuilt per request (TLS handshake per 5 s poll) | **Fixed** — `K8sClientPool.get_admin_client` cached seam |
| Queue count = full-table `GROUP BY` on the never-purged `tasks` table, per 5 s poll | **W047** (open; root cause W035) |

### Edge cases (10)
| Finding | Disposition |
|---|---|
| Hung K8s API pinned the request thread (5 s polls coalesce into it) | **Fixed** (with Performance #3) |
| Reachable node with empty `spock.local_node` (unjoined) → `other:IndexError` | **W049(b)** |
| Split brain: two reachable nodes both reporting the leader lock renders healthy | **W049(a)** |
| Multiple `spock.lag_tracker` rows, no ORDER BY — arbitrary row decides the lag alarm | **Fixed** — worst-lag aggregation (`test_probe_worst_lag_wins_across_subscriptions`) |
| Malformed `kubedash_replica_count` (abc/0/negative → 1) fallback untested | **W049(c)** |
| Transient 500 on a poll flips the page to the error banner, hiding the last good report | **W049(f)** |
| `formatLag` KiB/MiB boundary unobserved (every fixture `lag_bytes: 0`) | **W049(e)** |
| `postgres://` shorthand rejected by the override parser | **Fixed** — accepted alongside `postgresql://` |
| Typo'd name in `node_dsn_overrides` silently dropped | **W049(d)** |
| Keyword-format DSN path untested | **Fixed** (with VG3) |

### Accessibility (8)
| Finding | Disposition |
|---|---|
| Save error rendered behind the open modal's backdrop (Clusters) | **Fixed** — rendered in the dialog (role=alert) |
| No aria-live for the 5 s in-place updates | **W048** |
| KV tables use plain `td` row labels (no `th scope=row`) | **W048** |
| Conflict / pending-exception / stale-heartbeat states flagged by color only (×3) | **W048** |
| Kubeconfig keep-stored hint not `aria-describedby`-associated | **W048** |
| Add-Cluster submit disabled while invalid, no discoverable reason | **W048** |

### Spec (8: 2 wrong_implementation, 2 spec_drift, 2 missing_or_partial, 1 spec_zone_gap, 1 scope_creep)
| Finding | Disposition |
|---|---|
| Page rendered no status banner and never rendered `node_unreachable:n2` (live-confirmed) | **Fixed** — banner + reasons (MSW + e2e pinned) |
| R2 credential substitution on the keyword path unimplemented — probing as `pgedge` failed host auth (`fe_sendauth: no password supplied`, live-confirmed) | **Fixed** — app-credential substitution + unit pin; briefing clarification records the first gate's pgedge design note as superseded |
| `candidates` never null through the endpoint (un-specced `KUBEDASH_REPLICA_COUNT` fallback, live = 1 in dev) | **Fixed (spec)** — W044 closed: feature text updated + briefing note |
| Acceptance "boot fails with a ConfigError" for a malformed override, but the parse was request-time (500) | **Fixed** — boot-time validation of `[ha]` |
| Blueprint pgEdge integration artifact missing (spec_zone_gap + missing_or_partial ×2) | **W043** / covered by the first-gate live dev-stack verification |
| 039f7d89 bundled another change's deep-link csrf-echo test fix (scope_creep, minor, test-only) | no-action — noted |

### Red team (8, last lens)
| Finding | Disposition |
|---|---|
| `classid = 4294967295` matches only NEGATIVE `hashtext(rid)`; pod-name replica_ids hash positive (~50%) → election degraded forever in prod (live-verified both signs) | **Fixed** — `_LOCK_SQL` CASE on the hash sign + regression tests |
| ha-status can pin a sync worker 6+ s; 5 s polling exhausts the slots, starving liveness | **Fixed** — parallel probes (worst case ≈ 3 s) + statement_timeout |
| PUT rotates kubeconfig but `K8sClientPool` cached by cluster id with no invalidation | **Fixed** — `pool.invalidate(cluster_id)` on update + delete |
| `QueueOut` dropped the `failed` dead-letter count (also Standards) | **Fixed** (deduped) |
| Gate/list assumed one binding per (user, cluster); the 4-tuple uq allows multiple → `MultipleResultsFound` 500s | **Fixed** — `.first()` on the gate's admin-binding query |
| View gated Edit/Delete on platform role only; the API gate also admits cluster admins the UI hid | **Fixed** — row `role === 'admin'` OR platform admin (test-pinned) |
| `smoke.spec.ts` still asserted "Bound clusters" + the old inline register form — the rewrite broke that journey | **Fixed** — journey rewritten (OIDC login → clusters → Add-Cluster modal → row click → status page) |
| PUT accepted any YAML mapping; a doc without `clusters` 200'd then 500'd on first use | **Fixed** — structural validation (422 `INVALID_KUBECONFIG`) |

## Tally

**31 fix-now findings — all fixed at the review-fix gate and re-verified**
(backend floor 902 + 88 targeted on the final tree; vitest 508 with the
documented W042-class load flakes, affected files 100% standalone; e2e 20/20
incl. the rewritten journey and the row-click leg; live probes on the dev
two-node cluster — report.md § Review-fix gate).
**5 parked → W043 (updated) + W046, W047, W048, W049 (new).**
**No-action:** Security Info (leader.token), Spec scope_creep (test-only
commit bundling), Standards style FYIs ×2, module-size advisory, gate-block
duplication.

## Verdict

**met-with-fixes** — every CRITICAL/HIGH finding (classid sign, probe
credential auth, dead-letter visibility, pool staleness, gate cardinality,
unbounded request paths, broken e2e journey, missing banner) was fixed and
re-verified at the gate; residuals are tracked as W043/W046–W049 with named
follow-ups. Route: **ship** (state: review complete).
