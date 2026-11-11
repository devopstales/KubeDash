# Report — 2026-10-27-postgres-queue-revocation-active-active

| | |
|---|---|
| Change | `2026-10-27-postgres-queue-revocation-active-active` (TASK-042/043/044, TASK-106/107/108/109) |
| Phase reached | `qa` (2026-11-10) |
| Scope under test | commits `54486251^..5ad77ff0` on `rebase` — 16 commits, TICKET-01…07 |
| Verdict | **CONCERNS** — 2 unautomated acceptance scenarios (live-verified only), 2 artifact/evidence gaps, no CRITICAL |
| Gate run | `skillgrid:qa`, four-state floor, 2026-11-10 |

Replaces RQ + Redis with the Postgres `tasks` queue (ADR-0029), Postgres `kv`
store for the revocation deny-list / OIDC state / SAR cache (ADR-0030), and a
two-node pgEdge/Spock dev stack (ADR-0031).

---

## 1. Test Plan

| # | Tier | Command | Result |
|---|---|---|---|
| 1 | Change-scoped unit | `uv run pytest tests/models/test_new_tables.py tests/core/test_pgqueue.py tests/core/test_leader_fence.py tests/core/test_kvstore.py tests/services/test_revocation.py tests/core/test_security_revocation.py tests/services/test_rbac_cache.py tests/test_worker_gate.py tests/test_no_redis_imports.py -q` | **51 passed** (38.11 s) |
| 2 | Unit floor (CI gate) | `uv run pytest -m "not integration" -q` | **847 passed, 10 deselected** (190.74 s) |
| 3 | Post-fix re-verify | `uv run pytest tests/api/test_auth.py tests/core/test_leader_fence.py -q` | **21 passed** |
| 4 | Post-fix re-verify | `uv run pytest tests/test_leader.py tests/test_worker_gate.py tests/models -q` | **20 passed** (19.12 s) |
| 5 | Lint (change files) | `uv run ruff check <changed app/test files>` | **All checks passed** |
| 6 | Lint (repo-wide, CI form) | `uv run ruff check .` | 62 errors — all pre-existing, none in this change's files (W013) |
| 7 | Types | `uv run mypy app` | 79 errors / 17 files — all pre-existing; this change's own error fixed (80 → 79) |
| 8 | Live infra | `docker ps`, `docker exec kdpg-n1/n2 psql …` | two-node pgEdge healthy 19 h; no redis container; autoddl propagated (see §2) |
| 9 | Automated infra test | — | **none exists** (see §4) |

Integration tier (`-m integration`, kind + Testcontainers) was not run: not
required by this change's CI path and Docker-in-kind is unavailable in this
session. Recorded as a verification-scope limitation, not a pass.

---

## 2. Goal-Backward Verification

Derived from `briefing.md` goals; each truth checked bottom-up against
observable behaviour.

| # | Truth (pre-derived) | Status | Evidence |
|---|---|---|---|
| T1 | A task enqueued in Postgres is claimed once and only once | VERIFIED | `test_enqueue_then_claim_returns_path`, `test_two_concurrent_claimers_do_not_double_claim` (two real connections, `SKIP LOCKED`) |
| T2 | A failing task retries with backoff and dead-letters after 3 attempts | VERIFIED | `test_fail_dead_letters_at_three_attempts`, test_fail_backoff_requeues, test_backoff_curve |
| T3 | A crashed claimer's rows are reaped back to `pending` | VERIFIED | `test_reaper_requeues_stale_processing`, `test_reap_once_sweeps_when_leader` |
| T4 | A stale leader cannot write past its lease | VERIFIED | `test_stale_fence_write_affects_zero_rows`; `leader_lease.fence` NOT NULL live on n1 |
| T5 | Logout makes the access token unusable immediately | VERIFIED | `test_logout_revokes_the_access_token_jti` (added at this gate) — row in `revoked_jtis` + replay `401 token revoked` |
| T6 | A revoked `jti` is rejected on any replica | VERIFIED | `test_verify_jwt_rejects_a_revoked_jti` (deny-list read goes to `kv`/`revoked_jtis`, no process state) |
| T7 | An OIDC `state` is single-use | VERIFIED | `test_new_state_is_stored_and_consumed_once` + `test_consume_state_unknown_state_raises` |
| T8 | A SAR verdict is cached hit-path without re-asking the cluster | VERIFIED | `test_cache_hit_never_asks_the_cluster`, `test_cache_hit_serves_denial_from_kv` |
| T9 | No module imports `redis`/`flask_redis` | VERIFIED | `tests/test_no_redis_imports.py` (2 tests: import scan + `pyproject` deps) |
| T10 | `task dev-up` brings two pgEdge nodes and no redis | PRESENT_BEHAVIOR_UNVERIFIED | live: `kdpg-n1`/`kdpg-n2` `pgedge/pgedge:pg17-latest` up 19 h healthy, `spock.node` = n1,n2 on both, zero redis containers — **but** the backend `/health` check against this stack was not re-run at this gate, and no automated test asserts the topology |
| T11 | A migration applied on one node reaches the other | VERIFIED | live: `tasks`/`revoked_jtis`/`kv`/`leader_lease` all present on **n2** after the n1 migration; no automated test (W028) |

Weakest truth: **T10** → caps the floor below PASS.

---

## 3. Traceability Matrix

All 12 scenarios in `acceptance.feature`.

| # | Scenario | Test | Status |
|---|---|---|---|
| 1 | `enqueue-then-claim` | `test_pgqueue::test_enqueue_then_claim_returns_path` | COMPLIANT |
| 2 | `concurrent-claimers` | `test_pgqueue::test_two_concurrent_claimers_do_not_double_claim` | COMPLIANT |
| 3 | `failed-task-retries-and-dead-letters` | `test_fail_dead_letters_at_three_attempts` + `test_fail_backoff_requeues` + `test_backoff_curve` | COMPLIANT |
| 4 | `crashed-claim-reaper` | `test_reaper_requeues_stale_processing` + `test_worker_gate::test_reap_once_sweeps_when_leader` | COMPLIANT |
| 5 | `stale-leader-write-fenced` | `test_leader_fence::test_stale_fence_write_affects_zero_rows` | COMPLIANT |
| 6 | `logout-revokes-jti` | `test_auth::test_logout_revokes_the_access_token_jti` (added at gate) | COMPLIANT |
| 7 | `revoked-jti-rejected` | `test_security_revocation::test_verify_jwt_rejects_a_revoked_jti` + `test_revoked_jti_returns_401` | COMPLIANT |
| 8 | `oidc-state-single-use` | `test_kvstore`/`test_security_revocation`: `test_new_state_is_stored_and_consumed_once`, `test_consume_state_unknown_state_raises` | COMPLIANT |
| 9 | `sar-cache-hit` | `test_rbac_cache` (3 tests, incl. `test_cache_hit_never_reasks_the_cluster`) | COMPLIANT |
| 10 | `no-module-imports-redis` | `tests/test_no_redis_imports.py` | COMPLIANT |
| 11 | `dev-up-brings-two-pgedge-nodes-with-no-redis` | — | **PARTIAL** (live-verified only, W028) |
| 12 | `migration-run-on-one-node-propagates-to-the-other` | — | **PARTIAL** (live-verified only, W028) |

10/12 COMPLIANT, 2/12 PARTIAL, 0 MISSING, 0 CONTRADICTED.

Gate-status coverage: the change touches a migration (schema) and the queue —
both exercised above. No scenario exists for the `kv` TTL reap path on the
sqlite tier (see W032); not in `acceptance.feature`, so not PARTIAL.

---

## 4. Verification-Gap Audit

| Gap | Class | Disposition |
|---|---|---|
| Scenarios 11/12 assert the dev stack shape; no test (pytest) can express `docker compose up` without Testcontainers/kind | manual-only | WARNING — W028; `task dev-up` is a developer task, and the two one-way gates were run live at execution (0e969d3c2e02 migration, two-node pgEdge autoddl) |
| Blueprint names `backend/tests/core/test_pgqueue_crash.py` as a deliverable; the file does not exist | artifact drift | WARNING — W029; the behaviour *is* covered by `test_pgqueue::test_reaper_requeues_stale_processing`, so this is a plan/artifact mismatch, not a behaviour gap |
| `kv_reap` / `kv_delete` have `now()` without a sqlite branch (`kv_get`/`kv_set` do) | untested path | SUGGESTION — W032; the api-tier sqlite app never calls `kv_reap` (only the Gunicorn worker on Postgres) |
| No `.skillgrid/sdd/2026-10-27-postgres-queue-revocation-active-active/` ledger | evidence | WARNING — W030 |
| Integration tier not executed this gate | scope | recorded in §13, not a finding (no integration test in this change's CI path) |

No gap where a scenario's *user-visible* behaviour is unexercised by any tier:
the two PARTIALs are dev-infrastructure assertions, and both were run live.

---

## 5. TDD Evidence Audit

No RED/GREEN evidence table exists for this change and there is no execution
ledger under `.skillgrid/sdd/`. Tickets were executed as co-committed `feat`
units (16 commits, `54486251^..5ad77ff0`), matching the branch-wide pattern
recorded in W015/W021 for changes executed before the ledger discipline.

| Ticket | Recorded RED | Verdict |
|---|---|---|
| TICKET-01…07 | none | EVIDENCE_ABSENT (advisory) |

The deterministic check is explicitly advisory when the table is absent (it may
never escalate to CRITICAL on absence alone), so this is recorded as W030
(WARNING), not as a MISSING_RED floor failure. Behaviour is nevertheless covered:
every acceptance scenario has a named test, and two of them (`logout` deny-list
wiring, `worker_gate` reaper) were shown to be *unpinned before* being added or
inspected at this gate — the logout gap was real and was closed here.

---

## 6. Assertion Quality Audit

Spot-checked every test backing scenarios 1–10 for vacuous or over-mocked
assertions.

| Check | Result |
|---|---|
| Asserts observable output, not mock calls | clean — `test_pgqueue` asserts DB row state (`status`, `attempts`, `claimed_by`) after real SQL; `test_leader_fence` asserts `rowcount == 0` |
| No `assert True` / no assertion-free tests | clean |
| Mocks confined to the seam | clean — `test_rbac_cache` monkeypatches `_sar_allowed` (the cluster seam) and keeps `kvstore` real; `test_security_revocation` uses a real sqlite engine |
| Negative paths asserted | clean — denial (`test_cache_hit_serves_denial_from_kv`), replay 401, unknown state raises, dead-letter after 3 |
| Real concurrency, not simulated | clean — `test_two_concurrent_claimers…` uses two engines/connections against the same DB |

No weak-assertion finding.

---

## 7. Coverage

`config.yaml` has no `testing`/`quality` coverage section → **N/A** (defaults,
no threshold configured). No coverage run performed or claimed.

---

## 8. Test Quality & Strategy

- Tier placement is right: queue/kv/leader logic is unit-tested against real
  SQL (sqlite for the api tier, Postgres-only branches guarded), so the tests do
  not need kind.
- Dialect split is the main strategic risk: `pgqueue` and `kvstore` carry
  sqlite branches to keep the unit floor cheap, which means the
  `FOR UPDATE SKIP LOCKED` path can only be proven on Postgres. It is proven —
  by the live two-node stack and by the `claim` implementation — but not in CI.
  This is the same class as W028 and is folded into it.
- Suite runtime is acceptable: 51 change tests in 38 s; full floor 191 s.
- Flake risk: `test_two_concurrent_claimers…` is order-independent (both
  claimers must get distinct rows); no timing sleeps beyond the backoff clock
  injection in `test_backoff_curve`.

---

## 9. Security (manual mode)

No `security` section in `config.yaml` and no Trivy/Semgrep baseline recorded
for this change → manual review of the diff's security surface.

| Surface | Finding |
|---|---|
| Session revocation | Stronger than before: logout now deny-lists the access-token `jti`, so a stolen access token dies at logout instead of at TTL. Deny-list read is per-request against `revoked_jtis`/`kv` — no process-local cache to go stale across replicas (ADR-0025/0030 honored) |
| `verify_jwt` → `UUID(claims["jti"])` | `jti` is minted as `str(uuid.uuid4())`; a foreign/hand-made token with a non-UUID `jti` raises `ValueError` rather than 401 → SUGGESTION W034 (not exploitable for auth bypass; it is a 500 on a forged token) |
| Committed credential | `dev/pgedge/db.json` carries the pgEdge `internal_admin` password `z1Zsku10a91RS526jnVrLC39` — the published example credential for the dev container, dev-only, and already documented in the briefing's Owed-Decision Gate; the app's own creds stay dev defaults. Flagged as W031 so it is not reused outside `dev/` |
| SQL | All new SQL is parameterized (`text()` + bound params); `claim`'s `SKIP LOCKED` is fixed text. No string interpolation of identifiers |
| Air-gap (ADR-0020) | Removing Redis strictly narrows the runtime surface; no new outbound call. No frontend change in this diff, so `task fe-check` is untouched |
| Secrets in code | none in `app/` (grep: no `redis`, no hard-coded JWT/enc keys outside test fixtures) |

---

## 10. Code Quality Gate

| Gate | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | repo-wide **62 errors, all pre-existing** (W013); this change's files **clean** — the two errors it introduced (E501 in `leader.py`, I001 in `models/__init__.py`) were fixed in-gate → PASS (baseline-relative, per recorded convention) |
| Types | `uv run mypy app` | **79 errors / 17 files**, all pre-existing; this change introduced 1, now fixed (80 → 79) → PASS (baseline-relative) |
| Import layer | `app/services/` has no Flask import | PASS — `rbac`/`revocation` take `Engine` and stay Flask-free |
| Migration | `migrations/versions/0e969d3c2e02_*` | PASS — applied live on n1, propagated to n2; no hand-edited dev schema |
| Config (ADR-0028) | no new hard-coded identity defaults | PASS — `kubedash.ini` + example updated together |
| ADR gate | ADR-0029/0030/0031 present, indexed in `ASSUMPTIONS.md` § LOCKED | PASS |

The repo-wide lint/type floor is red on `rebase` independently of this change
(W013); CI runs the same two commands, so the branch will not go green until
that debt is paid. That is a branch-level blocker, not attributable here.

---

## 11. Duplication

`config.yaml` has no `duplication` section and no jscpd baseline → **N/A**.
Not measured; not claimed.

---

## 12. State Drift

| Artifact | Drift |
|---|---|
| `state.yaml` | was `phase: executed`; set to `qa` by this gate |
| `tasks.md` | stale `**STATUS:** sliced` banner → corrected to `qa` |
| `briefing/blueprint` | blueprint's `test_pgqueue_crash.py` file was never created → W029 (behaviour covered) |
| OKF / ADR index | consistent: 0029/0030/0031 present and marked in-force; no dangling reference to `redis` in the decisions index |
| Generated `qa-gate.mjs` checks | **could not run**: the script resolves project-local `.agents/skills/verification/qa/scripts/` and `<root>/scripts/*.mjs`, neither of which exists here (`state_drift`, `size_budget`, `adr_invariants` report "script not found"). Drift/OKF/banner/traceability/TDD checks were done by hand above → limitation |

---

## 13. Verification Scope

| Dimension | Covered | Not covered |
|---|---|---|
| Backend unit | ✅ 847 passed (CI floor) | — |
| Integration (kind + Testcontainers) | — | not run (not in this change's CI path; no Docker-in-kind this session) |
| Live dev stack | ✅ two-node pgEdge, autoddl, fence column, no redis | backend `/health` against the stack not re-run |
| Frontend | n/a (no frontend change) | — |
| Chart | n/a (no chart change in this diff) | — |
| Security | ✅ manual review of the diff | no Trivy/Semgrep baseline configured |
| Duplication | — | no jscpd baseline configured |

---

## 14. Floor (four-state gate)

| Dimension | State |
|---|---|
| Goal-backward | PARTIAL (T10 backend-health clause unverified this gate) |
| Traceability | PARTIAL (2/12 scenarios manual-only) |
| Verification gaps | WARNING (3) |
| TDD evidence | advisory absent (W030) |
| Assertion quality | clean |
| Coverage | N/A |
| Test quality/strategy | clean |
| Code-quality gates | PASS (baseline-relative; branch debt W013) |
| Security | WARNING (dev credential W031) |
| State drift | PASS after this gate's `state.yaml`/`tasks.md` fixes; script limitation noted |

**FLOOR: ✓ PASS with WARNINGS → CONCERNS.**

---

## 15. Findings

Closed in-gate (not carried): the missing logout→deny-list test
(`test_logout_revokes_the_access_token_jti`), the two lint errors this change
introduced in `leader.py`/`models/__init__.py`, and the one mypy error it
introduced.

Parked to `.skillgrid/WINDOWS.md`:

| ID | Severity | Finding |
|---|---|---|
| W028 | WARNING | Scenarios 11/12 (two-node `dev-up`, cross-node autoddl) have no automated assertion — live-verified only |
| W029 | WARNING | Blueprint artifact `backend/tests/core/test_pgqueue_crash.py` never created; behaviour covered by `test_pgqueue::test_reaper_requeues_stale_processing` |
| W030 | WARNING | No TDD evidence table / execution ledger for this change (retrofit, co-committed `feat` units) |
| W031 | WARNING | Dev pgEdge `internal_admin` credential committed in `dev/pgedge/db.json` (docs example, dev-only) — must not be reused outside `dev/` |
| W032 | SUGGESTION | `kvstore.kv_reap`/`kv_delete` lack a sqlite branch while `kv_get`/`kv_set` have one — untested on the api-tier sqlite app |
| W033 | SUGGESTION | Stale RQ prose in `app/tasks/*.py` docstrings after ADR-0029 (docs only; no imports) |
| W034 | SUGGESTION | `verify_jwt` does `UUID(claims["jti"])` unguarded — a forged non-UUID `jti` yields 500 instead of 401 |

0 CRITICAL, 0 FAIL-level, 4 WARNING, 3 SUGGESTION.

---

## 16. Gate Decision

**CONCERNS** — no CRITICAL finding; every hard gate passes on a
baseline-relative basis; but two acceptance scenarios rest on live evidence
only, one blueprint artifact is missing, and TDD evidence was never recorded.
Proceed to `skillgrid:requesting-code-review`; the WARNINGs above are
non-blocking and should be picked up by TASK-level follow-ups (W028 → an infra
smoke test or an explicit "manual gate" annotation on the scenarios).

### Human override

**Recorded 2026-11-10.** The gate returned CONCERNS (no CRITICAL). The change
owner instructed "ship" after reading the verdict, which is the explicit
override CONCERNS requires — so integration proceeded and the WARNINGs travel
with this archive instead of blocking. The two manual-only acceptance
scenarios (W028) are the accepted risk: live-verified once, never
regression-guarded.

---

## Final-State Facts

- **Shipped 2026-11-10** on branch `rebase`, kept as the deliverable and the
  rollback unit (no merge to `main`; that is a separate explicit act).
- **Commits** (oldest first): `4d793038` docs(qa) · `7db8346b` style(backend)
  · `73fcfed5` test(auth) · `30311403` docs(review) · `da790985`
  fix(leader) · `9738fd7a` docs(ship, archive) · `981524a8` docs(retro).
- **Integration evidence** (integrated tree, after all review fixes):
  `uv run pytest -m "not integration"` → **848 passed, 10 deselected**,
  186 s, exit 0. Change-scoped: 51 (QA), 41 then 29 (post-fix). `ruff` clean
  on every changed file; `mypy app` unchanged at the 79-error branch
  baseline (W013). No frontend or chart file changed, so `fe-build` /
  `fe-check` / `helm lint` were not re-run.
- **Archive move**: 7 files, `git mv`, `diff -r` against a pre-move snapshot
  empty; committed as pure renames (`9738fd7a`).
- **Debt carried**: W028 (manual-only scenarios), W029 (blueprint
  `test_pgqueue_crash.py` never created), W030 (no TDD ledger), W031
  (dev-only pgEdge credential in `dev/pgedge/db.json`), W032–W034
  (suggestions), W035 (no `tasks` retention — ADR-gated), W036 (missing
  indexes for claim/reap + `revoked_jtis.expires_at`).
- **Still owed**: an independent (Grade A) review — the recorded review is
  Grade C, diagnostic only.

## Acceptance Verdict

**CONCERNS + human override** — the shippable verdict from § 16, accepted by
the change owner. Every hard gate passes baseline-relative; 14 of 16
acceptance scenarios are automated, 2 rest on a single live observation
(W028). Not a PASS, and the difference is exactly those two scenarios.

## Decisions

- **Postgres is the broker** — `tasks` + `SELECT … FOR UPDATE SKIP LOCKED`,
  claiming on any replica, with only enqueue/scheduling leader-gated
  (ADR-0029). **Session revocation** moved to the Postgres `revoked_jtis`
  deny-list + `kv` store (ADR-0030), which removed Redis's last two consumers
  and let it leave the stack entirely. **Two-node pgEdge/Spock** with a
  strict fencing token on `leader_lease` (ADR-0031).
- **Fix-in-gate over park-in-gate** for the three review findings (fence
  atomicity, duplicated Bearer/cookie precedence, false docstring). Retention
  (W035) and index gaps (W036) were parked instead, because the task runner
  is an ADR-gated domain: no retention policy may be invented in code.
- **The fence increments inside the upsert** (`fence = leader_lease.fence + 1`
  → `RETURNING fence`), never as a read-then-bind.
- **Keep the work branch** — ship did not merge `main` (repo standing rule).

## Lessons

- **A green sequential suite cannot see an interleaving bug.** The
  read-then-bind fence passed the whole unit floor; only a reader asking "what
  if two peers commit between these lines" found it. For anything that grants
  authority across replicas, the test that matters exercises the interleaving.
- **A docstring is a claim and needs the same scrutiny as code.** "The reaper
  bounds the table" was false (the reaper resets stale rows; nothing deletes
  `done` rows) and it hid W035 from review for a whole change.
- **Lint and type debt hides in the last mile.** QA's first pass surfaced
  E501/I001 plus a `_heartbeat` annotation — cheap, but only if `ruff` runs on
  the changed files before the suite, not after.
- **Only enqueue needs the leader.** Claims must stay replica-agnostic or the
  queue serializes behind one pod; over-gating is as wrong as under-gating.
- **Archive root is configuration, not memory** — `.skillgrid/config.yaml`
  says `xarchive`, while the skills default to `change-archive/`.

## Patterns

- **Leader-gated enqueue + any-replica claim**: claim ordered by readiness,
  reaper with a stale threshold (120 s), `MAX_ATTEMPTS = 3` with exponential
  backoff, then dead-letter — a shape reusable for any future queue work.
- **One credential seam**: a single `_request_token()` that resolves
  Bearer-before-cookie, with the auth check binding `g.current_jti` once, so
  the accept path and the revocation path cannot disagree about which token
  is live.
- **Deny-list with expiry-driven reaping**: key by `jti`, store an expiry equal
  to the token's own lifetime, let a leader reaper drop expired rows — no
  unbounded growth by construction (contrast W035, where no such rule exists).
- **Single-statement authority tokens** (see the gotcha page below).

## Surprises

- `tasks` rows are **never deleted** — the queue grows without bound and no
  ADR defines retention (W035). The obvious assumption ("the reaper cleans
  up") is wrong twice over.
- A partial index on `status = 'pending'` **is** legal in Postgres, because
  text equality is immutable — while the `now()` predicate the blueprint
  correctly rejected is not. Two adjacent rules, easy to conflate.
- The queue's own unit tests need **Docker** (Testcontainers Postgres), so
  the "unit floor" is not a pure-Python floor.
- Deleting Redis removed a health signal the status surface had been reading:
  every `redis` reference had to be traced through compose, config, and docs,
  not just the two code consumers.

## Archive Summary

`.skillgrid/xarchive/2026-10-27-postgres-queue-revocation-active-active/` —
`briefing.md`, `blueprint.md`, `tasks.md`, `acceptance.feature`,
`findings.md`, this `report.md` (QA half + retro half + environment retro),
`review.md` (three axes, Grade C). The change replaced the Redis/RQ task
broker and the Redis revocation set with Postgres (ADR-0029/0030) on a
two-node pgEdge stack (ADR-0031), and shipped with 848 unit tests green on
`rebase`. Durable findings lifted to the vault: one gotcha page, the fence
atomicity rule. Next for this area: an independent review, then W035's
ADR-0029 amendment (retention) with W036's indexes in the same migration.

---

## Environment Retro

Run after ship on 2026-11-10 with `skillgrid:environment-retro`; adopted as
reflect's environment half. Harness findings only —
nothing here changes shipped code. Existing guardrails read first: `config.yaml`
(`testing.runner`, no coverage/quality/security sections), `scripts/*.py` collectors,
`.github/workflows/ci.yaml`, `.git/hooks/{pre-commit,commit-msg}`.

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| Automated checks | The QA and ship skills invoke project-local `scripts/qa-gate.mjs` and `scripts/state-lock.mjs`; neither exists — `scripts/` holds only Python collectors. Every gate run pays a failed lookup and hand-rolls the deterministic checks (state drift, size budget, ADR invariants), which is exactly where hand-rolled checks go quiet. | Vendor both scripts under `scripts/`, or add a `skillgrid.scripts_root` key to `.skillgrid/config.yaml` so the skills resolve the real location | session: `qa-gate.mjs` reported "script not found" for `state_drift`/`size_budget`/`adr_invariants`; `node scripts/state-lock.mjs` absent; `ls scripts` |
| Automated checks | Global git config sets `commit.gpgsign=true` + `gpg.format=ssh`, but the signing key is not in the ssh-agent: `git commit` fails with `Couldn't find key in agent?` | Load the signing key in the environment setup, **or** set repo-local `commit.gpgsign=false` — every commit on `rebase` is unsigned (`%G?` = N), so the global setting only creates friction | session: 2 failed commits; `git cat-file -p 1d401eac \| grep -c gpgsig` = 0 |
| Automated checks | `git add <paths> && git commit` is not index-exclusive in this workspace: unrelated in-flight spec files (`.skillgrid/specs/2026-11-10-ha-status-page/*`) were staged when the commit ran | Write the habit as `git commit --only -- <paths>` (or `git add -p`) in the commit contract so a concurrently-dirty index cannot sweep in another change | session: staged HA-status-page files appeared after an unrelated `git add`; had to `git reset` them |
| Navigation | `state.yaml` `pipeline.current_change` (`2026-10-29-session-object-navigation`, phase `qa`) did not identify the change actually being worked; with 23 `in_flight` entries (phases as stale as `slicing` from 2026-10-28) and no `.skillgrid/sdd/<change>/` ledger, the change's position had to be re-derived from `git log` | Add a state-hygiene rule: the phase transition that leaves a change must update `pipeline.current_change`, and the execution skills must write the per-change ledger | `state.yaml:13`; `ls .skillgrid/sdd` (no entry for this change) |
| Coding standards | The review found an ADR-stated *mechanism* (fence increment as LWW tiebreaker) implemented as read-then-write, which no sequential test can catch — QA passed it. This is a judgement gap, not a lintable pattern. | Add one line to the QA audit procedure: for every in-force ADR that states a concurrency mechanism, require a test that exercises the *interleaving*, not just the ordered sequence | `review.md` "Important" #1 vs `report.md` gate CONCERNS |
| Steering-file no-ops | `AGENTS.md`'s Artifacts table records `specs/` but no archive root, while the skills default to `.skillgrid/change-archive/` and this repo uses `.skillgrid/xarchive/` — every ship step needs a `config.yaml` lookup to avoid creating a second archive | Add the archive row to the Artifacts table (`change-archive` = `.skillgrid/xarchive/`) | session ship step; `.skillgrid/config.yaml:15` |
| Tool economy | A pytest summary piped through `tail -N` was swallowed twice, forcing the same ~190 s suite to be re-run to read the verdict | Run the suite to a log file, then grep `^(FAILED\|ERROR\|N passed)`; wrap it once in `scripts/` rather than re-typing the pipe per gate | session: full floor run re-executed after the summary was cut off; `/tmp/kd-ship-floor.log` |
| Information access | Mnemonic `mem_*` tools were unavailable in this runtime, so the ship/retro context could not be persisted and the QA/TDD evidence had to be reconstructed from commits | Enable the mnemonic MCP for agent runs, or make the execution skills write the ledger file directly so the evidence survives without the memory service | session: no `mem_save`/`mem_session_summary` tool exposed; W030 |

**Proposed follow-up tickets** (proposals only — nothing implemented here):

1. Vendor or wire `qa-gate.mjs` + `state-lock.mjs` (highest value: every QA/ship run benefits, and the drift/ADR checks currently only run when a human does them by hand).
2. Resolve the signing mismatch (load the key, or repo-local `commit.gpgsign=false`) plus the `git commit --only` habit — two mechanical failures in one session.
3. Add the archive row to `AGENTS.md`'s Artifacts table and the state-hygiene rule for `pipeline.current_change`.
