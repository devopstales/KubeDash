# KubeDash Test-Observability Pipeline — Design Briefing (requirements & intent)

> **STATUS:** `draft` (2026-10-17)

> **Role:** this is the *what* — the validated design/spec: problem, intent,
> requirements, success criteria. The companion `blueprint.md` is the *how*
> (implementation plan). Do not rename.

## Problem / Intent

The KubeDash 5.0 base structure now runs 68 backend tests and a Playwright
scaffold, but there is **no way to see test health at a glance**: results live
in terminal output, coverage is a number you have to remember, and there is no
load, security, duplication, or frontend-component testing at all. The dev
stack already ships **Prometheus + Grafana** (auto-provisioned datasource + a
file-based dashboard provider) — but Prometheus is "query-only" (ADR-0003) and
only self-scrapes; nothing pushes *test* results into it, and no dashboards
exist for it.

This change builds the **test-observability pipeline**: a set of local test
suites (unit, functional, frontend-unit, e2e, duplication, static security,
dynamic security, load) whose structured results are **pushed to Prometheus**
via a Pushgateway and **visualized in Grafana** on the existing dev stack. It
is a local, on-demand review tool driven from the root `Taskfile` — **not a CI
pipeline** (the repo has no GitHub CI by explicit decision).

## Purpose & Success Criteria

- **Purpose:** give every KubeDash developer a single `task test-all` that
  runs the full test matrix and surfaces pass/fail, duration, coverage,
  duplication, security findings, and load metrics on a live Grafana dashboard
  — no scrolling terminals, no forgotten coverage numbers, an at-a-glance
  green/red health picture.
- **Success criteria:**
  - `task test-all` runs all eight suites in order (no-app suites first,
    live-app suites last); each suite's result is pushed to the Pushgateway
    and appears in Grafana within one scrape interval (15 s).
  - `task test-unit` alone produces a push; the Grafana
    `kubedash-test-observability` dashboard shows pass/fail/skip by suite,
    duration, and coverage % for the backend unit tier.
  - Frontend component tests (Vitest + Testing Library) run **without a live
    backend** (MSW-mocked) and report coverage into the same dashboard.
  - The duplication suite (jscpd, Python + TypeScript) reports duplicated-line
    % and block count.
  - The static-security suite (Trivy: `fs` + `config`/IaC + `image`) and the
    dynamic-security suite (Wapiti DAST against the running API, JWT
    authenticated) both report findings, **separated on the dashboard by
    `tool` label** (Trivy = static, Wapiti = dynamic), each with a
    severity breakdown.
  - The load suite (k6) reports RPS, p50/p95/p99 latency, error rate, and
    vuser count against the §7.5 tuning budgets (`first_paint_backstop=5m`,
    `namespace_list_timeout=5s`).
  - Live-app suites (`e2e`, `dast`, `load`) **degrade gracefully**: if the dev
    stack / backend is not up, the suite is reported `skipped` (not failed) and
    the run continues, so `task test-all` is green on a host without Docker.
  - `task test-clean` removes `tmp/testing/` artifacts and deletes the
    Pushgateway job so a fresh run starts clean.
- **Out of scope:**
  - **GitHub CI / CI-CD workflows** — the repo has no GitHub CI. The
    Taskfile is the single entry point; nothing is triggered by a push to
    GitHub. (This re-scopes TASK-011's CI/CD half — see Impact on Global Docs.)
  - A new Prometheus/Grafana deployment — this change **reuses** the existing
    `dev/` Prometheus + Grafana; it only adds a Pushgateway service and a
    scrape job.
  - The app's own runtime metrics (it stays query-only per ADR-0003) — this
    pipeline pushes *test-result* metrics, not app telemetry.
  - Long-term retention / historical querying beyond the Grafana
    `run_id`-trend panels (the Pushgateway holds the last push per group;
    trends are over the `run_id` label, not a TSDB archive).
  - Replacing any existing test — the 68 backend tests and the Playwright
    scaffold are *wired in*, not rewritten (except the marker split and the
    `playwright.config.ts` fix, both additive/mechanical).

## Context

- **Fits existing patterns: yes.** The dev stack (`dev/docker-compose.yml`)
  already runs `prometheus` + `grafana` with an auto-provisioned Prometheus
  datasource and a **file-based dashboard provider**
  (`dev/grafana/provisioning/dashboards/providers.yml`) that loads any JSON
  dropped into `dev/grafana/provisioning/dashboards/dashboards/`. This change
  adds a `pushgateway` service to that same compose file and a scrape job to
  `dev/prometheus/prometheus.yml` — it does not fork the observability stack.
- **In-force decisions constraining this change:**
  - ADR-0003 (observability query-only) — the app reads from Prometheus and
    does not scrape itself. We preserve that: Prometheus scrapes the
    *Pushgateway*, not the app, and the app's own metrics remain stubs
    (`app/api/metrics.py` 501s, `app/services/prometheus.py` raises).
  - ADR-0008 (leader election: PG advisory lock + `leader_lease`) — the load
    suite's primary target is the no-duplicate-RQ-jobs property across
    leader-role replicas; the existing `task multi-up` / `task failover`
    (built this session) is the manual check the load test automates.
  - ADR-0006 (single container: Gunicorn serves API + static SPA) — e2e and
    Wapiti target the Flask-served app on `:8080`.
  - The frontend is **React 19** (not Vue) — `vite.config.ts` uses
    `@vitejs/plugin-react`, entry is `react-dom/client`. Component tests use
    `@testing-library/react` (already a dep); **`@vue/test-utils` does not
    apply.**
- **Conventions** (per the base-structure briefing): Python 3.12 + `uv` +
  `ruff` + `mypy --strict`; TypeScript strict + `pnpm`; Conventional Commits.
  Test deps are **dev-only** and must not leak into the runtime image.
- **Known environment constraint:** this host has **no Docker** and no
  container runtime. Live-app suites and the Testcontainers-backed backend
  integration tier **error at fixture setup here** (a documented environment
  block, not a code defect). The no-app suites (unit, frontend-unit, dup,
  security-static) and the push pipeline run fully on this host.

## Approaches Considered

- **Chosen: Pushgateway + per-suite sidecar push scripts.** Each suite writes
  a JSON/JSONL artifact; a single `dev/testing/push_to_prometheus.py` helper
  (the metric-schema single source of truth) parses it and pushes to the
  Pushgateway with `suite`/`tool`/`outcome`/`severity`/`type`/`target`/`run_id`
  labels. Decoupled from any test framework; short-lived runs (pytest, vitest,
  jscpd, trivy) don't need to expose a scrape endpoint.
- **Rejected: Prometheus scrapes the test containers.** k6 has a native
  Prometheus exporter, but pytest/vitest/jscpd/trivy are short-lived and would
  need a plugin + Prometheus reachable from the runner; inconsistent across
  the six static suites. One push helper beats six scrape integrations.
- **Rejected: Grafana Agent / Alloy pipeline.** Most "production-shaped" but
  the heaviest for a dev stack; overkill for an on-demand local review tool.
- **Chosen: Playwright fully replaces Selenium.** Playwright is already the
  e2e scaffold, is in `package.json`, is faster, and has tracing/retries. No
  separate Selenium dependency is introduced. (User-confirmed: "if Playwright
  can replace Selenium it is OK.")
- **Rejected: separate Selenium suite.** A second browser framework doubles
  maintenance for the same surface; the skill notes Wapiti (and thus DAST of
  the SPA) is crawler-blind to JS-rendered routes anyway, so the browser
  surface is Playwright's job, not Selenium's.

## Requirements

1. **R1 — Push pipeline spine:** a `pushgateway` service in
   `dev/docker-compose.yml` (image `prom/pushgateway`, port `9091`,
   `restart: unless-stopped`); a `job_name: pushgateway` scrape target
   (`pushgateway:9091`) in `dev/prometheus/prometheus.yml`; and
   `dev/testing/push_to_prometheus.py` — the **metric-schema single source of
   truth** that reads a suite's JSON artifact and pushes it to
   `PROMETHEUS_PUSHGATEWAY` (env, default `http://localhost:9091/metrics/job/kubedash-tests`)
   with a per-invocation `run_id` (timestamp) label.
   - **Current:** no Pushgateway, no push helper; Prometheus only self-scrapes.
   - **Target:** `task dev-up` brings up Pushgateway on `:9091`;
     `push_to_prometheus.py` accepts an artifact path + a `--suite` label and
     exits 0 on success, non-zero on push failure (so a broken pipeline fails
     loudly).
   - **Acceptance:** with the dev stack up, `python dev/testing/push_to_prometheus.py
     <fixture.json> --suite=unit` exits 0; `promtool check` (or a Prometheus
     query for the metric) shows the series; a push to an unreachable gateway
     exits non-zero.
   - **Acceptance scenario:** `happy path push-helper-pushes-artifact` → `acceptance.feature`

2. **R2 — Metric schema (single source of truth):** the push helper defines,
   via `prometheus_client`, exactly these series:
   - `kubedash_tests_duration_seconds{suite}` — Histogram
   - `kubedash_tests_total{suite, outcome}` — Counter (`outcome` ∈
     passed | failed | skipped | error)
   - `kubedash_test_coverage_percent{suite}` — Gauge
   - `kubedash_duplication_lines_percent` — Gauge;
     `kubedash_duplication_blocks_total` — Gauge
   - `kubedash_security_vulns_total{tool, severity, type}` — Counter
     (`tool` ∈ trivy | wapiti; `severity` ∈ critical | high | medium | low;
     `type` for trivy ∈ sca | iac | secret | image, for wapiti = the module,
     e.g. sql | xss | csrf)
   - `kubedash_load_rps{target}` / `kubedash_load_latency_p50_seconds{target}`
     / `kubedash_load_latency_p95_seconds{target}` /
     `kubedash_load_latency_p99_seconds{target}` /
     `kubedash_load_errors_total{target}` / `kubedash_load_vusers{target}`
     — Gauges
   - **Current:** none of these series exist.
   - **Target:** the schema lives in one module; adding a suite label value
     (e.g. `suite=frontend-unit`) requires no schema change.
   - **Acceptance:** a unit test on the helper asserts each metric name +
     label set matches the spec above (a schema-drift guard); pushing a
     well-formed artifact for each suite produces the expected series.
   - **Acceptance scenario:** `happy path metric-schema-drift-guard` → `acceptance.feature`

3. **R3 — Backend unit + functional suites:** split the existing 68-test
   backend suite into a `unit` tier (no container needed) and a `functional`
   tier (API / Testcontainers), via `unit` / `functional` pytest markers
   (currently only `integration` exists). Each runs `pytest --json-report
   --cov=app` and emits the shared artifact shape (per-test outcome +
   coverage %). Dev deps added: `pytest-json-report`, `pytest-cov`.
   - **Current:** 68 tests, only an `integration` marker; no json-report, no
     coverage reporting into the pipeline.
   - **Target:** `task test-unit` and `task test-functional` each run their
     tier, write `tmp/testing/<suite>.json`, and push. Coverage % for the
     unit tier lands on the dashboard.
   - **Acceptance:** `task test-unit` on this host (no Docker) runs the
     non-integration unit tier green and pushes `kubedash_tests_total{suite=unit}`
     + `kubedash_test_coverage_percent{suite=unit}`; `task test-functional`
     reports `skipped` here (Docker-blocked) but runs where Docker is present.
   - **Acceptance scenario:** `happy path backend-suites-split-and-push` → `acceptance.feature`

4. **R4 — Frontend component suite (Vitest + Testing Library):** author the
   missing frontend component/unit tests (none exist yet — only the Playwright
   scaffold). Targets: `lib/api.ts` (JWT attach, **single-in-flight 401 refresh
   + double-rotation**, rotated `kd_refresh` storage, error-envelope mapping),
   `store/cluster.ts`, `hooks/useCluster.ts`, and the three views' render
   paths. Uses the planned MSW setup (`tests/msw.ts`) so **no live backend is
   needed**. Uses `@testing-library/react` + `user-event` (already deps) +
   `@vitest/coverage-v8` for coverage.
   - **Current:** `frontend/` has Vitest + Testing Library installed but **zero**
     `.test.`/`.spec.` files in `src/`.
   - **Target:** `task test-frontend-unit` runs `vitest run --reporter=json`
     with coverage, writes `tmp/testing/frontend-unit.json`, and pushes. Runs
     on this host (no Docker) via MSW.
   - **Acceptance:** the double-rotation refresh race in `lib/api.ts` has a
     deterministic component test (two concurrent 401s → one refresh, the
     rotated token is stored, no duplicate refresh); `task test-frontend-unit`
     is green here and pushes `suite=frontend-unit` coverage.
   - **Acceptance scenario:** `happy path frontend-refresh-race-tested` → `acceptance.feature`

5. **R5 — E2E suite (Playwright, replaces Selenium):** fix the existing
   `playwright.config.ts` (its `webServer` runs `vite preview --port 4173`
   while `baseURL` points at `:8080` — self-contradictory) so the SPA is
   served by the real Flask app on `:8080`; run `playwright test
   --reporter=json` and push. **Playwright is the sole browser framework — no
   Selenium dependency is added.** Needs the dev stack + a browser download.
   - **Current:** `frontend/e2e/smoke.spec.ts` (2 specs) + a broken
     `playwright.config.ts`; ENV-blocked on this host.
   - **Target:** `task test-e2e` pre-flights the stack; if up, runs the spec
     and pushes `suite=e2e`; if the stack is down, reports `skipped`. The
     `webServer`/`baseURL` mismatch is resolved (point at `:8080`, drop the
     `vite preview` webServer).
   - **Acceptance:** against a live backend, the login→OIDC-seam and
     cluster-list specs pass and `suite=e2e` is pushed; with no backend,
     `task test-e2e` exits with `skipped` (not failed).
   - **Acceptance scenario:** `happy path e2e-runs-or-skips` → `acceptance.feature`

6. **R6 — Duplication suite (jscpd):** add `jscpd` (dev dep) and run it
   per-language (Python `backend/`, TypeScript `frontend/`) with a tuned
   threshold, `--reporters json`. The Go `cli/` is small and is included if a
   threshold yields signal. Writes `tmp/testing/dup.json` (duplicated-line % +
   block count) and pushes.
   - **Current:** no jscpd config, no duplication signal anywhere.
   - **Target:** `task test-dup` runs jscpd over backend + frontend, pushes
     `kubedash_duplication_lines_percent` + `kubedash_duplication_blocks_total`.
   - **Acceptance:** a deliberately duplicated block introduced into a temp
     fixture is detected and raises the block count; `task test-dup` pushes the
     gauges and exits 0 (duplication is reported, not a hard gate, unless a
     configured threshold is exceeded).
   - **Acceptance scenario:** `happy path duplication-detected-and-pushed` → `acceptance.feature`

7. **R7 — Static-security suite (Trivy):** run `trivy fs . --format json`
   (dependency CVEs + secrets), `trivy config dev/docker-compose.yml
   charts/ Dockerfile* --format json` (IaC/Dockerfile misconfigs — relevant
   once TASK-011's chart lands), and `trivy image <img> --format json` where an
   image exists. Writes `tmp/testing/security-trivy.json` and pushes
   `kubedash_security_vulns_total{tool=trivy, severity, type}`. Trivy's
   mnemonic store pass (`scan_start` / `scan_store_findings` / `dep_ingest`
   for the SBOM) is the skill's long-term memory, separate from the Prometheus
   push. No live app needed.
   - **Current:** no security scanning in the repo.
   - **Target:** `task test-security` runs Trivy (static), pushes, and works
     standalone on this host.
   - **Acceptance:** a known-vulnerable dependency fixture yields a `critical`/
     `high` finding pushed with `tool=trivy`; a clean tree pushes zero findings
     (series at 0, not absent).
   - **Acceptance scenario:** `happy path trivy-static-findings-pushed` → `acceptance.feature`

8. **R8 — Dynamic-security suite (Wapiti DAST):** run
   `wapiti -u http://localhost:8080 -o json -m
   sql,xss,exec,file,xxe,crlf,csrf,http_headers,cookieflags,csp` against the
   running Flask **API** (the SPA's client-rendered routes are Playwright's
   surface, not Wapiti's — Wapiti is crawler-blind to JS routes). Auth via
   `--form-script` reusing **TASK-011's `e2e/oidc-mock.py`** flow to obtain a
   JWT session (built in this change's Phase 4, per user decision). Writes
   `tmp/testing/security-wapiti.json` and pushes
   `kubedash_security_vulns_total{tool=wapiti, severity, type}`. Wapiti hits
   are fuzzer leads — the dashboard shows them as leads (severity by module),
   not confirmed vulns. Needs the dev stack + backend + the oidc-mock.
   - **Current:** no DAST anywhere.
   - **Target:** `task test-dast` pre-flights the stack + oidc-mock; runs Wapiti
     on the API with a JWT session; pushes; reports `skipped` if the stack is
     down.
   - **Acceptance:** against a live API, Wapiti runs and pushes
     `tool=wapiti` findings (or a zero-finding series); the `--form-script`
     login bootstrap yields a valid JWT (verified by a `/api/v1/auth/me` 200
     before the scan); with no stack, `task test-dast` is `skipped`.
   - **Acceptance scenario:** `happy path wapiti-dast-authed-and-pushed` → `acceptance.feature`

9. **R9 — Load suite (k6):** add a `k6` run (dev-only binary) with
   `--summary-json` against the running stack. Targets: (a) **leader-election
   no-duplicate-RQ-jobs** across N leader-role replicas (the ADR-0008 property
   the `task multi-up`/`task failover` flow checks manually); (b)
   `GET /api/v1/clusters/<id>/resources/pods` holding the 5 s
   `namespace_list_timeout` budget under many clusters/namespaces; (c) JWT
   single-flight refresh under concurrent 401s. Writes
   `tmp/testing/load.json` and pushes the `kubedash_load_*` gauges.
   - **Current:** no load/perf testing of any kind.
   - **Target:** `task test-load` runs k6, pushes RPS/latency/errors/vusers per
     `target`; reports `skipped` if the stack is down.
   - **Acceptance:** the pods-budget target's p95 stays within the 5 s budget
     in the summary (asserted by the k6 script's `thresholds`); the
     no-duplicate-jobs target shows zero duplicate RQ enqueues across leader
     replicas; `task test-load` pushes the gauges.
   - **Acceptance scenario:** `happy path load-budget-holds` → `acceptance.feature`

10. **R10 — Dashboards (Grafana):** two auto-provisioned JSON dashboards in
    `dev/grafana/provisioning/dashboards/dashboards/` (loaded by the existing
    file provider — no manual import):
    - `kubedash-test-observability.json` — latest-run overview (pass/fail/skip
      by suite, duration, coverage %, dup %, **security split: Trivy static vs
      Wapiti dynamic** by severity) + trend panels over `run_id`.
    - `kubedash-load.json` — RPS, p50/p95/p99, error rate, vusers vs. the §7.5
      tuning budgets.
    - **Current:** the dashboard folder holds only `.gitkeep`.
    - **Target:** both JSONs load on `task dev-up`; the observability dashboard
      shows a green/red per-suite panel and the security split; the load
      dashboard plots latency against the budget lines.
    - **Acceptance:** after `task test-all`, both dashboards render populated
      panels (no "No data") for every suite that ran; the security panel
      separates `tool=trivy` from `tool=wapiti`.
    - **Acceptance scenario:** `happy path dashboards-render-all-suites` → `acceptance.feature`

11. **R11 — Taskfile trigger surface:** new root `Taskfile` tasks (all
    CWD-independent, consistent with the existing `dev-*`/`multi-*` style):
    `test-unit`, `test-functional`, `test-frontend-unit`, `test-e2e`,
    `test-dup`, `test-security`, `test-dast`, `test-load`, `test-all`,
    `test-clean`, `test-dashboards`. Each suite task: run the suite → write
    `tmp/testing/<suite>.json` → call `push_to_prometheus.py`. `test-all` runs
    in order `unit → functional → frontend-unit → dup → security → e2e → dast
    → load`; live-app suites pre-flight the stack and report `skipped` (not
    failed) when it is down. `test-clean` removes `tmp/testing/` artifacts and
    `DELETE`s the Pushgateway job.
    - **Current:** the `Taskfile` has `build`/`cross`, `dev-*`, `multi-*`,
      `backend-run*`, `db-shell`, `failover` — no `test-*`.
    - **Target:** `task test-all` is the single entry point; `task --list`
      shows all `test-*` tasks; each is independently runnable.
    - **Acceptance:** `task test-all` on this host (no Docker) runs the five
      no-app suites green, reports the three live-app suites `skipped`, and
      exits 0; a failing no-app suite makes `test-all` exit non-zero **after**
      pushing (gate + observability both fire).
    - **Acceptance scenario:** `happy path test-all-gates-and-pushes` → `acceptance.feature`

## Implementation Decisions

- **Modules to build/modify (all new except noted):**
  - `dev/docker-compose.yml` (add `pushgateway` service) — *modify*
  - `dev/prometheus/prometheus.yml` (add `pushgateway` scrape job) — *modify*
  - `dev/testing/push_to_prometheus.py` (new) — the schema + pusher
  - `dev/testing/` fixtures (new) — sample artifacts for the schema test
  - `dev/grafana/provisioning/dashboards/dashboards/kubedash-test-observability.json`
    (new) + `kubedash-load.json` (new)
  - `Taskfile.yaml` (add `test-*` tasks) — *modify*
  - `backend/pyproject.toml` (add `pytest-json-report`, `pytest-cov` dev deps)
    — *modify*; `backend/tests/` marker tags (`unit`/`functional`) — *modify*
  - `backend/tests/test_push_helper.py` (new) — schema-drift guard
  - `frontend/package.json` (add `@vitest/coverage-v8`; confirm `jscpd`) —
    *modify*; `frontend/tests/` (new) — MSW + component tests;
    `frontend/playwright.config.ts` (fix webServer/baseURL) — *modify*
  - `dev/e2e/oidc-mock.py` (new, or under `e2e/`) — the Wapiti
    `--form-script` login bootstrap (shares the TASK-011 mock-OIDC design)
  - `dev/testing/k6/` (new) — k6 test scripts + `--summary-json` handling
  - Dev-only tool installs: `trivy`, `jscpd`, `k6`, `wapiti3` (Python 3.12–3.14)
- **Interfaces:**
  - `push_to_prometheus.py <artifact.json> --suite <name>` (and `--tool`,
    `--target` where applicable) → push; exit 0 / non-zero.
  - Shared **artifact shape** (every suite emits this; the pusher parses it):
    `{ suite, run_id, duration_seconds, outcomes: {passed, failed, skipped,
    error}, coverage_percent?, duplication? {lines_percent, blocks},
    security? {tool, findings: [{severity, type}]}, load? {target, rps,
    p50, p95, p99, errors, vusers} }`.
  - Taskfile tasks shell out to the suite runner, then to the push helper.
- **Data flow:** suite runner → `tmp/testing/<suite>.json` →
  `push_to_prometheus.py` → Pushgateway (`:9091`) → Prometheus scrape (15 s) →
  Grafana query → dashboard panels. `run_id` (timestamp) makes each run's
  series distinct so trend panels accumulate across runs.
- **Error handling / gate policy:** a suite that *runs* and *fails* (red test,
  threshold exceeded) → pushed **and** the task exits non-zero. A suite that
  *cannot run* (Docker/stack down) → pushed as `skipped` and the task exits 0.
  A push that fails (gateway down) → task exits non-zero (the pipeline is part
  of the gate).
- **Dependencies (all dev-only):** Python: `prometheus_client` (push helper
  venv), `pytest-json-report`, `pytest-cov`, `wapiti3`. Node:
  `@vitest/coverage-v8`, `jscpd`. Binaries: `trivy`, `k6`. Images:
  `prom/pushgateway`.
- **Phasing:** Phase 1 = R1 + R2 + R11 (spine: Pushgateway, Prometheus job,
  push helper, schema, dashboard skeletons, Taskfile tasks). Phase 2 = R3
  (backend suites). Phase 3 = R4 + R5 + R6 + R7 (frontend-unit, e2e, dup,
  Trivy). Phase 4 = R8 + R9 (Wapiti DAST with oidc-mock auth, k6 load) + R10
  (final dashboards).

## Testing Decisions

- **What makes a good test here:** the pipeline is verified by its *output* —
  the pushed series and the rendered panels. The schema-drift guard
  (`backend/tests/test_push_helper.py`) asserts the exact metric names + label
  sets; the per-suite artifact shape is asserted by feeding each a fixture and
  checking the resulting series.
- **Modules to test:** `push_to_prometheus.py` (schema + push + exit codes);
  each suite's adapter (artifact emission) via a fixture; the Taskfile tasks
  via `task <t>` run + `task dev-ps`/Prometheus query.
- **Prior art:** the base-structure test suite (68 tests) is the model for the
  backend unit/functional split; the existing `task multi-up`/`failover` is
  the model the k6 leader-election target automates.
- **Edge cases:** Pushgateway unreachable → non-zero exit; empty findings
  (clean scan) → series at 0, not absent; live-app suite with stack down →
  `skipped`, not failed; `run_id` collision → none (timestamp at second
  resolution + suite label); a suite that produces no artifact (crash) →
  treated as `error`, pushed, task non-zero.

## Impact on Global Docs

- **TASK-011 re-scope (Backlog):** the ticket is
  "TICKET-10: Helm chart + CI/CD workflows + e2e mock OIDC." With no GitHub CI
  in this repo, the **CI/CD half is dropped**; it becomes
  "TICKET-10: Helm chart + e2e mock OIDC (no CI)." AC #1 drops the actionlint +
  "ci.yaml green on branch" clause (keep the `test_chart.py` + `helm
  lint/template` assertions). Plan step 2 drops `.github/workflows/ci.yaml +
  e2e.yaml`. A comment records the re-scope + that e2e now runs locally via
  `task test-e2e`. The **`e2e/oidc-mock.py`** deliverable is shared by this
  change's R8 (Wapiti auth bootstrap) — so this pipeline *consumes* a
  TASK-011 artifact.
- `.skillgrid/ARCHITECTURE.md`: note the test-observability pipeline as a
  dev-time concern (Pushgateway + 8 suites + Grafana dashboards); the app
  remains query-only (ADR-0003) — no app-runtime metrics added.
- `.skillgrid/ASSUMPTIONS.md`: record the "no GitHub CI in this repo" decision
  (moves the CI question from open to locked) and that Playwright fully
  replaces Selenium for the browser surface.

## Clarity Report

The design was developed in a single Plan-mode session with the user on
2026-10-17 (four answer-select rounds locked the architecture, browser
framework, scope, TASK-011 re-scope, and the Trivy/Wapiti split).

| Dimension           | Score | Min  | Status | Notes                              |
|---------------------|-------|------|--------|------------------------------------|
| Goal Clarity        | 0.95  | 0.75 | pass   | "test-observability pipeline" = push results to Prometheus + Grafana, user-confirmed |
| Boundary Clarity    | 0.90  | 0.70 | pass   | 8 suites explicit; no-CI + query-only app boundaries in Out-of-scope |
| Constraint Clarity  | 0.90  | 0.65 | pass   | ADR-0003/0008/0006 in force; no-Docker host constraint documented |
| Acceptance Criteria | 0.88  | 0.70 | pass   | every requirement carries a concrete pass/fail check + scenario |
| **Clarity**         | 0.06  | ≤0.20| pass   | residual: exact k6 vuser/RRPS profile values (see Open Questions) |

**Interview log:**

| Round | Question summary         | Decision locked                    |
|-------|-------------------------|------------------------------------|
| 1     | How do results reach Prometheus? | Pushgateway + per-suite sidecar push scripts (not scrape, not Agent/Alloy) |
| 2     | Selenium vs Playwright for the browser layer? | Playwright fully replaces Selenium; no Selenium dependency |
| 3     | Scope of the build (full 8-tool vs phased)? | Full solution, phased (1 spine → 2 Python → 3 browser+static → 4 live-app) |
| 4     | CI integration + TASK-011 + Trivy/Wapiti split + Wapiti auth | No GitHub CI; re-scope TASK-011; Trivy=static / Wapiti=dynamic (API, JWT via oidc-mock `--form-script` built in Phase 4); Vitest+RTL (React, not Vue) for frontend components |

## Open Questions & Assumptions

- **Assumption:** the repo has **no GitHub CI** (user decision, 2026-10-17).
  The Taskfile is the only entry point. This re-scopes TASK-011's CI/CD half.
- **Assumption:** the frontend is **React 19**, so component tests use
  `@testing-library/react` (already a dep); `@vue/test-utils` is not used. If
  a Vue portion is later introduced, a parallel `@vue/test-utils` suite is
  additive.
- **Assumption:** Wapiti's authenticated scan reuses **TASK-011's
  `e2e/oidc-mock.py`**; the `--form-script` bootstrap is built in this
  change's Phase 4 (user chose to build it now rather than defer to
  TASK-011). If TASK-011's mock-OIDC shape differs, the bootstrap adapts to it.
- **Assumption:** the no-app suites (unit, frontend-unit, dup, security-static)
  run fully on this host (no Docker); the live-app suites (e2e, dast, load) and
  the Testcontainers integration tier are environment-blocked here and run
  where Docker is present.
- **Question:** the k6 load profile's concrete **vuser count / RPS ramp /
  duration** for the pods-budget and no-duplicate-jobs targets — the blueprint
  will propose starting values (e.g. 50 vusers, 60 s ramp) to be tuned against
  the 5 s budget; confirm the target concurrency that represents real usage.

## Decisions (ADR)

No new ADRs clear the bar — this change *implements* a dev-time observability
pipeline on top of in-force decisions, it does not change the app's
architecture. In-force ADRs constraining it: **ADR-0003** (observability
query-only — we scrape the Pushgateway, not the app), **ADR-0008** (leader
election — the load suite's no-duplicate-jobs target), **ADR-0006** (single
container — e2e/Wapiti target the Flask-served app on `:8080`).

## Terms

- **Test-observability pipeline** — the set of eight local test suites whose
  structured results are pushed to Prometheus via a Pushgateway and rendered in
  Grafana; driven by `task test-all`. Not in the terms files (introduced by
  this spec).
- **Artifact shape** — the single JSON/JSONL schema every suite emits and the
  push helper parses; defined in R2's Implementation Decisions.
- **run_id** — a per-invocation timestamp label that makes each run's series
  distinct so Grafana trend panels accumulate across runs.
