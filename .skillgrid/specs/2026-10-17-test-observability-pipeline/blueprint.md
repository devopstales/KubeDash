# KubeDash Test-Observability Pipeline — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-execution (recommended) or simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T2

**Build shape:** Spine-first — Task 1 builds the push pipeline (Pushgateway +
Prometheus job + push helper + schema + Taskfile) so every later task *immediately*
has a dashboard to push into; Tasks 2–8 then add one suite at a time, each
verified by its own pushed series. Chosen because the push pipeline is the
unknown (Pushgateway wiring + schema + the no-app/live-app degrade rule) and
every suite depends on it — building it first de-risks all seven suites at once.

**Goal:** Stand up the eight local test suites (backend unit, backend
functional, frontend-unit, e2e, duplication, static security, dynamic security,
load) whose structured results are pushed to Prometheus via a Pushgateway and
rendered in two Grafana dashboards on the existing dev stack — driven entirely
from the root `Taskfile` (`task test-all`), **no GitHub CI**.

**Architecture:** A single `dev/testing/push_to_prometheus.py` helper is the
metric-schema single source of truth. Each suite runner writes a JSON artifact
in one shared shape to `tmp/testing/<suite>.json`; the helper parses it and
pushes to a `pushgateway` compose service (`:9091`) with `suite`/`tool`/`outcome`/
`severity`/`type`/`target`/`run_id` labels. Prometheus (already in the dev
stack) scrapes the Pushgateway on its 15 s interval; Grafana (already
auto-provisioned) renders two file-provisioned JSON dashboards. The app itself
stays query-only (ADR-0003) — Prometheus scrapes the gateway, never the app.

**Tech Stack:** Python 3.12, `uv`, `prometheus_client`, `pytest` +
`pytest-json-report` + `pytest-cov`, `wapiti3`; Node 20, `pnpm`, Vitest +
`@vitest/coverage-v8` + `@testing-library/react` + MSW, `jscpd`, Playwright;
binaries `trivy`, `k6`; image `prom/pushgateway`; Prometheus + Grafana (existing
dev stack).

**Spec:** `.skillgrid/specs/2026-10-17-test-observability-pipeline/briefing.md`
(requirements R1–R11)

## Terms

- **Test-observability pipeline** — the eight local suites + Pushgateway push +
  Grafana render, driven by `task test-all`; `briefing.md` § Terms.
- **Artifact shape** — the single JSON schema every suite emits and the push
  helper parses; defined in Task 1 Interfaces.
- **run_id** — a per-invocation timestamp label making each run's series
  distinct so Grafana trend panels accumulate across runs.
- **No-app / live-app suite** — a suite that runs with no container runtime /
  stack (unit, frontend-unit, dup, security-static) vs. one that needs the dev
  stack + backend up (e2e, dast, load). Live-app suites report `skipped` (not
  failed) when the stack is down.

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- T1: `task dev-up` brings up a `pushgateway` service listening on `:9091`;
  `docker compose ps` shows it healthy *(backstop — needs Docker)*
- T2: `dev/prometheus/prometheus.yml` has a `job_name: pushgateway` target
  `pushgateway:9091`; after a push, a Prometheus query for
  `kubedash_tests_total` returns a series *(backstop — needs Docker)*
- T3: `python dev/testing/push_to_prometheus.py <artifact> --suite unit` exits
  0 against a reachable gateway; the same against an unreachable gateway exits
  non-zero (no silent swallow)
- T4: `backend/tests/test_push_helper.py` asserts the exact metric names + label
  sets from R2 (a schema-drift guard); it fails if any name or label is renamed
- T5: a well-formed artifact for each suite produces the expected series with
  the right `suite`/`tool`/`outcome`/`severity`/`type`/`target` labels
- T6: `task test-unit` on a no-Docker host runs the non-integration unit tier
  green and pushes `kubedash_tests_total{suite=unit}` +
  `kubedash_test_coverage_percent{suite=unit}`; `task test-functional` reports
  `skipped` on that host but runs where Docker is present
- T7: the `lib/api.ts` double-rotation refresh race has a deterministic
  component test (two concurrent 401s → exactly one refresh, rotated token
  stored, no duplicate refresh); `task test-frontend-unit` is green on a
  no-Docker host (MSW) and pushes `suite=frontend-unit`
- T8: `frontend/playwright.config.ts` no longer self-contradicts (no `vite
  preview` webServer while `baseURL` is `:8080`); against a live backend the
  login→OIDC-seam + cluster-list specs pass and push `suite=e2e`; with no
  backend `task test-e2e` exits `skipped` (not failed) *(backstop — needs stack
  for the pass path)*
- T9: `task test-dup` (jscpd, Python + TypeScript) pushes
  `kubedash_duplication_lines_percent` + `kubedash_duplication_blocks_total`; a
  deliberately duplicated fixture block raises the block count
- T10: `task test-security` (Trivy `fs` + `config` + `image`) pushes
  `kubedash_security_vulns_total{tool=trivy,severity,type}`; a known-vulnerable
  fixture yields a `critical`/`high` finding; a clean tree pushes a zero series
  (present, not absent)
- T11: `task test-dast` (Wapiti) runs against the running API with a JWT from
  the `e2e/oidc-mock.py` `--form-script` bootstrap (verified by a
  `/api/v1/auth/me` 200 before the scan) and pushes
  `kubedash_security_vulns_total{tool=wapiti,severity,type}`; with no stack it
  is `skipped` *(backstop — needs stack)*
- T12: `task test-load` (k6) pushes the `kubedash_load_*` gauges per `target`;
  the pods-budget target's p95 holds within the 5 s `namespace_list_timeout`
  (k6 `thresholds` assert it); the no-duplicate-jobs target shows zero duplicate
  RQ enqueues across leader replicas *(backstop — needs stack)*
- T13: two Grafana JSON dashboards load on `task dev-up` via the existing file
  provider; after `task test-all`, both render populated panels (no "No data")
  for every suite that ran; the observability dashboard's security panel
  separates `tool=trivy` from `tool=wapiti` *(backstop — needs Docker)*
- T14: `task test-all` runs the eight suites in order
  `unit → functional → frontend-unit → dup → security → e2e → dast → load`; on
  a no-Docker host it runs the five no-app suites green, reports the three
  live-app suites `skipped`, and exits 0; a failing no-app suite makes
  `test-all` exit non-zero **after** pushing (gate + observability both fire)
- T15: `task test-clean` removes `tmp/testing/` artifacts and `DELETE`s the
  Pushgateway job; a subsequent `task test-all` starts from a clean slate
- T16: `task --list` shows all `test-*` tasks; each is independently runnable
  and CWD-independent (consistent with the existing `dev-*`/`multi-*` style)

**Artifacts** (files that must exist with real implementation, not stubs):
- `dev/docker-compose.yml` — *modify*: add the `pushgateway` service
- `dev/prometheus/prometheus.yml` — *modify*: add the `pushgateway` scrape job
- `dev/testing/push_to_prometheus.py` — the schema + pusher (new)
- `dev/testing/fixtures/` — sample artifacts (one per suite) for the schema test (new)
- `dev/grafana/provisioning/dashboards/dashboards/kubedash-test-observability.json` (new)
- `dev/grafana/provisioning/dashboards/dashboards/kubedash-load.json` (new)
- `Taskfile.yaml` — *modify*: add all `test-*` tasks
- `backend/pyproject.toml` — *modify*: add `pytest-json-report`, `pytest-cov` (dev)
- `backend/tests/` — *modify*: add `unit`/`functional` markers to the 68 tests
- `backend/tests/test_push_helper.py` — schema-drift guard (new)
- `frontend/package.json` — *modify*: add `@vitest/coverage-v8`, `jscpd`
- `frontend/tests/` — MSW setup + component tests (new)
- `frontend/playwright.config.ts` — *modify*: fix webServer/baseURL
- `dev/e2e/oidc-mock.py` — the Wapiti `--form-script` login bootstrap (new; shares the TASK-011 mock-OIDC design)
- `dev/testing/k6/` — k6 test scripts + `--summary-json` handling (new)
- `dev/.gitignore` or root `.gitignore` — ensure `tmp/testing/` is ignored (the root `.gitignore` already has `tmp/`)

**Key links** (critical connections that must work together):
- K1: every suite runner emits the **artifact shape** defined in Task 1; the
  push helper is the only place that knows the metric schema — a suite never
  imports `prometheus_client` directly.
- K2: the `run_id` (timestamp) is generated by the push helper at push time, not
  by the suite — so a re-run of the same artifact produces a new, distinct run.
- K3: the Taskfile `test-*` tasks all call the same helper with the same
  `tmp/testing/<suite>.json` path convention; `test-all` is the only place that
  knows the suite order and the no-app/live-app split.
- K4: the Wapiti `--form-script` bootstrap reuses `dev/e2e/oidc-mock.py`; the
  same mock also serves the Playwright e2e login — one mock, two consumers.
- K5: the k6 no-duplicate-jobs target exercises the same leader-election path
  the existing `task multi-up`/`task failover` check manually — the k6 script
  asserts what `failover` observes.
- K6: the Grafana dashboards query only the metric names from R2; a rename in
  the helper is caught by the schema-drift test (T4) before it breaks the panels.

**One-way-door decisions** (hard to reverse — explicit user approval before implementing):
- OD-1: **The Pushgateway + shared artifact shape is the pipeline contract.**
  Every suite depends on the helper's schema and the `tmp/testing/<suite>.json`
  convention; changing either is a cross-suite migration. *Task 1.*
- OD-2: **Playwright is the sole browser framework** (Selenium fully replaced,
  no Selenium dependency). *Task 5.*
- OD-3: **No GitHub CI in this repo** — the Taskfile is the only entry point;
  the `run_id`-trend model (not a TSDB archive) is the retention story. *Task 1
  (run_id), Task 8 (dashboards).*

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Shell commands | Applicable: `Taskfile.yaml` tasks, `dev/testing/` shell invocations (jscpd/trivy/k6/wapiti), the push helper's `curl`-free `prometheus_client` push | All tool invocations use fixed arg lists; no request-data string interpolation; the push helper uses `prometheus_client.push_to` (not a shell `curl`) | T3: unreachable gateway → non-zero exit; T15: `test-clean` deletes only `tmp/testing/` + the gateway job |
| Subprocesses | Applicable: k6, trivy, jscpd, wapiti, playwright are external binaries; the push helper is a Python subprocess invoked by the Taskfile | Each is a fixed binary + fixed args; exit codes are interpreted (0 = ran, non-zero = ran-and-failed, special = skipped); a missing binary → `skipped`, not a crash | T6/T9/T10/T11/T12: each suite's missing-binary path reports `skipped` |
| Version-control automation | N/A: no git hooks or branch logic added (no CI by OD-3) | — | — |
| Executable-file classification | Applicable: `dev/testing/push_to_prometheus.py` is executed directly; k6 scripts are executed by k6 | Helper has no side effects beyond the push; k6 scripts are read-only (they assert, don't mutate the app) | T3: helper is idempotent (two pushes of the same artifact = two distinct `run_id` series) |
| Process integration | Applicable: the Pushgateway is a long-lived compose service the Prometheus scrape depends on; k6/dast target the live backend | Pushgateway has a healthcheck + `restart: unless-stopped`; live-app suites pre-flight the stack and degrade to `skipped` | T1: gateway healthy in `dev-ps`; T14: live-app suites `skipped` when stack down |
| Network trust | Applicable: the push helper talks to `PROMETHEUS_PUSHGATEWAY`; k6/wapiti hit `localhost:8080` | Both are loopback in dev; the gateway URL is env-overridable (default `http://localhost:9091`); no secret in the push (test results are non-sensitive) | T3: gateway-down → non-zero, no hang (bounded timeout on the push) |
| Mnemonic tool contracts | Applicable: Trivy's skill store pass (`scan_start`/`scan_store_findings`/`dep_ingest`) | Fail-open: a mnemonic store error logs and continues — it never blocks the push (the Prometheus push is the gate) | T10: trivy pushes even when the mnemonic store is unreachable |
| `_shared/{planning,craft,verification,knowledge}/` files | N/A: no skillgrid `_shared` files touched | — | — |

## Global Constraints

- Python 3.12; deps via `uv`; `ruff` + `mypy --strict` on any new Python (the
  push helper + `test_push_helper.py`); type hints on every public signature.
- TypeScript strict; `pnpm`; frontend test deps are **dev-only** (never in the
  runtime image).
- All new Python/node deps are **dev-only**; `prometheus_client` lives in the
  push-helper venv (or `backend` dev group), not the runtime `gunicorn` image.
- `tmp/testing/` is gitignored (the root `.gitignore` already ignores `tmp/`).
- The app stays **query-only** (ADR-0003): this change adds no app-runtime
  `/metrics` endpoint; Prometheus scrapes the Pushgateway, not the app.
- Conventional Commits; spec-zone commits (this folder) separate from code
  commits (zone guard).
- No GitHub CI (OD-3): the Taskfile is the entry point; nothing is triggered by
  a push to GitHub.
- Gate policy: a suite that *runs and fails* → pushed **and** task exits
  non-zero; a suite that *cannot run* (stack/binary missing) → pushed as
  `skipped` and task exits 0; a *push failure* (gateway down) → task exits
  non-zero.

## File Structure

**Pipeline spine (new):**
- `dev/testing/push_to_prometheus.py` — the schema + pusher (CLI: `<artifact>
  --suite <name>` [+ `--tool`, `--target`]); `prometheus_client` metrics defined
  once here; `run_id` generated here
- `dev/testing/fixtures/{unit,functional,frontend-unit,e2e,dup,security-trivy,
  security-wapiti,load}.json` — one sample artifact per suite (schema-test
  inputs)
- `dev/e2e/oidc-mock.py` — mock OIDC provider + the Wapiti `--form-script`
  login bootstrap (shares the TASK-011 design)

**Compose + Prometheus + Grafana (modify + new):**
- `dev/docker-compose.yml` — *modify*: `pushgateway` service (`prom/pushgateway`,
  `:9091`, healthcheck, `restart: unless-stopped`)
- `dev/prometheus/prometheus.yml` — *modify*: `job_name: pushgateway` →
  `pushgateway:9091`
- `dev/grafana/provisioning/dashboards/dashboards/kubedash-test-observability.json`
  — latest-run overview (pass/fail/skip by suite, duration, coverage %, dup %,
  security split trivy-vs-wapiti by severity) + `run_id` trend panels
- `dev/grafana/provisioning/dashboards/dashboards/kubedash-load.json` — RPS,
  p50/p95/p99, error rate, vusers vs. the §7.5 budget lines

**Taskfile (modify):**
- `Taskfile.yaml` — add `test-unit`, `test-functional`, `test-frontend-unit`,
  `test-e2e`, `test-dup`, `test-security`, `test-dast`, `test-load`,
  `test-all`, `test-clean`, `test-dashboards` (all CWD-independent)

**Backend (modify + new):**
- `backend/pyproject.toml` — *modify*: `pytest-json-report`, `pytest-cov` (dev
  group); `prometheus_client` (for the helper, dev group)
- `backend/tests/` — *modify*: tag the 68 tests `unit` / `functional` (the
  existing `integration` marker stays); conftest gets a `json-report` hook if
  needed
- `backend/tests/test_push_helper.py` — schema-drift guard (new)

**Frontend (modify + new):**
- `frontend/package.json` — *modify*: `@vitest/coverage-v8`, `jscpd` (dev)
- `frontend/tests/msw.ts` + `frontend/tests/api.test.ts` +
  `frontend/tests/views/*.test.tsx` — MSW + component tests (new)
- `frontend/playwright.config.ts` — *modify*: drop the `vite preview` webServer,
  point at `:8080`
- `frontend/vite.config.ts` — *modify* (if needed): `test.coverage` provider =
  `v8`

**Load + security tooling (new):**
- `dev/testing/k6/load.js` (or a small set) — the three targets (no-dup-jobs,
  pods-budget, jwt-single-flight) with `thresholds` + `--summary-json`
- dev-only tool installs: `trivy`, `k6`, `jscpd` (node), `wapiti3` (Python
  3.12–3.14)

---

### Task 1: Push pipeline spine (Pushgateway + Prometheus job + push helper + schema + Taskfile)

**Files:**
- Modify: `dev/docker-compose.yml`
- Modify: `dev/prometheus/prometheus.yml`
- Create: `dev/testing/push_to_prometheus.py`
- Create: `dev/testing/fixtures/*.json` (8 sample artifacts)
- Create: `backend/tests/test_push_helper.py`
- Create: `dev/grafana/provisioning/dashboards/dashboards/kubedash-test-observability.json` (skeleton)
- Create: `dev/grafana/provisioning/dashboards/dashboards/kubedash-load.json` (skeleton)
- Modify: `Taskfile.yaml` (all `test-*` tasks, wired to the helper; suites not yet built report `skipped`)
- Modify: `backend/pyproject.toml` (`prometheus_client` dev dep)

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - the **artifact shape** (single JSON schema every suite emits):
    `{ "suite": str, "run_id": str, "duration_seconds": float,
      "outcomes": {"passed": int, "failed": int, "skipped": int, "error": int},
      "coverage_percent": float | null,
      "duplication": {"lines_percent": float, "blocks": int} | null,
      "security": {"tool": "trivy"|"wapiti", "findings": [{"severity": str,
      "type": str}]} | null,
      "load": {"target": str, "rps": float, "p50": float, "p95": float,
      "p99": float, "errors": int, "vusers": int} | null }`
  - `dev/testing/push_to_prometheus.py <artifact.json> --suite <name>`
    [+ `--tool <trivy|wapiti>` for the security split] → parses the artifact,
    generates `run_id` = `strftime("%Y%m%dT%H%M%S")`, pushes via
    `prometheus_client.push_to(job="kubedash-tests",
    grouping_key={"suite": suite, "tool": tool, "run_id": run_id})`, exits 0 on
    success / non-zero on push failure (bounded timeout)
  - the **metric schema** (defined once, in the helper):
    `kubedash_tests_duration_seconds{suite}` (Histogram),
    `kubedash_tests_total{suite,outcome}` (Counter),
    `kubedash_test_coverage_percent{suite}` (Gauge),
    `kubedash_duplication_lines_percent` (Gauge),
    `kubedash_duplication_blocks_total` (Gauge),
    `kubedash_security_vulns_total{tool,severity,type}` (Counter),
    `kubedash_load_rps{target}` / `kubedash_load_latency_p50_seconds{target}` /
    `kubedash_load_latency_p95_seconds{target}` /
    `kubedash_load_latency_p99_seconds{target}` /
    `kubedash_load_errors_total{target}` / `kubedash_load_vusers{target}`
    (Gauges)
  - `pushgateway` compose service + Prometheus scrape job
  - Taskfile `test-*` tasks (the suites not yet built in this task emit a
    minimal `{"suite": ..., "outcomes": {"skipped": 1}}` artifact so
    `task test-all` runs end-to-end from Task 1)
  - two Grafana dashboard skeletons (panels wired to the R2 metric names; data
    appears as suites land)
- Seam: the artifact shape + the helper CLI — every later suite depends on
  both; the helper is the only place that knows the metric schema (K1)
- Deletion test: delete the helper and every suite's push disappears; delete the
  artifact shape and every suite's adapter breaks
- Adapters: 2 — the Taskfile tasks (production path) and `test_push_helper.py`
  (test path, using the fixtures)

**SATISFIES:** `push-helper-pushes-artifact`, `metric-schema-drift-guard`, `test-all-gates-and-pushes`

- [ ] **Step 1: Write the failing tests** (schema-drift guard + push/exit-code)

```python
# backend/tests/test_push_helper.py
import json
import subprocess
import sys
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "dev" / "testing" / "push_to_prometheus.py"
FIXTURES = Path(__file__).resolve().parents[1] / "dev" / "testing" / "fixtures"

# The exact schema from R2 — a rename or label drop fails this test.
EXPECTED_METRICS = {
    "kubedash_tests_duration_seconds": {"suite"},
    "kubedash_tests_total": {"suite", "outcome"},
    "kubedash_test_coverage_percent": {"suite"},
    "kubedash_duplication_lines_percent": set(),
    "kubedash_duplication_blocks_total": set(),
    "kubedash_security_vulns_total": {"tool", "severity", "type"},
    "kubedash_load_rps": {"target"},
    "kubedash_load_latency_p50_seconds": {"target"},
    "kubedash_load_latency_p95_seconds": {"target"},
    "kubedash_load_latency_p99_seconds": {"target"},
    "kubedash_load_errors_total": {"target"},
    "kubedash_load_vusers": {"target"},
}

def test_metric_schema_matches_spec(monkeypatch, tmp_path):
    # Point the helper at a throwaway in-process registry (no real gateway):
    # monkeypatch PROMETHEUS_PUSHGATEWAY to an unreachable port and assert the
    # helper BUILDS every expected metric before the push fails.
    ...
    assert set(built_metric_names) == set(EXPECTED_METRICS)
    for name, labels in EXPECTED_METRICS.items():
        assert metric_labels(name) == labels

def test_push_success_exit_zero(...):
    # fixture artifact + a local pushgateway (testcontainers) → exit 0
    ...

def test_push_failure_exit_nonzero(...):
    # PROMETHEUS_PUSHGATEWAY=http://localhost:1 (closed) → exit != 0, bounded
    ...

def test_each_fixture_produces_expected_series():
    for suite in ["unit","functional","frontend-unit","e2e","dup",
                  "security-trivy","security-wapiti","load"]:
        artifact = json.loads((FIXTURES / f"{suite}.json").read_text())
        # assert the artifact parses and maps to the right series
        ...
```

- [ ] **Step 2: Verify they fail** — `cd backend && uv run pytest tests/test_push_helper.py -q` (helper + fixtures don't exist yet)
- [ ] **Step 3: Add the `pushgateway` service to `dev/docker-compose.yml`**

```yaml
  pushgateway:
    image: prom/pushgateway
    ports:
      - "${PUSHGATEWAY_PORT:-9091}:9091"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9091/-/healthy"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    restart: unless-stopped
```

- [ ] **Step 4: Add the scrape job to `dev/prometheus/prometheus.yml`**

```yaml
  - job_name: pushgateway
    static_configs:
      - targets: ["pushgateway:9091"]
```

- [ ] **Step 5: Implement `dev/testing/push_to_prometheus.py`** — parse the
  artifact, define the R2 metrics once, generate `run_id`, push via
  `prometheus_client.push_to` with a bounded timeout; exit 0 / non-zero. The
  helper must not import any suite-specific code (K1).
- [ ] **Step 6: Write the 8 fixture artifacts** in `dev/testing/fixtures/`
  matching the artifact shape (one per suite, with representative values).
- [ ] **Step 7: Add the Taskfile `test-*` tasks** — each: run the suite (a
  `: # not yet built — emits a skipped artifact` placeholder for the suites
  Tasks 2–8 will fill) → write `tmp/testing/<suite>.json` → call the helper.
  `test-all` runs the fixed order; `test-clean` + `test-dashboards` per R11.
- [ ] **Step 8: Add the two dashboard JSON skeletons** wired to the R2 metric
  names (panels render "No data" until suites push).
- [ ] **Step 9: Verify** — `task dev-up && task test-all` (Docker host): all
  eight suites emit + push (five no-app run, three live-app `skipped`); the
  Grafana observability dashboard shows the pushed series. On a no-Docker host:
  `task test-unit` (once Task 2 lands) + the spine's placeholder suites push
  and `task test-all` exits 0.
- [ ] **Step 10: Commit** — `feat(testing): push pipeline spine (Pushgateway + schema + Taskfile)`

---

### Task 2: Backend unit + functional suite split (markers + json-report + cov)

**Files:**
- Modify: `backend/pyproject.toml` (`pytest-json-report`, `pytest-cov` dev deps; `[tool.pytest.ini_options]` marker registration)
- Modify: `backend/tests/**` — tag the 68 tests `unit` / `functional` (existing `integration` marker stays)
- Modify: `Taskfile.yaml` — fill in the `test-unit` / `test-functional` suite commands (replacing Task 1's placeholders)

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1)
- Produces: `tmp/testing/unit.json` + `tmp/testing/functional.json` in the
  artifact shape (from `pytest --json-report --cov=app`); the `unit`/
  `functional` markers
- Seam: the marker split — `task test-unit` = `-m "unit"`,
  `task test-functional` = `-m "functional and not unit"`; the `json-report`
  plugin output is the adapter from pytest's per-test results to the artifact
  shape
- Deletion test: remove the markers and the two tasks can't select their tiers
- Adapters: 2 — the Taskfile task (production) and a small `pytest --json-report`
  → artifact-shape converter (the json-report JSON is reshaped to the shared
  shape by the task, not by the helper)

**SATISFIES:** `backend-suites-split-and-push`

- [ ] **Step 1: Register the markers** in `pyproject.toml`
  (`markers = [..., "unit: ...", "functional: ..."]`).
- [ ] **Step 2: Tag the existing 68 tests** — unit = no container needed;
  functional = API / Testcontainers. (Mechanical; the `integration` marker is
  orthogonal and stays.)
- [ ] **Step 3: Write a failing check** — `task test-unit` must select only
  `unit`-marked tests and push `suite=unit` coverage.
- [ ] **Step 4: Fill the Taskfile tasks** — `test-unit`:
  `pytest -m "unit" --json-report --cov=app --cov-report=json` → reshape to
  `tmp/testing/unit.json` → helper. `test-functional`: same with
  `-m "functional and not unit"`; pre-flight Docker, `skipped` if absent.
- [ ] **Step 5: Verify** — no-Docker host: `task test-unit` green + pushes
  `suite=unit` + coverage; `task test-functional` → `skipped`. Docker host:
  `task test-functional` runs the API tier green.
- [ ] **Step 6: Commit** — `feat(testing): backend unit/functional split + coverage push`

---

### Task 3: Frontend component suite (Vitest + Testing Library + MSW)

**Files:**
- Modify: `frontend/package.json` (`@vitest/coverage-v8` dev dep)
- Modify: `frontend/vite.config.ts` (`test.coverage.provider = "v8"`)
- Create: `frontend/tests/msw.ts` (MSW server + API handlers)
- Create: `frontend/tests/api.test.ts` (the `lib/api.ts` suite incl. the double-rotation race)
- Create: `frontend/tests/views/login.test.tsx`, `clusters.test.tsx`, `cluster.test.tsx`
- Modify: `Taskfile.yaml` — fill `test-frontend-unit`

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1); the existing `lib/api.ts`,
  `store/cluster.ts`, `hooks/useCluster.ts`, three views
- Produces: `tmp/testing/frontend-unit.json` (from `vitest run --reporter=json
  --coverage`); the MSW + component test files
- Seam: MSW is the adapter that lets the suite run with **no live backend**
  (K for no-app on a no-Docker host); `vitest --reporter=json` + coverage is
  reshaped to the artifact shape
- Deletion test: remove the MSW handlers and the `lib/api.ts` refresh tests
  can't run offline
- Adapters: 2 — the Taskfile task (production) and the vitest-JSON→artifact
  converter

**SATISFIES:** `frontend-refresh-race-tested`

- [ ] **Step 1: Write the failing test** — the double-rotation race in
  `lib/api.ts`: fire two concurrent 401s → assert exactly one
  `/api/v1/auth/refresh` call, the rotated `kd_refresh` is stored, the second
  request retries with the new token (no duplicate refresh).
- [ ] **Step 2: Verify it fails** (no MSW / test yet) — `cd frontend && pnpm vitest run tests/api.test.ts`
- [ ] **Step 3: Build `tests/msw.ts`** — handlers for `/api/v1/auth/*`,
  `/api/v1/clusters`, `/api/v1/clusters/:id/resources/pods`.
- [ ] **Step 4: Implement the `api.test.ts` suite** (JWT attach, single-in-flight
  refresh, double-rotation, rotated storage, error-envelope mapping) until green.
- [ ] **Step 5: Add the view render tests** (Login redirects to `/api/v1/auth/login`;
  Clusters lists from `/api/v1/clusters`; Cluster renders the pod table).
- [ ] **Step 6: Fill the Taskfile task** — `vitest run --reporter=json
  --coverage` → reshape → `tmp/testing/frontend-unit.json` → helper. No Docker
  needed (MSW).
- [ ] **Step 7: Verify** — no-Docker host: `task test-frontend-unit` green +
  pushes `suite=frontend-unit` + coverage; the race test passes.
- [ ] **Step 8: Commit** — `feat(testing): frontend Vitest+RTL component suite (MSW, no backend)`

---

### Task 4: E2E suite (Playwright — replaces Selenium) + config fix

**Files:**
- Modify: `frontend/playwright.config.ts` (drop the `vite preview` webServer;
  `baseURL` = `:8080`; the app is served by Flask)
- Modify: `frontend/e2e/smoke.spec.ts` (keep the 2 specs; adjust if the config
  change alters the login-seam assertion)
- Create (if needed): `frontend/e2e/helpers/` (token/seed helpers)
- Modify: `Taskfile.yaml` — fill `test-e2e` (pre-flight the stack; `skipped` if
  down)

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1); the live Flask app on `:8080`;
  `dev/e2e/oidc-mock.py` (Task 6 builds it — e2e can use it for the login
  round-trip, or the existing no-token seam assertion)
- Produces: `tmp/testing/e2e.json` (from `playwright test --reporter=json`)
- Seam: **Playwright is the sole browser framework** (OD-2) — no Selenium
  dependency; the config's `baseURL`→`:8080` is the contract that the Flask app
  serves both API and SPA (ADR-0006)
- Deletion test: remove the Playwright config fix and the specs hit the wrong
  origin (the old `vite preview` on 4173)
- Adapters: 2 — the Taskfile task (production) and the playwright-JSON→artifact
  converter

**SATISFIES:** `e2e-runs-or-skips`

- [ ] **Step 1: Write the failing check** — `task test-e2e` with no backend →
  `skipped` (not failed); the config no longer references `vite preview`.
- [ ] **Step 2: Fix `playwright.config.ts`** — remove `webServer` (the Flask app
  on `:8080` is the server), keep `baseURL` `:8080`, keep
  `trace: on-first-retry`.
- [ ] **Step 3: Adjust `smoke.spec.ts`** if the login-seam assertion changed
  with the config fix.
- [ ] **Step 4: Fill the Taskfile task** — pre-flight `:8080` (curl
  `/healthz`); if down → `skipped`; else `playwright test --reporter=json` →
  reshape → `tmp/testing/e2e.json` → helper. (Browser download is a
  pre-flight: `playwright install` if missing.)
- [ ] **Step 5: Verify** — Docker host with backend up: both specs pass + push
  `suite=e2e`. No backend: `task test-e2e` → `skipped`.
- [ ] **Step 6: Commit** — `feat(testing): Playwright e2e (replaces Selenium) + config fix`

---

### Task 5: Duplication suite (jscpd, Python + TypeScript)

**Files:**
- Modify: `frontend/package.json` (`jscpd` dev dep) — or a root dev tool
- Create: `dev/testing/jscpd.json` (config: patterns for `backend/` +
  `frontend/`, threshold, `--reporters json`)
- Modify: `Taskfile.yaml` — fill `test-dup`

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1)
- Produces: `tmp/testing/dup.json` (duplicated-line % + block count, from
  `jscpd --reporters json`)
- Seam: the per-language jscpd config (Python + TS; Go `cli/` included only if
  a threshold yields signal); the jscpd-JSON→artifact converter
- Deletion test: remove the jscpd config and `test-dup` has nothing to scan
- Adapters: 2 — the Taskfile task (production) and the jscpd-JSON→artifact
  converter

**SATISFIES:** `duplication-detected-and-pushed`

- [ ] **Step 1: Write the failing check** — a temp fixture with a deliberately
  duplicated block is detected and raises the block count.
- [ ] **Step 2: Add `jscpd` + the config** (`dev/testing/jscpd.json`): patterns
  `backend/**/*.py`, `frontend/src/**/*.{ts,tsx}`; a sensible threshold;
  `--reporters json`.
- [ ] **Step 3: Fill the Taskfile task** — `jscpd --config dev/testing/jscpd.json
  --reporters json` → reshape (duplicated-line % + blocks) → `tmp/testing/dup.json`
  → helper. Missing binary → `skipped`.
- [ ] **Step 4: Verify** — the fixture block is detected; `task test-dup` pushes
  `kubedash_duplication_lines_percent` + `kubedash_duplication_blocks_total`;
  exits 0 (reported, not a hard gate unless the threshold is exceeded).
- [ ] **Step 5: Commit** — `feat(testing): jscpd duplication suite (Py + TS)`

---

### Task 6: Static-security suite (Trivy) + oidc-mock for the DAST bootstrap

**Files:**
- Create: `dev/e2e/oidc-mock.py` (mock OIDC provider — shares the TASK-011 design;
  also the Wapiti `--form-script` login bootstrap)
- Create: `dev/testing/wapiti-login.py` (the `--form-script` that logs in via
  `oidc-mock.py` and prints the cookie/JWT for Wapiti)
- Modify: `Taskfile.yaml` — fill `test-security` (Trivy) and add the oidc-mock
  as a pre-flight for `test-dast`
- (Tool: `trivy` binary, dev-only)

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1); the `trivy` binary
- Produces: `tmp/testing/security-trivy.json` (findings from `trivy fs` +
  `trivy config` + `trivy image` where an image exists); `dev/e2e/oidc-mock.py`
  + `dev/testing/wapiti-login.py` (consumed by Task 7)
- Seam: Trivy's JSON output → the artifact shape's `security` field
  (`tool=trivy`, findings with `severity` + `type` ∈ sca|iac|secret|image); the
  mnemonic store pass is fail-open (Threat Matrix)
- Deletion test: remove the Trivy task and no static findings are pushed
- Adapters: 2 — the Taskfile task (production) and the trivy-JSON→artifact
  converter

**SATISFIES:** `trivy-static-findings-pushed`

- [ ] **Step 1: Write the failing check** — a known-vulnerable dependency
  fixture yields a `critical`/`high` finding pushed with `tool=trivy`; a clean
  tree pushes a zero series (present, not absent).
- [ ] **Step 2: Fill the Taskfile task** — `trivy fs . --format json` +
  `trivy config dev/docker-compose.yml charts/ Dockerfile* --format json` (+
  `trivy image` where an image exists) → merge findings → reshape
  (`tool=trivy`, `severity`, `type`) → `tmp/testing/security-trivy.json` →
  helper. Missing binary → `skipped`. (The mnemonic `scan_start` /
  `scan_store_findings` / `dep_ingest` pass is fail-open.)
- [ ] **Step 3: Build `dev/e2e/oidc-mock.py`** — a minimal OIDC provider
  (authorize + token endpoints) matching the TASK-011 design; a
  `wapiti-login.py` `--form-script` that hits it and emits the session for
  Wapiti.
- [ ] **Step 4: Verify** — `task test-security` pushes trivy findings (or zeros);
  the oidc-mock + login bootstrap yield a valid JWT (a `/api/v1/auth/me` 200
  check) — the pre-condition Task 7 relies on.
- [ ] **Step 5: Commit** — `feat(testing): Trivy static-security suite + oidc-mock bootstrap`

---

### Task 7: Dynamic-security suite (Wapiti DAST, JWT-authed)

**Files:**
- Modify: `Taskfile.yaml` — fill `test-dast` (pre-flight stack + oidc-mock;
  run Wapiti; `skipped` if down)
- (Tool: `wapiti3`, Python 3.12–3.14, dev-only)

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1); the live API on `:8080`;
  `dev/e2e/oidc-mock.py` + `dev/testing/wapiti-login.py` (Task 6)
- Produces: `tmp/testing/security-wapiti.json` (findings from `wapiti -o json`,
  `tool=wapiti`, `type` = the wapiti module)
- Seam: Wapiti targets the **Flask API** (not the SPA — Wapiti is crawler-blind
  to JS routes; the SPA's client-side surface is Playwright's, Task 4); the
  `--form-script` auth is the adapter that gets Wapiti a JWT session
- Deletion test: remove the `--form-script` and Wapiti's authed routes 401
- Adapters: 2 — the Taskfile task (production) and the wapiti-JSON→artifact
  converter

**SATISFIES:** `wapiti-dast-authed-and-pushed`

- [ ] **Step 1: Write the failing check** — against a live API, Wapiti runs
  authed and pushes `tool=wapiti` findings (or a zero series); no stack →
  `skipped`.
- [ ] **Step 2: Fill the Taskfile task** — pre-flight `:8080` + the oidc-mock;
  `wapiti -u http://localhost:8080 -o json --form-script dev/testing/wapiti-login.py
  -m sql,xss,exec,file,xxe,crlf,csrf,http_headers,cookieflags,csp` → reshape
  (`tool=wapiti`, `severity` by module, `type` = module) →
  `tmp/testing/security-wapiti.json` → helper. Wapiti hits are **leads**
  (severity by module), not confirmed vulns. Missing binary / stack → `skipped`.
- [ ] **Step 3: Verify** — live API: Wapiti runs authed (the pre-scan
  `/api/v1/auth/me` 200 holds) and pushes `tool=wapiti`; the dashboard's
  security panel now shows the trivy-vs-wapiti split. No stack → `skipped`.
- [ ] **Step 4: Commit** — `feat(testing): Wapiti DAST suite (JWT-authed via oidc-mock)`

---

### Task 8: Load suite (k6) + final dashboards

**Files:**
- Create: `dev/testing/k6/no_dup_jobs.js` (leader-election no-duplicate-RQ-jobs across leader replicas)
- Create: `dev/testing/k6/pods_budget.js` (`/resources/pods` p95 within the 5 s `namespace_list_timeout`)
- Create: `dev/testing/k6/jwt_single_flight.js` (concurrent 401s → one refresh)
- Modify: `Taskfile.yaml` — fill `test-load` (pre-flight stack; run the k6
  targets; `skipped` if down)
- Finalize: both Grafana dashboard JSONs (all panels populated; the load
  dashboard plots latency against the §7.5 budget lines)
- (Tool: `k6` binary, dev-only)

**Interfaces:**
- Consumes: the artifact shape + helper (Task 1); the live stack; the existing
  `task multi-up`/`task failover` leader-election path (the no-dup-jobs target
  automates what `failover` checks)
- Produces: `tmp/testing/load.json` (per-target rps/p50/p95/p99/errors/vusers
  from `k6 --summary-json`); the finalized dashboards
- Seam: k6 `thresholds` assert the pods-budget p95 ≤ 5 s and zero duplicate RQ
  enqueues; the k6-`--summary-json`→artifact converter (one `load` entry per
  `target`)
- Deletion test: remove a k6 target and its `target`-labeled series stop
- Adapters: 3 — the Taskfile task (production) + the three k6 scripts + the
  k6-JSON→artifact converter

**SATISFIES:** `load-budget-holds`, `dashboards-render-all-suites`

- [ ] **Step 1: Write the failing checks** — (a) pods-budget: p95 ≤ 5 s
  (k6 `thresholds` fail otherwise); (b) no-dup-jobs: zero duplicate RQ enqueues
  across N leader replicas; (c) jwt-single-flight: one refresh under concurrent
  401s.
- [ ] **Step 2: Write the three k6 scripts** with `thresholds` + a VU/ramp
  profile (starting values per the briefing Open Question — e.g. 50 VUs, 60 s
  ramp — to be tuned).
- [ ] **Step 3: Fill the Taskfile task** — pre-flight the stack (+ `task
  multi-up` for the no-dup-jobs target); run each k6 target `--summary-json` →
  reshape (one `load` entry per `target`) → `tmp/testing/load.json` → helper.
  No stack → `skipped`.
- [ ] **Step 4: Finalize the dashboards** — observability: latest-run
  pass/fail/skip by suite, duration, coverage %, dup %, **security split
  trivy-vs-wapiti** by severity, `run_id` trends. Load: RPS, p50/p95/p99,
  error rate, vusers **with the 5 s budget line** on the pods target.
- [ ] **Step 5: Verify** — `task test-all` end-to-end (Docker host): all eight
  suites push; both dashboards render populated panels (no "No data") for every
  suite that ran; the pods p95 holds the budget; no-dup-jobs shows zero
  duplicates. No-Docker host: the five no-app suites green, three live-app
  `skipped`, `test-all` exits 0.
- [ ] **Step 6: Commit** — `feat(testing): k6 load suite + finalized Grafana dashboards`

---

## Change Classification

`standard` → L2 verification floor (full suite run + the push pipeline
verified). Escalation note: Task 1 (the pipeline spine — Pushgateway wiring +
schema + the no-app/live-app degrade rule) is the load-bearing task; if the
final review finds the artifact shape or the gate policy (gate + observability
both fire) needs revision, escalate to `skillgrid:parallel-code-review` because
every suite depends on it (OD-1).

## Self-Review (run by the author)

1. **Spec coverage:** R1→T1/T2/T3, R2→T4/T5, R3→T6, R4→T7, R5→T8, R6→T9,
   R7→T10, R8→T11, R9→T12, R10→T13, R11→T14/T15/T16. No requirement without a
   truth or a task.
2. **Must-haves coverage:** every requirement maps to ≥1 truth; the artifact
   groups cover every Files line; K1–K6 name the cross-task contracts.
3. **One-way-door completeness:** OD-1 (Task 1), OD-2 (Task 4), OD-3 (Task 1 +
   Task 8) — all listed in Must-Haves and tagged on their tasks.
4. **Placeholder scan:** the Task 1 Taskfile tasks carry explicit
   "not-yet-built → skipped artifact" placeholders for the suites Tasks 2–8
   fill; no `TBD`/`implement later` in the spine (the helper + schema + artifact
   shape are shown in full). The k6 VU/ramp profile is the one parameter left
   to tune (briefing Open Question), not a placeholder.
5. **Type consistency:** the artifact shape is defined once (Task 1 Interfaces)
   and every suite's converter targets it; `run_id` is generated only in the
   helper (K2); the helper CLI (`<artifact> --suite` [+ `--tool`]) is stable
   across Tasks 1–8.

## Execution Handoff

8 tasks → **slicing required** (`skillgrid:slicing` produces `tasks.md` with
waves; the build shape is spine-first, so the first wave is Task 1 alone —
nothing else can push until the spine exists — then Tasks 2–8 in dependency
order, with 2/3/5 independent of each other once the spine lands). After
slicing, execution options: **Subagent-Driven (recommended)** — fresh subagent
per task with two-stage review; or **Inline** — `skillgrid:simple-execution`
with checkpoints. Final review: default `skillgrid:requesting-code-review`;
escalate to `skillgrid:parallel-code-review` if Task 1's artifact shape / gate
policy changes during execution.

**Dependency notes:**
- Task 4 (e2e) and Task 7 (dast) both consume `dev/e2e/oidc-mock.py` (built in
  Task 6) — so **Task 6 lands before Task 7**, and Task 4 can use the mock for
  its login round-trip (or the no-token seam) once it exists.
- Task 7 (dast) and Task 8 (load) need the live stack + the multi-instance
  leader setup (`task multi-up`) — both are live-app suites and degrade to
  `skipped` without it.
- **TASK-011** (Helm chart + e2e mock OIDC, re-scoped to drop CI/CD) is the
  sibling that owns `charts/kubedash` + the canonical `e2e/oidc-mock.py`; this
  change's Task 6 builds the same mock so the DAST bootstrap is self-contained,
  and the two should converge on one `oidc-mock.py` (TASK-011's is canonical —
  this change's Task 6 should reuse it once TASK-011 lands rather than fork it).
