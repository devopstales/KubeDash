# KubeDash — Repository Instructions

KubeDash is a multi-cluster Kubernetes dashboard with OIDC auth and
observability (logs, metrics, traces). One container: Gunicorn (Flask 3 +
Smorest) serves the REST API **and** the built React SPA; an in-process RQ
worker runs only on the leader replica (PG advisory lock + `leader_lease`
table). Python 3.12 / React 19 + TS + Vite / Go 1.22 CLI.

<!-- skillgrid-preamble:start -->
# Standards

## Environment & Tooling

- **Language**: Python 3.12 (`backend/`, uv), TypeScript 5.8 (`frontend/`), Go 1.22+ (`cli/`)
- **Package manager**: uv (`backend/`), pnpm via corepack (`frontend/`), Go modules (`cli/`)
- **Task runner**: `task` — root `Taskfile.yaml`, CWD-independent; `task --list` is the canonical task catalog
- **Install**: `uv sync` (in `backend/`); `task fe-install` (frozen lockfile)
- **Test**: `uv run pytest -m "not integration"` (backend unit floor; integration is kind-gated + Testcontainers); `corepack pnpm test` (in `frontend/`, Vitest + RTL + MSW); `go test ./...` (in `cli/`); `task e2e` / `task e2e-ssl` (Playwright vs the local stack)
- **Lint**: `uv run ruff check . && uv run mypy app` (`backend/`); `corepack pnpm lint` (`frontend/`); `go vet ./...` (`cli/`)
- **Format**: `uv run ruff format` (`backend/`); `corepack pnpm lint --fix` (eslint + prettier, `frontend/`); `gofmt -w .` (`cli/`)
- **Build (dev)**: `task fe-build` (tsc + eslint + vite → `frontend/dist`); `task build` (CLI, version injected via `-X`; `task cross` for 5 targets)
- **Run (dev)**: `task dev-stack` (compose + Alembic head + leader backend, plain HTTP :8080 — ADR-0027); `task fe-dev` (vite dev, API proxied to :8080)
- **Docker (dev deps)**: `task dev-up` (Postgres, Redis, Prometheus, Grafana, Jaeger, SSO); `task kind-up` (local kind + metrics-server, idempotent)
- **Security scan**: CI Trivy gates the image on CRITICAL (`exit-code: 1`); local `trivy fs . --scanners vuln` is advisory

## Key Directories

| Dir | What |
|---|---|
| `backend/` | Flask 3 + Smorest app factory — `app/{core,api,models,services,tasks}`, `migrations/` (Alembic), `tests/` (pytest), `wsgi.py` (Gunicorn + leader-gated RQ), `Dockerfile` (3-stage), `kubedash.ini` (primary config, ADR-0028), `static/` (the served SPA bundle) |
| `frontend/` | React 19 + TS + Vite (CoreUI template) — `src/views/` (one folder per route), `tests/` (Vitest + RTL), `e2e/` (Playwright), `STYLEGUIDE.md` (UI pieces) |
| `cli/` | Go kubectl credential plugin (cobra) |
| `charts/kubedash/` | Helm chart (N replicas, leader election) — the deployment artifact |
| `dev/` | docker-compose dev stack, kind config, certs/TLS, demo-data scripts |
| `.skillgrid/` | Skillgrid: knowledge bundle, ADR index, specs, state |
| `.backlog/` | Backlog.md tracker (tasks, decisions, milestones) |

## Engineering Standards

- **Backend layering:** `app/api/<domain>.py` is one Smorest `Api` per domain (≤ ~300 lines, Pydantic schemas, no cross-domain imports). `app/services/` is pure Python with **no Flask imports** — the integration boundary. `app/models/` is SQLAlchemy 2.0.
- **Read path:** UI and read services read from the **informer cache**, not per-request K8s API calls (ADR-0010). Mutations go through the API; the cache updates on watch events.
- **Push:** SSE is the primary server→client channel; WebSocket only for bidirectional exec (ADR-0009).
- **Tasks:** RQ tasks in `app/tasks/` run **only on the leader** (PG advisory lock, ADR-0008).
- **Frontend:** view-folder layout (one folder per route, CoreUI convention). Server state → TanStack Query; UI state → Zustand. No Tailwind — CoreUI SCSS. UI pieces follow `frontend/STYLEGUIDE.md`.
- **Object navigation:** no object identity in the URL (ADR-0040) — session-scoped object ref + same-origin form-POST deep link; one route per kind (no `/data` suffix).

## Security & Escalation Boundaries

- **Air-gap (ADR-0020):** zero outbound calls at runtime; no CDN/external references in the built bundle — `task fe-check` is the gate (CI runs the same script).
- **Sessions (ADR-0025):** HttpOnly cookies (`kd_access` + `kd_refresh`); no credentials in URLs or `localStorage`; `Authorization: Bearer` is accepted only for the kubectl credential plugin.
- **One-way doors (ADR-gated + migration-gated):** the cluster registry schema and `KUBEDASH_SECRET_KEY` (AES-256-GCM for kubeconfig encryption — distinct from the HS256 JWT key).
- **Config (ADR-0028):** `backend/kubedash.ini` is the primary source, `KUBEDASH_*` env is override, no hard-coded defaults for identities/credentials — fail fast at boot. Do not add fallback defaults.
- **Escalate (stop and ask):** any change touching the one-way doors, session transport, or the auth flow beyond an ADR's stated scope.

## Dependency Policies

- **ADR-gated domains:** stack, deployment shape, auth, push transport, task runner, caching, config source. Check `.skillgrid/ASSUMPTIONS.md` § LOCKED before changing any of them.
- **New third-party dependency:** record a new ADR (madr-full) before it lands; every ADR also gets a `.backlog/decisions/decision-NNN` copy (NNN = ADR number, zero-padded to 3).

## Architecture Constraints

- **Single container (ADR-0006):** Gunicorn serves the REST API + the built SPA; the RQ worker is in-process and leader-only (ADR-0007/0008).
- **Dev DB is migration-managed:** Alembic is the schema source of truth — never hand-edit the dev DB's schema; `task dev-stack` applies the same head path prod uses.
- **Chart is the deployment artifact:** `helm lint` + `helm template` must stay green; CI e2e installs the chart into kind against a mock OIDC.

## Definition of Done

- **CI (`.github/workflows/ci.yaml`):** backend `ruff check` + `mypy app` + `pytest -m "not integration"`; frontend `tsc --noEmit` + `eslint` + `vite build` + air-gap check; CLI `go vet` + `go test`; chart `helm lint` + `helm template` + `tests/test_chart.py`; image build + Trivy CRITICAL gate; workflow lint.
- **E2E (`.github/workflows/e2e.yaml`, main):** kind + Helm install + mock OIDC + Playwright smoke.
- **Local floor before shipping:** unit suite green (`uv run pytest -m "not integration"`), `task fe-build` + `task fe-check` after any frontend change, `task e2e` when the auth/SPA surface changed.

## Issue Tracker

Backlog.md — `.backlog/` via the `backlog` CLI (tasks, decisions, milestones); edit tracker state with the CLI, not by hand.

## Memory

Mnemonic — reference `~/.agents/skills/_shared/rules/mnemonic-memory.md`

## Code Indexing

Mnemonic — reference `~/.agents/skills/_shared/rules/mnemonic-memory.md` (Code Index Ladder)

## Testing standards

reference `~/.agents/skills/_shared/rules/code-standards.md`

## SDD Standards

reference `~/.agents/skills/_shared/rules/sdd-structure.md`
<!-- skillgrid-preamble:end -->

<!-- skillgrid:start -->
## Skillgrid

This project is configured with Skillgrid. Project: **kubedash**.

Config: `.skillgrid/config.yaml` (static) — read it before running any Skillgrid skill.
State: `.skillgrid/state.yaml` (dynamic) — where the project is right now (phase, current change, progress).

### Artifacts

| Artifact | Path |
|----------|------|
| Project knowledge (architecture, terms, ADRs, constraints) | `.skillgrid/knowledge/` (OKF bundle: `decisions/` `glossary/` `invariants/` `workflows/` `reference/` + `index.md`) |
| Architecture (live) | `.skillgrid/ARCHITECTURE.md` — update when the codebase changes |
| In-force ADR index | `.skillgrid/ASSUMPTIONS.md` § LOCKED |
| Project state (phase, current change, progress) | `.skillgrid/state.yaml` |
| Specs (briefing, blueprint, tasks, acceptance) | `.skillgrid/specs/` |
| Execution ledger | `.skillgrid/sdd/` (gitignored) |

**Domain model:** read the vocabulary + ADRs under `.skillgrid/knowledge/` (`glossary/` + `decisions/`, index: `index.md`; in-force decisions: `.skillgrid/ASSUMPTIONS.md` § LOCKED) before designing or implementing.

**Rules & standards:** operational rules are owned by this file's `### Rules` section (the real source — edit there). Shared standards are referenced, never inlined — each loads via the skills that apply it.

- **Coding conventions** — reference `~/.agents/skills/_shared/rules/code-standards.md` for detailed coding conventions.
- **Testing conventions** — reference `~/.agents/skills/_shared/references/strict-tdd.md` for the TDD cycle and testing conventions.
- **Commits & verification** — reference `~/.agents/skills/_shared/rules/commits.md` for the commit contract, `~/.agents/skills/_shared/rules/verification-ladder.md` for the verification ladder, and `~/.agents/skills/_shared/planning/rigor-tiers.md` for rigor tiers.
- **Memory, code index & web cache** — reference the `skillgrid:mnemonic` skill (shared rules: `~/.agents/skills/_shared/rules/mnemonic-memory.md`, `mnemonic-artifacts.md`, `mnemonic-code-indexing.md`).

### Rules

*Operational rules only — the real source of truth is this section (edit here). Design decisions do not live here; they are ADRs in `.skillgrid/ASSUMPTIONS.md` § LOCKED → `.skillgrid/knowledge/decisions/04-adr-NNNN-slug.md`.*

- **Ship keeps the work branch** — the `ship` phase does NOT merge into `main`. The work branch (`rebase`) is the deliverable and the rollback unit; merging into `main` is a separate, explicit act (VERIFIED assumption, 2026-10-18).
- **ADR gate** — check `.skillgrid/ASSUMPTIONS.md` § LOCKED before touching an ADR-gated domain (Dependency Policies). New ADRs: madr-full, 4-digit monotonic, never reused (next: 0041); each also gets a `.backlog/decisions/decision-NNN` copy.
- **Conventional commits** only; work units atomic and independently revertable.
- **Tracker is pipeline-driven** — SDD tickets are created by the `ticketing` skill and phase-lifecycle tracker updates follow `~/.agents/skills/_shared/rules/ticketing/backlogmd.md`. The Backlog nudge's conversation-start `backlog instructions overview` read applies to conversations doing tracker work (create/execute/finalize/lookup); for pipeline work the entry is `.skillgrid/state.yaml` + the in-flight spec, not the tracker. The versioned guides (`task-creation` / `task-execution` / `task-finalization`) stay mandatory before their lifecycle actions.
- **Spec zone commits before code zone** — spec artifacts land before the change that implements them.
- **Frontend loop** — use `task fe-dev`, never bare `pnpm dev` (no `VITE_API_BASE` → CORS-fails against :8080). After any frontend change: `task fe-build` + `task fe-sync` (Flask serves `backend/static/`), and `task fe-check` before shipping.
- **Backend loop** — `uv run pytest -m "not integration"` is the unit floor; integration tests are kind-gated (`task kind-up`) and need Docker (Testcontainers).
- **Config** — the INI is the source of truth (ADR-0028): change `backend/kubedash.ini` and `kubedash.ini.example` together with config code; never reintroduce hard-coded identity/credential defaults.
- **Knowledge bundle** — any write to a `.skillgrid/knowledge/` concept file updates `index.md` + `log.md` in the same edit.
- **Prose** — markdown the agent writes or reviews follows the `~/.agents/skills/google-styleguides/` group (python, typescript, go, markdown, json, shell, html-css): advisory, defers to the repo formatters (`ruff`/`mypy`, `tsc`/`eslint`, `gofmt`). Use `skillgrid:codebase-design` vocabulary (module, interface, seam, depth) for interface-design discussion in ADRs/specs.

### Issue Tracker

Backlog.md — reference `~/.agents/skills/_shared/rules/ticketing/` (backlogmd, github, gitlab, jira CLI + formatting standards) for ticketing conventions.

### Memory

Persistent memory is active (Mnemonic). Use `mem_save` for decisions, `mem_search` for recall, `code_status` → `code_index` → `code_search` for code orientation. Full protocol: `skillgrid:mnemonic` skill.

### Workflow

`brainstorming` → `writing-blueprints` → `slicing` → `ticketing` → execution (`subagent-execution` or `simple-execution`) → `qa` → `requesting-code-review` → `receiving-code-review` → `ship` → `reflect`

Run `skillgrid:onboarding` to update config after stack changes.
<!-- skillgrid:end -->

<!-- mnemonic:start -->
<CRITICAL_INSTRUCTION>

## Mnemonic — Memory

This project uses Mnemonic persistent memory (per-project SQLite store). Memory
supplements the repo — when a memory and a committed artifact disagree, **the
committed artifact wins** (repo is the source of truth).

**Session protocol (every session):**

1. `mem_session_start` once, before first project work.
2. **Recall before you work:** `mem_context(limit: 5)` for recent session
   summaries; `mem_search(query: "<topic>")` for the topic at hand.
3. Previews are truncated (~300 chars): `mem_get_observation(id)` for the full
   body before relying on it as a constraint or acceptance criterion.
4. Before saying "done": `mem_session_summary` with all six sections (Goal /
   Instructions / Discoveries / Accomplished / Next Steps / Relevant Files),
   then `mem_session_end`.

**Save (`mem_save`) when:** a decision is made, a non-obvious finding or gotcha
is discovered, a convention is confirmed. `title` MUST equal `topic_key`;
`scope: "project"`; pass the active `session_id`. SDD artifacts use
`skillgrid/{YYYY-MM-DD-<topic>}/{briefing|blueprint|tasks|execution-progress|report|review-report}`
— upsert semantics (same key replaces in place).
**Do not save:** what is already committed — code, ADRs, specs. Git is the
source of truth; the knowledge bundle is the ADR record.

Full protocol: `skillgrid:mnemonic` skill. Save shape + session rules:
`~/.agents/skills/_shared/rules/mnemonic-memory.md`.

## Mnemonic — Code Index

The code index is maintained for this project (git root, per-project store).
Prefer it over tree-dumping; prefer index tools over `rg`/`grep` when exploring
unfamiliar areas (`rg`/`grep` remain right for exact-identifier lookups).

**Orientation ladder (this repo's mounted menu):**

1. `code_status` — freshness first (`fresh` | `lag` | `empty` | `unknown`). If
   not `fresh`, run `code_index` (incremental) before trusting any search or
   structural result. Check after clone, branch switch, or large edits.
2. `code_explore` — primary structural query: one call returns the relevant
   symbols' verbatim source, the call paths between them, and a blast-radius
   summary. Treat the source it returns as already read; do not re-verify with
   grep.
3. `code_search` (BM25) / `code_semantic_search` / `code_hybrid_search` — find
   where something is; keep result provenance (mem vs code, never silently fused).
4. `code_read` — exact slice, only for a path + line range already narrowed by
   the steps above. Never read a whole file speculatively.

**After a change:** `code_affected` answers "which tests do I run after this
change" (import + test edges, depth-capped).

Full convention (freshness semantics, intent router, CLI fallback):
`~/.agents/skills/_shared/rules/mnemonic-code-indexing.md`.

</CRITICAL_INSTRUCTION>
<!-- mnemonic:end -->

<!-- BACKLOG.MD GUIDELINES START -->
<!-- backlog.md-instructions-version: 1.53.0 -->
<CRITICAL_INSTRUCTION>

## Backlog.md Workflow

This project uses Backlog.md for task and project management.

**At the beginning of each conversation in this project, run `backlog instructions overview` before answering or taking action. Re-read it only if you have not read it yet in the current conversation.**

Use the overview to decide whether to search, read, create, or update Backlog tasks.

Before task lifecycle actions, read the matching detailed guide:
- `backlog instructions task-creation` before creating or splitting tasks
- `backlog instructions task-execution` before planning, changing status or assignee, adding a plan or implementation notes, or implementing task work
- `backlog instructions task-finalization` before checking acceptance criteria, writing final summaries, or moving tasks to terminal statuses

Use `backlog <command> --help` before running unfamiliar commands. Help shows options, fields, and examples.

Do not edit Backlog task, draft, document, decision, or milestone markdown files directly. Use the `backlog` CLI so metadata, relationships, and history stay consistent.

</CRITICAL_INSTRUCTION>
<!-- BACKLOG.MD GUIDELINES END -->
