# Review — 2026-10-27-postgres-queue-revocation-active-active

> Change: `.skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/`
> Generated: 2026-11-10 (requesting-code-review)
> Diff range: `54486251^..5ad77ff0` (the change) + `1d401eac..HEAD` (QA in-gate fixes + the review fixes below)
> Rigor tier: T2 (single-pass three-axis review per `_shared/planning/rigor-tiers.md`)
> Independence: **Grade C on all three axes** — see `## Independence`. This review is
> **diagnostic only** and does not by itself satisfy the "independently reviewed" gate.

The durable audit record of the code review, next to `report.md` (which owns the QA
gate). The three axes are reported side by side, never merged.

## What Important means

- **Critical** — must fix before merge: security, data loss, broken functionality, or a
  `SATISFIES` scenario whose code path does not match its Given/When/Then. Blocks `ship`.
- **Important** — should fix before merge: drift from a term or an in-force ADR, a hard
  standard breach, a missing or partial requirement, unrequested behavior. Unfixed
  Important findings do not proceed.
- **Minor** — nice to have: baseline smells, style, optimization, doc polish. Capped and
  summarized below.

## Cap the nits

5 Minor findings listed per axis maximum; nothing collapsed on this diff. Tooling-found
issues (ruff/mypy — the branch-wide debt in W013) are not re-reported here.

## Passes

### Standards

- **Worst issue (within this axis):** the leader fence was incremented by a
  `SELECT`-then-bind, so two peers acquiring in the same instant could hold an *equal*
  fence — the tie ADR-0031 says the fence breaks. Fixed in this pass.
- **Findings:** 0 Critical / 3 Important / 3 Minor
- **Verdict:** met-with-fixes

### Spec

- **Worst issue (within this axis):** 2 of 12 acceptance scenarios have no automated
  assertion (dev-stack topology + cross-node migration), and one blueprint artifact was
  never created. Both parked by the QA gate (W028/W029); no behavior is unverified.
- **Findings:** 0 Critical / 1 Important (process evidence, parked) / 1 Minor
- **Verdict:** met-with-fixes

### Security

- **Worst issue (within this axis):** none exploitable. The only credential in the diff is
  the pgEdge dev container's published example password in `dev/pgedge/db.json`.
- **Findings:** 0 Critical / 0 High / 0 Medium / 1 Low / 1 Info
- **Verdict:** secure

## Findings

### Critical

- None.

### Important

- [Standards] `backend/app/core/leader.py:acquire_once` — fence advanced by reading
  `SELECT fence` and binding `next_fence`; two concurrent acquires interleave between that
  read and the upsert, so both can capture the same fence. ADR-0031 defines the fence as
  the cross-node LWW tiebreaker via an increment. *Blast radius was contained* — the
  heartbeat predicate also matches `replica_id`, so a duplicate fence cannot make two
  replicas lead — but the ADR's stated mechanism did not hold. **Fixed:** the increment
  now lives inside the upsert (`fence = leader_lease.fence + 1`, qualified target column;
  literal `1` on the insert side), which also deletes one statement.
- [Standards] `backend/app/core/security.py:_auth_check` / `_current_jti` — the
  Bearer-then-cookie credential precedence (ADR-0025, a one-way door) was implemented
  twice; a future edit to one copy would silently diverge the accept path from the
  logout/revocation path. **Fixed:** one `_request_token()` seam, and `_auth_check` binds
  `g.current_jti` from the claims it already verified, so `_current_jti` no longer decodes
  a second time.
- [Standards] `backend/app/models/task.py` module docstring claimed "the reaper bounds the
  table"; the reaper only re-queues `processing` rows — `status='done'` rows are never
  deleted, so the table grows with every completed run (~1,440 rows/day/task type at the
  current `INTERVALS`). **Docstring corrected**; retention is a task-runner design
  question (ADR-gated domain) and is parked as **W035** rather than invented here.
- [Spec] No TDD RED/GREEN evidence table and no `.skillgrid/sdd/` ledger for any of the 7
  tickets → **parked as W030** per the QA gate's rule that absence of the table is
  advisory (it may never escalate on absence alone), so this is a recorded process gap,
  not an open code action. Behaviour coverage itself is complete (12/12 scenarios have a
  test or live evidence).

### Minor

- [Standards] `backend/app/core/pgqueue.py:reap` — `BACKOFF_CAP_SECONDS` is interpolated
  with an f-string into the SQL while the module's stated rule is bound params. The value
  is a module constant (not injectable), but bind it as `:cap` for consistency with `fail`.
- [Standards] `backend/wsgi.py:_start_worker_if_leader` — the name says "if leader" but the
  worker starts on every replica; only *scheduling* and the *reaper* are leader-gated.
  Rename to `_start_worker()` (or `_start_worker_on_replica`).
- [Standards] `backend/app/api/auth.py` calls `security._current_jti()`. A private name
  crossing a module boundary: make it public (`current_jti`) since the API layer is a
  documented caller.
- [Spec] `claim()` returns `(path, id)` where the blueprint said `str | None`. Justified —
  the worker needs the id to `complete`/`fail` — and documented in the code, but the
  blueprint should be reconciled at archive time (folded into W029).

## Minor detail: what was checked and found clean

Parameterized SQL throughout (no identifier interpolation, no dynamic table names);
`FOR UPDATE SKIP LOCKED` inside the single atomic `UPDATE`; `attempts` deliberately not
incremented on claim (failures, not claims, drive dead-lettering); backoff computed
SQL-side from pre-increment `attempts`; migration is guarded and idempotent for
create_all-era dev DBs; `services/` stays Flask-free (`Engine` passed in); one-shot OIDC
state uses `DELETE`-as-test rather than read-then-delete; deny-list rows are TTL-bounded
by the token's own lifetime; `tests/core/test_pgqueue.py` runs against real Postgres via
Testcontainers, so the `SKIP LOCKED` path is genuinely exercised.

## Independence

| Axis | Grade | Rationale |
|------|-------|-----------|
| Standards | C | inline self-review — no subagent dispatch is available in this runtime |
| Spec | C | inline self-review, and the same session wrote the change |
| Security | C | inline self-review, and the same session wrote the change |

**Reading the grade:** **C** = inline self-review or the implementer's verdict leaked in —
**diagnostic only**, cannot stand as the independent evidence that `ship` or a merge
requires. To reach Grade A this pass needs re-dispatch from a fresh context (or
`skillgrid:parallel-code-review` with a cross-model reviewer).

## Verdict

- **Standards:** met-with-fixes (all 3 Important fixed in this pass)
- **Spec:** met-with-fixes (evidence/artifact gaps parked as W028/W029/W030, no code action)
- **Security:** secure
- **Floor (decides):** met-with-fixes — and **Grade C**, so the independent-review gate is
  still open
- **Worst issue (across all three axes):** the fence's read-then-bind could produce equal
  fences across peers (fixed); no exploitable security finding
- **Unfixed Important count (must be 0 to proceed):** 0 code items (one process item parked
  as W030 by the QA gate's advisory rule)
