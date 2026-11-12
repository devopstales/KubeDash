# Review — TLS Edge + Security Headers (R3/R4 header layer)

> Change: `.skillgrid/specs/2026-10-24-tls-security-headers/` (moves to `.skillgrid/xarchive/…` at ship)
> Generated: 2026-11-03 (requesting-code-review)
> Diff: working-tree (untracked `backend/app/core/security_headers.py`, `backend/tests/test_security_headers.py` + the `backend/app/__init__.py` wiring hunk) — not yet committed; SHA range lands at ship.
> Rigor tier: T2 (blueprint `Tier: T2`)
> Independence: Grade A per axis (three fresh subagent contexts, no shared session history)
>
> The durable audit record of the code review. Next to `report.md` (which owns the QA gate).
> The three review axes are reported **side by side, never merged** — that separation is the point.

## What Important means

- **Critical** — must fix before merge. Security, data loss, broken functionality, a `SATISFIES` scenario whose RED evidence is missing or whose code path does not match the Given/When/Then.
- **Important** — should fix before merge. Architecture drift from a term or in-force ADR, a hard standard breach, a missing/partial requirement, or behavior the spec never asked for (scope creep). Unfixed Important issues do not proceed.
- **Minor** — nice to have. Baseline smells, style, optimization, doc polish. Capped.

## Passes

> Three axes, side by side. Never merged into one verdict.

### Standards

- **Worst issue (within this axis):** missing type annotation on `_headers` (Important, fixed).
- **Findings:** 0 Critical / 1 Important / 2 Minor (3 FYI collapsed)
- **Verdict:** met-with-fixes

### Spec

- **Worst issue (within this axis):** none (two non-blocking nuances, not findings).
- **Findings:** 0 Critical / 0 Important / 0 Minor
- **Verdict:** met

### Security

- **Worst issue (within this axis):** `no-store` scoped on raw `request.path` (Medium, fixed).
- **Findings:** 0 Critical / 0 High / 1 Medium / 1 Low / 0 Info
- **Verdict:** secure-with-fixes

## Findings

### Critical

- (none)

### Important

- [Security→**FIXED**] `backend/app/core/security_headers.py` — `no-store` branch keyed on
  `request.path.startswith("/api/")`; `request.path` semantics + smorest method-specific routing
  mean a literal `/api/`-prefixed path that does **not** match an API rule could be (or could
  wrongly not be) no-stored. Scoping on `request.url_rule.rule` (the matched, registered rule)
  makes the invariant exact: only responses that matched a route under `/api/` are no-stored.
  Locked by `test_security_headers.py::test_api_no_store_scoped_to_matched_rule_not_raw_path`.
- [Standards→**FIXED**] `backend/app/core/security_headers.py:34` — `_headers(resp)` was the only
  untyped function in the module; the `# type: ignore[no-untyped-def]` papered over the gap. Now
  annotated `def _headers(resp: Response) -> Response` (`from werkzeug.wrappers import Response`).

### Minor

- [Standards] `test_security_headers.py` — the constant header-set assertions repeat across the
  3xx and 401 tests (Duplicated Code smell). Consider one parametrized case over the response
  classes asserting the header set once. (Deferred — the two tests intentionally isolate the
  3xx-login and 401-envelope paths; the overlap is small.)
- [Standards] `test_security_headers.py` — the `header → value` pairs in
  `test_api_response_carry_all_security_headers` are a table that could be one `for`. (Deferred.)

### Parked (FYI / future-state)

- [Security→**PARKED**] `apidocs.py:46-50` — `/api/docs/<name>` swagger assets are un-hashed but
  under the `/api/` prefix; a future re-pin of the vendored bundle under the same name would be
  served from the browser cache. Not exploitable today (no re-pin has happened). Latent
  supply-chain/integrity gap — re-address when the swagger bundle is re-pinned (hash the filename
  or pin `no-store` with a test).
- [Standards→**FYI**] `test_security_headers.py` — the fixture passes `KUBEDASH_JWT_SECRET` where
  `tests/api/conftest.py` uses the double-prefixed `KUBEDASH_KUBEDASH_JWT_SECRET` (the INI-leg
  override). Works for `create_app`'s `app.config` either way; only the Settings leg differs.
  Confirm intended spelling at next conftest touch.
- [Standards→**FYI**] `__init__.py:107` — in-function import of `register_security_headers`
  matches the `apidocs`/`init_oidc` pattern; top-level would be equally consistent. Pure taste.

## Independence

| Axis | Grade | Rationale |
|------|-------|-----------|
| Standards | A | fresh `reviewer` subagent; saw only the work product + glossary/ADR/standards sources |
| Spec | A | fresh `reviewer` subagent; saw only the work product + acceptance.feature/blueprint/briefing |
| Security | A | fresh `security-reviewer` subagent; saw only the work product + OWASP skill references |

**Reading the grade:** all three are **A** — independent evidence, not the implementer talking to itself.

## Verdict

- **Standards:** met-with-fixes
- **Spec:** met
- **Security:** secure-with-fixes
- **Floor (decides):** met-with-fixes
- **Worst issue (across all three axes):** `no-store` scoping on raw `request.path` (Medium, FIXED)
- **Unfixed Important count (must be 0 to proceed):** 0 (both Important findings fixed this pass)

## Triage / fix loop (receiving-code-review)

| Finding | Severity | Disposition | Action |
|---------|----------|-------------|--------|
| no-store raw-path scope | Medium | FIX NOW | scoped on `url_rule.rule` + regression test; 8/8 pass |
| `_headers` untyped | Important | FIX NOW | annotated with `werkzeug.wrappers.Response`; 8/8 pass |
| swagger asset un-hashed | Low | PARK | future-state; re-address at re-pin |
| duplicated header assertions | Minor | PARK | deferred; the two tests intentionally isolate paths |
| header-table loop | Minor | PARK | deferred |
| fixture JWT-secret spelling | FYI | PARK | confirm at next conftest touch |
| in-function import | FYI | PARK | taste; no circularity |
