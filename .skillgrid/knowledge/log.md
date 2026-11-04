# KubeDash — Knowledge Base Log

> Journal of knowledge-base writes, newest last. Every write appends here in
> the same edit as the concept + `index.md`.

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
