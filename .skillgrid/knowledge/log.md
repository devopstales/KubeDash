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

## 2026-10-26

- Bundle restructured: `.skillgrid/artifacts/` → `.skillgrid/knowledge/`.
  - 13 ADR files (0014..0026) → `decisions/`
  - `01-business-terms.md`, `02-technical-terms.md` → `glossary/`
  - Created `invariants/`, `workflows/`, `reference/` (empty)
  - Created `index.md`, `log.md`, `reverse-index.md`
  - `config.yaml` `conventions.artifacts` → `.skillgrid/knowledge`
  - Path references updated: `AGENTS.md`, `ARCHITECTURE.md` (§2 tree, §12, §13, header), `ASSUMPTIONS.md` (header + LOCKED paths). Archive/spec/backlog files kept as history.
