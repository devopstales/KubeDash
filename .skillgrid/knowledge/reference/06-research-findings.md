# Research Findings — Durable, Cross-Change

> Distilled, cross-change findings that survive their originating change.
> Append-only; each entry names its source change and evidence. Change-local
> findings stay in that change's `report.md` (archive).

## jscpd dead-code detection characteristics (source: 2026-11-07-dead-code-cleanup)

jscpd's dead-code pass is a **candidate generator, not a proof**. Verified in
the 2026-11-07 dead-code sweep (187 findings, 60 files deleted):

1. **False positives in JSX value/member position.** jscpd flagged `import
   React from 'react'` as unused in `CertManagerData.tsx` while
   `React.Fragment` was used in JSX (commit `7a55bde3` repair), and flagged
   the `CIcon` import in `AppHeaderDropdown.jsx` as unused while 9 `<CIcon/>`
   uses remained (`17425c2f` repair). The build (tsc + vite) and the test
   suite caught both; the jscpd report did not.
   **Rule:** every jscpd unused-import finding gets an independent
   import-specifier grep + a build/tsc gate before deletion. Budget for a
   fix round (~1% of findings).
2. **`index.*` entry-point heuristic blind spot.** Files imported only from a
   barrel (`index.js`) are never flagged unused — the barrel is treated as an
   entry point, so its re-exports count as imported. This masked two dead
   chains: `views/icons/index.js` (deleted as a T03 addendum, `c40d4c49`) and
   `components/header/` (still open, TASK-099/W026).
   **Rule:** for barrel-structured code, grep external references of the
   *barrel itself*; zero external refs ⇒ the whole chain is dead; delete
   chain-first.
3. **String-based wiring is invisible.** Spawn strings
   (`wsgi.py:179` → `_rq_worker_main`), the scheduler registration, and
   `tests/test_file_map.py`'s string-pinned EXPECTED list keep 23 backend
   files alive that look unused to any import analysis.
   **Rule:** before deleting any backend file, check the three string-wiring
   sites (spawn string, scheduler, test_file_map.py) — the 2026-11-07 sweep
   recorded per-file verdicts in `.backlog` note `5654e914`.

Related tooling note: `tsc --noEmit` does not type-check `.jsx` files
(checkJs off), so a deleted import in a .jsx is invisible to the build until
eslint (react/jsx-no-undef) or runtime — run eslint over .jsx in any
template-residue sweep (frontend/STYLEGUIDE.md).
