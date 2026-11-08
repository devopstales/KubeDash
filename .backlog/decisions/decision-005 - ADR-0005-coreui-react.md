---
id: decision-005
title: "ADR-0005 CoreUI React + free admin template over shadcn/ui/Tailwind"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0005-coreui-react.md`

# CoreUI React + free admin template over shadcn/ui/Tailwind

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

The 5.0 SPA needed a React component stack and a starting scaffold.
4.1 was Bootstrap 5 (server-rendered Jinja2). Candidate stacks:
shadcn/ui + Tailwind, MUI, or the CoreUI free React admin template
(Bootstrap/SCSS-based).

#### Decision Drivers

- **4.1 visual continuity.** Operators move from a Bootstrap 5 UI;
  keeping the Bootstrap family makes the 5.0 shell recognizable.
- **No Tailwind.** The CoreUI template is SCSS-based; adopting it means
  styling is CoreUI SCSS variables + `@coreui/coreui` classes, custom
  overrides in `src/scss/`. Tailwind utility classes would be a second
  styling system.
- **Admin-template shape fits the product.** A K8s dashboard is
  sidebar + header + dense data tables — exactly the free template's
  shell (Header, Sidebar, Footer, `_nav`, `routes`).
- **MIT, AI-friendly scaffold.** The template is MIT-licensed and
  widely-known, so generated code lands in the right places.

#### Considered Options

- **shadcn/ui + Tailwind.** Rejected: drops the Bootstrap lineage, adds
  a second styling system, and the admin shell would be built from
  scratch.
- **MUI.** Rejected: theming drift from 4.1; heavier license/dependency
  surface than needed.
- **CoreUI free React admin template (CHOSEN).** Adopt its `src/`
  layout verbatim as the KubeDash shell (Header, Sidebar, Footer,
  `_nav.tsx`, `routes.tsx`), then extend with KubeDash feature views.

#### Decision Outcome

**Chosen option: `@coreui/react` on the free admin template.**

- View-folder convention: one `src/views/<Name>/` per route; views do
  not import each other except through `lib/` (API client + types) and
  `components/` (shared widgets).
- Icons: Font Awesome Free (`@fortawesome/fontawesome-free`) — broader
  K8s glyph coverage than the template default.
- Data tables: DataTables React with the Bootstrap 5 skin (ADR-0023
  builds on this choice); secret values via react-syntax-highlighter
  (ADR-0024).
- Styling: CoreUI SCSS only — no Tailwind; dark mode via
  `[data-theme="dark"]`.

##### Consequences

- Good: 4.1 continuity; the admin shell ships with the template; one
  styling system; MIT.
- Bad: CoreUI is a Bootstrap-derived library — less idiomatic-React
  than headless stacks; its conventions (view folders, SCSS) must be
  followed, not blended.
- Confirmation: `frontend/package.json` (`@coreui/react`),
  `frontend/src/_nav.tsx`, `frontend/tests/nav.test.tsx`
  (`menu-matches-4-1-without-plugins`), `frontend/STYLEGUIDE.md`.

#### Linking Decisions and Constraints

- ADR-0022 — the sidebar's 4.1-parity structure sits on this shell.
- ADR-0023 / ADR-0024 — table + highlight skins chosen for this stack.
- ADR-0020 — the template is vendored (air-gap).

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §4.1; verified against
`frontend/package.json` (`@coreui/react ^5.13.0`, `datatables.net-bs5`,
`react-syntax-highlighter`) and `frontend/src/_nav.tsx` on 2026-11-06.
