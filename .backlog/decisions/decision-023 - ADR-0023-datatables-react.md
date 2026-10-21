---
id: decision-023
title: "ADR-0023 User-management tables: DataTables React with the Bootstrap 5 skin"
date: '2026-10-21'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0023-datatables-react.md`

# User-management tables: DataTables React with the Bootstrap 5 skin

---
status: "accepted"
date: 2026-10-21
supersedes: none
---

**Decision-makers.** paladm (project owner)
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash 4.1 renders the User List as a CoreUI card around a Bootstrap 5
DataTable (`vendor/datatables@2.2.2` + `dataTables.bootstrap5`, columns
Username, Email, Permission, Type, Action, `responsive`, `pageLength: 25`).
The 5.0 user-management views were specified and built with CoreUI `CTable`,
which has no search, paging, or the 4.1 table chrome. Operators coming from
4.1 should see the same list structure. ADR-0005 keeps the CoreUI React
shell; it does not choose the data-grid widget inside that shell.

DataTables' React quick start
(<https://datatables.net/manual/components/react/quick-start>) shows
`datatables.net-react` with the default `datatables.net-dt` stylesheet.
4.1 does not use that stylesheet. It uses the Bootstrap 5 integration.

#### Decision Drivers

- The User List, privilege list, template list, audit list, and My Access
  list must match the 4.1 DataTable structure
- The CoreUI shell stays (ADR-0005); Tailwind stays forbidden
- The grid must be bundled (ADR-0020). No CDN stylesheet or script
- Only MIT DataTables packages. The commercial Editor extension is out
- One table component for every list in this feature, so the pages do not
  mix `CTable` and DataTables

#### Considered Options

- `datatables.net-react` + `datatables.net-bs5` (Bootstrap 5 skin)
- `datatables.net-react` + `datatables.net-dt` (the quick-start stylesheet)
- Keep CoreUI `CTable`

#### Decision Outcome

Chosen option: "`datatables.net-react` + `datatables.net-bs5`", because 4.1
loads `dataTables.bootstrap5` inside the CoreUI card, and the React
component API is the one in the quick start. `datatables.net-dt` would put
the DataTables default skin on a Bootstrap page.

Wiring, once per app, in a shared `frontend/src/components/KubeDataTable.tsx`:

```js
import DataTable, { Column } from 'datatables.net-react'
import DT from 'datatables.net-bs5'
import 'datatables.net-bs5/css'

DataTable.use(DT)
```

Lists pass row objects and `<Column>` children. Options match 4.1:
`responsive: true`, `pageLength: 25`, table class `table table-bordered`.
The card around the table stays CoreUI (`CCard`, header "User List" on the
users page). jQuery is not added back. The Editor extension is not installed.

##### Consequences

- Good, because the lists use the same grid 4.1 operators already know,
  inside the existing CoreUI shell
- Good, because search, paging, and the Bootstrap table skin come from the
  library instead of a one-off `CTable`
- Bad, because `datatables.net-react` and `datatables.net-bs5` are new
  runtime dependencies and must stay vendored in the image (ADR-0020)
- Bad, because DataTables measures layout, so Vitest mocks
  `KubeDataTable` and asserts the columns and rows passed in. The real
  grid is checked in the browser
- Neutral, because ADR-0005 is unchanged: CoreUI still owns the shell,
  sidebar, cards, buttons, and modals

##### Confirmation

- `frontend/package.json` depends on `datatables.net-react` and
  `datatables.net-bs5`, and does not depend on `datatables.net-dt` or
  `datatables.net-editor`
- User List, My Access, privilege list, template list, and audit list
  render through `KubeDataTable`
- `task fe-check` stays green (the CSS is imported from the package, not
  a CDN URL)

#### Pros and Cons of the Options

##### `datatables.net-react` + `datatables.net-bs5` (chosen)

The React component from the quick start, with the stylesheet 4.1 already uses.

- Good, because the table matches 4.1's Bootstrap 5 DataTable inside a CoreUI card
- Good, because the React API (`DataTable`, `Column`, `DataTable.use`) is the documented one
- Bad, because it is a new dependency pair

##### `datatables.net-react` + `datatables.net-dt`

The quick start copied literally, including `import 'datatables.net-dt/css'`.

- Good, because it matches the quick-start snippet with no adaptation
- Bad, because the default DataTables skin is not the 4.1 Bootstrap table

##### Keep CoreUI `CTable`

- Good, because it adds no dependency
- Bad, because the list is not the 4.1 DataTable (no search, no paging, different markup)

#### More Information

- 4.1 include: branch `4.1`,
  `src/kubedash/templates/segments/components/datatable_snippet.html.j2`
  (`datatables@2.2.2`, `dataTables.bootstrap5`)
- React API: <https://datatables.net/manual/components/react/quick-start>
- This ADR does not change ADR-0022's routes. It chooses the grid inside
  those pages.
