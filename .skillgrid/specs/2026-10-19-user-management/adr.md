# ADR review — user-management UI matches 4.1 DataTables

ADR review for the user-management list UI. In-force rows read from
`.skillgrid/ASSUMPTIONS.md` § LOCKED on 2026-10-21.

## Reviewed

- ADR-0005 — CoreUI React shell. Still in force. DataTables replaces
  `CTable` inside that shell; it does not replace the shell.
- ADR-0011 — plugin kubeconfig. The User List has no Kubernetes user type
  and no certificate download.
- ADR-0013 — permission management. Bind/unbind and templates stay this
  feature's behavior. The privilege form is the 4.1 layout over that API.
- ADR-0020 — air-gap. DataTables CSS is imported from the npm package.
- ADR-0021 — no manual user create/delete. The User List omits Add User
  and Delete. Type is OpenID or Local.
- ADR-0022 — routes stay `/admin/permissions`, `?tab=audit`, and
  `/permissions`. This review does not move them.

## Created

- ADR-0023 — `datatables.net-react` + `datatables.net-bs5`.
  Record: `.skillgrid/artifacts/04-adr-0023-datatables-react.md`.
  Tracker copy: `.backlog/decisions/decision-023 - ADR-0023-datatables-react.md`.
