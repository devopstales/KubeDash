# ADR Review Manifest

- **Change:** `2026-10-21-sidebar-nav`
- **Status:** completed
- **Review date:** 2026-10-21

## In-Force ADRs Reviewed

- `.skillgrid/artifacts/04-adr-0005-coreui-react.md` — CoreUI React + free admin
  template; the sidebar uses its `CSidebarNav`/`CNavGroup`/`CNavTitle` primitives
  and dark theme
- `.skillgrid/artifacts/04-adr-0013-permission-management.md` — the 5.0-only
  `My access` entry (self-service kubeconfig) lives in the Permissions section
- `.skillgrid/artifacts/04-adr-0020-air-gap-deployment.md` — the nav must not
  introduce external URLs (air-gap check stays green)
- `.skillgrid/artifacts/04-adr-0021-local-admin-auth.md` — admin gating of the
  Settings group follows the existing role check (`me.role == 'admin'`)

## New Durable ADRs Created

- `.skillgrid/artifacts/04-adr-0022-sidebar-nav-4-1-parity.md` — sidebar
  navigation adopts the 4.1 information-parity structure (sections, groups,
  entry names, order, admin gating); the 4.1 Plugins group is dropped (no 5.0
  plugin system)

## Supersessions

- None.
