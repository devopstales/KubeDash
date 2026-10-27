# Sidebar — 4.1 shell and menu — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution (recommended) or skillgrid:simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Status:** PROPOSED
> **Tier:** T1
> **Critic:** skipped (T1)
> **Build shape:** Facade — the 4.1 menu and stub pages stand up on the existing CoreUI shell; resource views stay out of this change.
> **Change classification:** `small` (one frontend concern, no migration, no new dependency; verification floor L1)
> **Goal:** Replace the four-item sidebar with the 4.1 menu minus Plugins, put Cluster Details first under Permissions, and point every entry at an existing view or one shared stub.
> **Architecture:** `navigation({ clusterId, isAdmin })` in `_nav.tsx` is the only menu source. `AppSidebar` reads the cluster store and `useCluster().me` and passes the result to the existing `AppSidebarNav`. Stub paths share `views/Stub`. Settings URLs stay behind the existing `AdminRoute`. Header visibility moves to a zustand store both header and sidebar already can import.
> **Tech Stack:** React 18, TypeScript, CoreUI (`CNavTitle`, `CNavGroup`, `CNavItem`, `CBadge`), React Router, Zustand, Vitest, Testing Library. No new dependencies.
> **Spec:** `.skillgrid/specs/2026-10-21-sidebar-nav/briefing.md`
> **Decision note:** Cluster Details is the one menu row ADR-0022 does not list. The accepted ADR file is not edited. Menu labels, order, dropped plugin entries, and the shared `/clusters` target for Cluster Metrics and Kubernetes Cluster come from that ADR plus briefing.md § Menu.

## Implementation Boundary

KubeDash 4.1 is a visual and menu-structure reference only. Do not copy,
import, serve, or modify its Jinja templates. Every production change in this
blueprint is implemented in the existing React/CoreUI SPA under
`frontend/src/`.

## Hypothesis

**Claim:** The existing `AppSidebarNav` can render the 4.1 group/title/badge structure from a pure `navigation()` result, and one stub component can back every entry that has no view.
**Right condition:** `navigation({ clusterId: 7, isAdmin: true })` lists Cluster Details at `/clusters/7` as the first Permissions entry, omits Plugins, and `/workload/pods` renders the stub heading `Pods`.
**Wrong condition:** Cluster Details stays a top-level item, a plugin entry is present, or a stub path redirects to `/clusters`.
**Thinnest MVP:** Task 1's contract test plus Task 3's `/workload/pods` route. If the contract shape cannot be rendered by `AppSidebarNav` without a new nav component, stop.
**Door check:** Task 1. A failing assertion on order or on the Plugins absence means the data shape is wrong; do not start routes until that test passes.

## Global Constraints

- Menu rows, labels, paths, and dropped entries: per briefing.md § Menu.
- Plugins group and nested plugin entries stay absent: per `.skillgrid/artifacts/04-adr-0022-sidebar-nav-4-1-parity.md`.
- CoreUI only: per ADR-0005 and per AGENTS.md § Rules (no Tailwind).
- React only: the 4.1 Jinja files are reference material, not implementation
  inputs. No Jinja or server-rendered frontend code.
- No outbound URL in the bundle: per ADR-0020. Footer and nav items have no `href` to another origin.
- No new dependency: per AGENTS.md § Rules.
- `app/services/` is not touched. This change is frontend-only.
- Admin enforcement stays `AdminRoute` in `frontend/src/routes.tsx`. Hiding a nav group is presentation.

## Must-Haves

### Truths

- An admin with cluster id 7 sees, in order, Dashboard (Cluster Metrics, Workload + Beta), title Permissions, Cluster Details → `/clusters/7`, My access → `/permissions`, then User Management and Cluster Permissions, then title Interface and its six groups, then Settings. `backstop` — confirmed by the rendered sidebar test, not by reading the array alone.
- A non-admin does not see Settings, Auth Provider, HA Status, or Audit Log. `backstop`
- The strings `Plugins`, `Cert-Manager`, `LoadBalancers`, `Gateway API`, `Trivy Operator`, and `Applications` do not appear in `navigation()` for either role.
- `/workload/pods` renders `Pods` and `This view is not available yet.` and does not navigate away. `backstop`
- `/settings/sso-config` redirects a non-admin to `/`. `backstop`
- `/admin/permissions?tab=audit` shows the Audit panel. `backstop`
- The header menu button hides and shows the sidebar. `backstop`
- The footer has both required text strings and zero `<a>` elements.

### Artifacts

- `frontend/src/_nav.tsx` exports `navigation` and the types below. The old flat four-item array is gone.
- `frontend/src/views/Stub/index.tsx` exports the stub view.
- `frontend/src/store/sidebar.ts` exports `useSidebarStore`.
- `frontend/tests/nav.test.tsx` covers R1, R2, R5, R6, and R7.
- `frontend/src/App.tsx` registers every stub path from briefing.md § Menu.

### Key links

- `AppSidebar` calls `navigation({ clusterId: selectedCluster?.id ?? null, isAdmin: me?.role === 'admin' })` and passes the array to `AppSidebarNav`.
- Cluster Details' `to` is computed inside `navigation`, not hardcoded to `/clusters/1`.
- Each stub route's `title` prop equals that row's Entry column. The route path equals that row's Path column.
- `AdminPermissionsView` initializes `tab` from `useSearchParams()`.

### One-way doors

None.

## File Structure

### Modify

- `frontend/src/_nav.tsx` — replace the flat list with `navigation()`.
- `frontend/src/components/AppSidebar.jsx` — call `navigation`, bind `visible` to the sidebar store. Unfoldable stays local.
- `frontend/src/components/AppHeader.jsx` — menu button calls `useSidebarStore.getState().toggle` via the hook. Delete the unused `sidebarShow` state.
- `frontend/src/components/AppSidebarNav.jsx` — render an item with `divider: true` as a `div.border-top.d-none.d-md-flex` and ignore its name. Existing group and title behavior stays.
- `frontend/src/components/AppFooter.jsx` — two text nodes, no anchors.
- `frontend/src/App.tsx` — import `StubView` and register stub routes before the `*` redirect.
- `frontend/src/views/AdminPermissions/index.tsx` — read `tab` from the query string once, as the initial `useState` value.

### Create

- `frontend/src/views/Stub/index.tsx`
- `frontend/src/store/sidebar.ts`
- `frontend/tests/nav.test.tsx`

`tasks.md` moves Task 3's tests into `frontend/tests/views/Stub.test.tsx`, `frontend/tests/views/admin_permissions.test.tsx`, and `frontend/tests/components/AppFooter.test.tsx` so tickets can run in parallel. The test bodies below are unchanged; only their file changes.

### Not touched

- `frontend/src/views/Clusters`, `Cluster`, `Permissions`, and the admin view's data fetching.
- Backend, Helm, and `_nav` consumers other than `AppSidebar`.

## Types

`navigation` returns `NavItem[]`. `AppSidebarNav` already branches on `item.items` (group) versus a leaf. Titles and links are leaves. Dividers are leaves with `divider: true`.

```ts
import type { ReactNode } from 'react'

export type NavBadge = { color: 'warning'; text: 'Beta' }

export type NavItem = {
  component: React.ElementType
  name: string
  icon?: ReactNode
  badge?: NavBadge
  to?: string
  items?: NavItem[]
  divider?: boolean
  className?: string
}

export function navigation(input: {
  clusterId: number | null
  isAdmin: boolean
}): NavItem[]
```

Icon names, all from `@coreui/icons` (already a dependency):

| Group or item | Icon |
|---|---|
| Dashboard | `cilSpeedometer` |
| Cluster Details | `cilList` |
| My access | `cilShieldAlt` |
| User Management | `cilUser` |
| Cluster Permissions | `cilGroup` |
| Cluster | `cilLayers` |
| Workloads | `cilApplications` |
| Network | `cilLan` |
| Storage | `cilStorage` |
| Security | `cilShieldAlt` |
| Other Resources | `cilNotes` |
| Settings | `cilSettings` |

Wrap each with `<CIcon icon={...} customClassName="nav-icon" />`. These names are exports of `@coreui/icons` in this repo.

## Tasks

### Task 1: Menu contract

**Files:**
- Create: `frontend/tests/nav.test.tsx`
- Modify: `frontend/src/_nav.tsx`
- Test: `frontend/tests/nav.test.tsx`

**Interfaces:**
- Consumes: nothing
- Produces: `navigation({ clusterId, isAdmin })` as typed above. Later tasks import it.

**SATISFIES:** menu-matches-4-1-without-plugins, cluster-details-follows-selection, settings-hidden-for-non-admin

- [ ] **Step 1: Write the failing test**

```tsx
import { describe, expect, test } from 'vitest'
import { navigation, type NavItem } from '../src/_nav'

function flat(items: NavItem[]): { name: string; to?: string }[] {
  return items.flatMap((item) =>
    item.divider ? [] : item.items ? [{ name: item.name }, ...flat(item.items)] : [{ name: item.name, to: item.to }],
  )
}

const adminLabels = [
  'Dashboard', 'Cluster Metrics', 'Workload',
  'Permissions', 'Cluster Details', 'My access',
  'User Management', 'Users', 'Groups',
  'Cluster Permissions', 'ServiceAccounts', 'Roles', 'RoleBindings', 'ClusterRoles', 'ClusterRoleBindings',
  'Interface', 'Cluster', 'Namespaces', 'Nodes', 'CRDs',
  'Workloads', 'Pods', 'Deployments', 'StatefulSets', 'DaemonSets', 'ReplicaSets',
  'Network', 'Services', 'Ingress',
  'Storage', 'ConfigMaps', 'Volumes', 'VolumeClaims', 'VolumeSnapshot', 'StorageClass', 'SnapshotClass',
  'Security', 'Secrets', 'Network Policies', 'Priority Classes',
  'Other Resources', 'HPAs', 'VPAs', 'Pod Disruption Budget', 'Resource Quota', 'Limit Range', 'Runtime Class',
  'Settings', 'Auth Provider', 'Kubernetes Cluster', 'HA Status', 'Audit Log',
]

describe('navigation contract', () => {
  test('admin menu matches 4.1 order with Cluster Details under Permissions', () => {
    const items = navigation({ clusterId: 7, isAdmin: true })
    expect(flat(items).map((e) => e.name)).toEqual(adminLabels)
    const details = flat(items).find((e) => e.name === 'Cluster Details')
    expect(details?.to).toBe('/clusters/7')
    const workload = items[0].items?.find((e) => e.name === 'Workload')
    expect(workload?.badge).toEqual({ color: 'warning', text: 'Beta' })
    expect(workload?.to).toBe('/dashboard/workload-map')
    const joined = adminLabels.join('\n')
    for (const banned of ['Plugins', 'Cert-Manager', 'LoadBalancers', 'Gateway API', 'Trivy Operator', 'Applications']) {
      expect(joined).not.toContain(banned)
    }
  })

  test('no selected cluster points Cluster Details at the registry', () => {
    const items = navigation({ clusterId: null, isAdmin: false })
    const names = flat(items).map((e) => e.name)
    expect(names).not.toContain('Settings')
    expect(names).not.toContain('Audit Log')
    expect(flat(items).find((e) => e.name === 'Cluster Details')?.to).toBe('/clusters')
    expect(flat(items).find((e) => e.name === 'Users')?.to).toBe('/admin/permissions?tab=users')
  })
})
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `pnpm --dir frontend exec vitest run tests/nav.test.tsx`
Expected: FAIL because `navigation` is not exported.

- [ ] **Step 3: Implement `navigation`**

Replace the body of `frontend/src/_nav.tsx`. Build the array in briefing.md § Menu order. Dashboard is a `CNavGroup` with no preceding title. Insert two divider leaves (`component` `'div'`, `divider: true`, `name: ''`, `className: 'border-top d-none d-md-flex'`) after Dashboard and after the Permissions block. Permissions and Interface titles are `{ component: CNavTitle, name: 'Permissions' | 'Interface' }`. Groups are `CNavGroup` with `compact` implied by `AppSidebarNav` (it already passes `compact`). Append the Settings group only when `input.isAdmin` is true.

Path for each leaf is the Path cell in briefing.md § Menu. Cluster Details uses `` input.clusterId == null ? '/clusters' : `/clusters/${input.clusterId}` ``. Users uses `/admin/permissions?tab=users`. Audit Log uses `/admin/permissions?tab=audit`.

Do not add a Plugins group. Do not add Cert-Manager, LoadBalancers, Gateway API, Trivy Operator, or Applications.

- [ ] **Step 4: Re-run the test**

Run: `pnpm --dir frontend exec vitest run tests/nav.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/_nav.tsx frontend/tests/nav.test.tsx
git commit -m "$(cat <<'EOF'
feat(sidebar): define the 4.1 menu contract without plugins

EOF
)"
```

### Task 2: Render the menu and wire the header toggler

**Files:**
- Create: `frontend/src/store/sidebar.ts`
- Modify: `frontend/src/components/AppSidebar.jsx`, `frontend/src/components/AppSidebarNav.jsx`, `frontend/src/components/AppHeader.jsx`, `frontend/tests/nav.test.tsx`
- Test: `frontend/tests/nav.test.tsx`

**Interfaces:**
- Consumes: `navigation` from Task 1. `useClusterStore` (`selectedCluster.id`). `useCluster().me.role`.
- Produces: `useSidebarStore` with `{ visible: boolean; toggle: () => void; setVisible: (visible: boolean) => void }`. Default `visible` is `true`.

**SATISFIES:** sidebar-shows-cluster-details-link, header-toggler-hides-sidebar

- [ ] **Step 1: Extend the failing test**

Add to `frontend/tests/nav.test.tsx`. Mock `useCluster` so the render does not need MSW: `vi.mock('../src/hooks/useCluster', () => ({ useCluster: () => ({ me: { role: 'admin' }, clusters: [] }) }))`. Set the store before render:

```tsx
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { useClusterStore } from '../src/store/cluster'
import AppHeader from '../src/components/AppHeader'
import AppSidebar from '../src/components/AppSidebar'

test('sidebar links Cluster Details at the selected cluster and the header toggles it', async () => {
  useClusterStore.setState({ selectedCluster: { id: 7, name: 'prod' } })
  render(
    <MemoryRouter>
      <AppSidebar />
      <AppHeader />
    </MemoryRouter>,
  )
  const details = await screen.findByRole('link', { name: 'Cluster Details' })
  expect(details.getAttribute('href')).toBe('/clusters/7')
  expect(screen.getByText('Settings')).toBeTruthy()
  const sidebar = document.querySelector('.sidebar')
  expect(sidebar?.className).toContain('show')
  await userEvent.click(screen.getByRole('button', { name: 'Toggle sidebar' }))
  expect(document.querySelector('.sidebar')?.className).not.toContain('show')
})
```

`AppHeader`'s toggler already sets `alt="Toggle sidebar"` on the icon; put `aria-label="Toggle sidebar"` on `CHeaderToggler` so the button role is named.

- [ ] **Step 2: Run and confirm failure**

Run: `pnpm --dir frontend exec vitest run tests/nav.test.tsx`
Expected: FAIL. The link `Cluster Details` is missing, or `href` is `/clusters/1`.

- [ ] **Step 3: Implement**

`frontend/src/store/sidebar.ts`:

```ts
import { create } from 'zustand'

type SidebarStore = {
  visible: boolean
  toggle: () => void
  setVisible: (visible: boolean) => void
}

export const useSidebarStore = create<SidebarStore>()((set) => ({
  visible: true,
  toggle: () => set((s) => ({ visible: !s.visible })),
  setVisible: (visible) => set({ visible }),
}))
```

`AppSidebar.jsx`: remove local `visible` state. `const visible = useSidebarStore((s) => s.visible)` and `const setVisible = useSidebarStore((s) => s.setVisible)`. Keep local `unfoldable`. Call `navigation({ clusterId: useClusterStore((s) => s.selectedCluster?.id ?? null), isAdmin: useCluster().me?.role === 'admin' })` and pass it as `items`.

`AppHeader.jsx`: delete `sidebarShow` / `setSidebarShow`. `onClick` of `CHeaderToggler` calls `useSidebarStore((s) => s.toggle)`. Add `aria-label="Toggle sidebar"`.

`AppSidebarNav.jsx`: at the start of the `items.map` callback, if `item.divider` return `<div key={index} className={item.className ?? 'border-top d-none d-md-flex'} />`.

- [ ] **Step 4: Re-run**

Run: `pnpm --dir frontend exec vitest run tests/nav.test.tsx`
Expected: PASS. Also run `pnpm --dir frontend exec vitest run` and expect the existing view tests still pass.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/store/sidebar.ts frontend/src/components/AppSidebar.jsx frontend/src/components/AppSidebarNav.jsx frontend/src/components/AppHeader.jsx frontend/tests/nav.test.tsx
git commit -m "$(cat <<'EOF'
feat(sidebar): render the 4.1 menu and share the header toggler

EOF
)"
```

### Task 3: Stub routes, admin tab query, footer text

**Files:**
- Create: `frontend/src/views/Stub/index.tsx`
- Modify: `frontend/src/App.tsx`, `frontend/src/views/AdminPermissions/index.tsx`, `frontend/src/components/AppFooter.jsx`, `frontend/tests/nav.test.tsx`
- Test: `frontend/tests/nav.test.tsx`

**Interfaces:**
- Consumes: stub paths and labels from briefing.md § Menu. `AdminRoute` and `ProtectedRoute` from `frontend/src/routes.tsx`.
- Produces: `StubView({ title }: { title: string })`.

**SATISFIES:** stub-page-names-the-entry, settings-url-rejects-non-admin, audit-tab-opens-from-menu, footer-has-no-outbound-link

- [ ] **Step 1: Write the failing tests**

`App` owns a `BrowserRouter`, so these tests do not mount `App`. The stub test renders `StubView` on its route. The audit test mounts `AdminPermissionsView` the same way `frontend/tests/views/admin_permissions.test.tsx` does (`QueryClientProvider`, `MemoryRouter`, MSW). The audit handler is the existing 501 body in that file (`code: 'NOT_IMPLEMENTED'`), which makes `auditQuery.data === null` and the view render `Audit log not available.` The tab button label is `Audit` (`aria-selected` on the `role="tab"` button).

```tsx
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { server } from './msw'
import AppFooter from '../src/components/AppFooter'
import StubView from '../src/views/Stub'
import AdminPermissionsView from '../src/views/AdminPermissions'

test('stub view shows the menu label', () => {
  render(
    <MemoryRouter initialEntries={['/workload/pods']}>
      <Routes>
        <Route path="/workload/pods" element={<StubView title="Pods" />} />
        <Route path="*" element={<p>redirected</p>} />
      </Routes>
    </MemoryRouter>,
  )
  expect(screen.getByRole('heading', { name: 'Pods' })).toBeTruthy()
  expect(screen.getByText('This view is not available yet.')).toBeTruthy()
  expect(screen.queryByText('redirected')).toBeNull()
})

test('footer labels are text', () => {
  const { container } = render(<AppFooter />)
  expect(screen.getByText(/DevOpsTales - KubeDash Copyright/)).toBeTruthy()
  expect(screen.getByText('CoreUI UI Components')).toBeTruthy()
  expect(container.querySelectorAll('a')).toHaveLength(0)
})

test('audit tab opens from the menu query', async () => {
  server.use(
    http.get('*/api/v1/audit', () =>
      HttpResponse.json(
        { error: { code: 'NOT_IMPLEMENTED', message: 'audit read not implemented' } },
        { status: 501 },
      ),
    ),
  )
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/admin/permissions?tab=audit']}>
        <AdminPermissionsView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  const auditTab = await screen.findByRole('tab', { name: 'Audit' })
  expect(auditTab.getAttribute('aria-selected')).toBe('true')
  expect(await screen.findByText('Audit log not available.')).toBeTruthy()
})
```

`apiFetch` treats that 501 body as `r.error`, and the view then sets `auditQuery.data` to `null`, which renders `Audit log not available.` The same status and envelope are already used by `audit501` in `frontend/tests/views/admin_permissions.test.tsx`.

- [ ] **Step 2: Run and confirm failure**

Run: `pnpm --dir frontend exec vitest run tests/nav.test.tsx`
Expected: FAIL because `views/Stub` does not exist, and the footer still contains an anchor.

- [ ] **Step 3: Implement**

`frontend/src/views/Stub/index.tsx`:

```tsx
const StubView = ({ title }: { title: string }) => (
  <div>
    <h1>{title}</h1>
    <p>This view is not available yet.</p>
  </div>
)

export default StubView
```

`App.tsx`: lazy-load is unnecessary for this one component; import it directly. Inside the protected `<Routes>`, before `path="*"`, add a `<Route>` for every stub path in briefing.md § Menu. Element is `<ProtectedRoute><StubView title="<Entry>" /></ProtectedRoute>`. For `/settings/sso-config` and `/settings/cluster-status`, wrap with `<ProtectedRoute><AdminRoute><StubView title="..." /></AdminRoute></ProtectedRoute>`. Do not add routes for view rows (`/clusters`, `/clusters/:id`, `/permissions`, `/admin/permissions`).

`AdminPermissions/index.tsx`:

```tsx
const params = new URLSearchParams(window.location.search)
const initial = params.get('tab')
const [tab, setTab] = useState<'users' | 'templates' | 'audit'>(
  initial === 'templates' || initial === 'audit' ? initial : 'users',
)
```

Use `useSearchParams` from `react-router-dom` instead of `window.location` when the view is under the router, which it is:

```tsx
const [params] = useSearchParams()
const requested = params.get('tab')
const [tab, setTab] = useState<'users' | 'templates' | 'audit'>(
  requested === 'templates' || requested === 'audit' ? requested : 'users',
)
```

`AppFooter.jsx` return:

```jsx
<CFooter fixed={false} className="px-4">
  <div>DevOpsTales - KubeDash Copyright &copy; 2021-2026</div>
  <div className="ms-auto">Powered by CoreUI UI Components</div>
</CFooter>
```

No `<a>` tags.

- [ ] **Step 4: Re-run and air-gap check**

Run: `pnpm --dir frontend exec vitest run`
Expected: PASS, including existing Clusters, Cluster, Permissions, and AdminPermissions tests.

Run: `task fe-check`
Expected: exit 0. The footer change removes the `https://coreui.io/docs/` anchor that would fail the air-gap scan.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/Stub/index.tsx frontend/src/App.tsx frontend/src/views/AdminPermissions/index.tsx frontend/src/components/AppFooter.jsx frontend/tests/nav.test.tsx
git commit -m "$(cat <<'EOF'
feat(sidebar): stub the 4.1 entries that have no view yet

EOF
)"
```

## Execution Order

1. Task 1 — contract (door check).
2. Task 2 — render and toggler. Depends on Task 1.
3. Task 3 — stubs, tab query, footer. Depends on Task 1 for the path list. Independent of Task 2's store, but the same test file overlaps, so run it after Task 2.

## Self-Review

- Spec coverage: R1 Task 1; R2 Task 2; R3 preserved by not replacing those routes (Task 3 step 3); R4 Task 3; R5 Task 3; R6 Task 2; R7 Task 3.
- Must-haves: every briefing row is either a `navigation` leaf (Task 1) or a route (Task 3). Dropped plugin names are asserted absent.
- One-way doors: none.
- Placeholder scan: no TBD. The audit assertion expects the existing string `Audit log not available.` and does not change that copy.
- Owed-decision gate: Cluster Details position, empty-selection target, badge text, shared `/clusters` mapping, footer year `2026`, and the decision not to edit ADR-0022 are named in briefing.md § Menu and § Purpose. No unnamed display value remains.
- Type consistency: `navigation` input is `{ clusterId: number | null; isAdmin: boolean }` in Task 1 and Task 2. `StubView` prop is `title: string` in Task 3. `useSidebarStore` fields match Task 2's interface block.

## Plan Review

READY FOR EXECUTION after the user approves this PROPOSED blueprint. Critic was skipped under the T1 rule. Slicing: 3 tasks, so `skillgrid:slicing` applies once execution is chosen. `acceptance.feature` is written only after that approval.
