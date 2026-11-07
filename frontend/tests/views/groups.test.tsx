import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import GroupsView from '../../src/views/Groups'
import { AdminRoute } from '../../src/routes'

// ponytail: the default MSW server already serves role:admin for /auth/me;
// the non-admin redirect test swaps it via server.use.

// Backend GroupOut shape (backend/app/schemas/groups.py) — the list route
// returns the full row, not just {group, member_count}.
const GROUPS = [
  { id: 1, name: 'dev', display_name: 'dev', source: 'oidc', member_count: 2, created_at: '2026-01-01T00:00:00Z' },
  { id: 2, name: 'platform', display_name: 'platform', source: 'oidc', member_count: 1, created_at: '2026-01-02T00:00:00Z' },
]

const USERS = [
  {
    id: 1,
    sub: 'u1',
    email: 'dev@kubedash.local',
    display_name: 'Dev',
    groups: ['dev'],
    role: 'admin',
    status: 'active',
    cluster_count: 1,
    last_login_at: '2026-10-19T08:00:00Z',
  },
  {
    id: 2,
    sub: 'oidc-alice',
    email: 'alice@example.com',
    display_name: 'Alice',
    groups: ['dev', 'platform'],
    role: 'user',
    status: 'active',
    cluster_count: 1,
    last_login_at: '2026-10-18T09:00:00Z',
  },
]

const withGroupsHandlers = () =>
  server.use(
    http.get('*/api/v1/admin/groups', () => HttpResponse.json(GROUPS)),
    http.get('*/api/v1/admin/users', () => HttpResponse.json(USERS)),
  )

const renderGroups = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/groups']}>
        <Routes>
          <Route path="/groups" element={<GroupsView />} />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const renderGroupsGate = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/groups']}>
        <Routes>
          <Route
            path="/groups"
            element={
              <AdminRoute>
                <GroupsView />
              </AdminRoute>
            }
          />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('GroupsView', () => {
  beforeEach(() => {
    localStorage.setItem('kd_token', 'test-token')
    withGroupsHandlers()
  })
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('lists-groups-with-member-counts', async () => {
    renderGroups()
    expect(await screen.findByText('dev')).toBeTruthy()
    expect(screen.getByText('platform')).toBeTruthy()
    // member counts render in the table (scoped to the table — the
    // DataTables pagination control also renders a "1" page button)
    const table = screen.getByRole('table')
    expect(within(table).getByText('2')).toBeTruthy()
    expect(within(table).getByText('1')).toBeTruthy()
  })

  // The row Name cell is a Link to the group's privileges page (the
  // e36cf42d admin-managed-groups rewrite replaced the old inline
  // members panel with the row link + the /user/group/privilege route).
  test('group-name-links-to-its-privileges-page', async () => {
    renderGroups()
    const link = await screen.findByRole('link', { name: 'dev' })
    expect(link.getAttribute('href')).toBe('/user/group/privilege?group=dev')
  })

  test('empty-groups-renders-empty-state', async () => {
    server.use(
      http.get('*/api/v1/admin/groups', () => HttpResponse.json([])),
    )
    renderGroups()
    expect(await screen.findByText(/No groups/)).toBeTruthy()
  })

  test('non-admin-redirected-away-from-groups', async () => {
    server.use(
      http.get('*/api/v1/auth/me', () =>
        HttpResponse.json({
          sub: 'u2',
          email: 'alice@example.com',
          display_name: 'Alice',
          groups: [],
          role: 'user',
        }),
      ),
    )
    renderGroupsGate()
    expect(await screen.findByText('Home page')).toBeTruthy()
  })

  test('create-group-posts-and-refetches', async () => {
    const user = userEvent.setup()
    let posted = false
    server.use(
      http.post('*/api/v1/admin/groups', async ({ request }) => {
        const body = (await request.json()) as { name: string }
        expect(body.name).toBe('sre')
        posted = true
        return HttpResponse.json({ id: 9, name: 'sre', member_count: 0 }, { status: 201 })
      }),
      http.get('*/api/v1/admin/groups', () =>
        HttpResponse.json([
          ...GROUPS,
          { id: 9, name: 'sre', display_name: 'sre', source: 'local', member_count: 0, created_at: '2026-01-03T00:00:00Z' },
        ]),
      ),
    )
    renderGroups()
    await screen.findByText('dev')
    // The create form is a CModal behind the header toggle.
    await user.click(screen.getByRole('button', { name: 'Add Group' }))
    await user.type(screen.getByPlaceholderText('Type the group name'), 'sre')
    // The dialog's submit is the second 'Add Group' button — scope to it.
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Add Group' }))
    expect(posted).toBe(true)
    expect(await screen.findByText('sre')).toBeTruthy()
  })

  test('create-group-duplicate-409-surfaces-error', async () => {
    const user = userEvent.setup()
    server.use(
      http.post('*/api/v1/admin/groups', () =>
        HttpResponse.json(
          { error: { code: 'CLUSTER_ALREADY_EXISTS', message: "group 'dev' already exists" } },
          { status: 409 },
        ),
      ),
    )
    renderGroups()
    await screen.findByText('dev')
    await user.click(screen.getByRole('button', { name: 'Add Group' }))
    await user.type(screen.getByPlaceholderText('Type the group name'), 'dev')
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Add Group' }))
    expect(await screen.findByText(/CLUSTER_ALREADY_EXISTS/)).toBeTruthy()
  })
})
