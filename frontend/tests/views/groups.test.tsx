import { render, screen } from '@testing-library/react'
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

const GROUPS = [
  { group: 'dev', member_count: 2 },
  { group: 'platform', member_count: 1 },
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
    // member counts render in the table
    expect(screen.getByText('2')).toBeTruthy()
    expect(screen.getByText('1')).toBeTruthy()
  })

  test('clicking-a-group-shows-its-members', async () => {
    const user = userEvent.setup()
    renderGroups()
    await screen.findByText('dev')
    await user.click(screen.getByText('dev'))
    expect(await screen.findByText('Members of dev')).toBeTruthy()
    // both u1 and oidc-alice carry the dev group
    expect(screen.getByText('Dev')).toBeTruthy()
    expect(screen.getByText('Alice')).toBeTruthy()
    // clicking again collapses the panel
    await user.click(screen.getByText('dev'))
    expect(screen.queryByText('Members of dev')).toBeNull()
  })

  test('empty-groups-renders-empty-state', async () => {
    server.use(
      http.get('*/api/v1/admin/groups', () => HttpResponse.json([])),
    )
    renderGroups()
    expect(await screen.findByText('No groups.')).toBeTruthy()
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
})
