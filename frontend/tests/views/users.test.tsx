import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import UsersView from '../../src/views/Users'
import BindModal from '../../src/views/AdminPermissions/components/BindModal'
import { AdminRoute } from '../../src/routes'

// ponytail: the default MSW server already serves role:admin for /auth/me;
// the non-admin redirect test swaps it via server.use.

const CLUSTERS = [
  { id: 1, name: 'prod', api_server: 'https://api.prod', context: 'kubedash-prod', status: 'ok', source: 'registry' },
  { id: 2, name: 'staging', api_server: 'https://api.stg', context: 'kubedash-staging', status: 'ok', source: 'registry' },
]

const TEMPLATES: import('../../src/lib/types').RBACTemplate[] = [
  {
    id: 1,
    name: 'viewer',
    description: 'Read-only',
    scope: 'namespace',
    rules: [{ api_groups: ['*'], resources: ['*'], verbs: ['get', 'list', 'watch'] }],
    builtin: true,
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
  },
]

const GROUPS = [
  { group: 'dev', member_count: 1 },
  { group: 'platform', member_count: 0 },
]

const USERS = [
  {
    id: 1,
    sub: 'u1',
    email: 'dev@kubedash.local',
    display_name: 'Dev',
    groups: [],
    role: 'admin',
    status: 'active',
    cluster_count: 1,
    last_login_at: '2026-10-19T08:00:00Z',
    user_type: 'OIDC',
  },
  {
    id: 0,
    sub: 'local:admin@kubedash.local',
    email: 'admin@kubedash.local',
    display_name: 'Admin',
    groups: [],
    role: 'admin',
    status: 'active',
    cluster_count: 2,
    last_login_at: '2026-10-19T08:00:00Z',
    user_type: 'Local',
  },
  {
    id: 2,
    sub: 'oidc-alice',
    email: 'alice@example.com',
    display_name: 'Alice',
    groups: ['dev'],
    role: 'user',
    status: 'active',
    cluster_count: 1,
    last_login_at: '2026-10-18T09:00:00Z',
    user_type: 'OIDC',
  },
]

const withUsersHandlers = () =>
  server.use(
    http.get('*/api/v1/admin/users', () => HttpResponse.json(USERS)),
    http.get('*/api/v1/admin/permissions/templates', () => HttpResponse.json(TEMPLATES)),
    http.get('*/api/v1/admin/groups', () => HttpResponse.json(GROUPS)),
    http.get('*/api/v1/clusters', () => HttpResponse.json({ items: CLUSTERS })),
  )

const renderUsers = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/users']}>
        <Routes>
          <Route path="/users" element={<UsersView />} />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const renderUsersGate = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/users']}>
        <Routes>
          <Route
            path="/users"
            element={
              <AdminRoute>
                <UsersView />
              </AdminRoute>
            }
          />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('UsersView (main-branch layout + DataTables)', () => {
  beforeEach(() => {
    localStorage.setItem('kd_token', 'test-token')
    withUsersHandlers()
  })
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('lists-users-with-type-column', async () => {
    renderUsers()
    // All three users render (DataTables shows them client-side).
    expect(await screen.findByText('Alice')).toBeTruthy()
    expect(screen.getByText('Dev')).toBeTruthy()
    expect(screen.getByText('Admin')).toBeTruthy()
    // The Type column shows Local for the bootstrap admin, OIDC for SSO.
    expect(screen.getByText('Local')).toBeTruthy()
    expect(screen.getByText('OIDC')).toBeTruthy()
    // The User List card header + breadcrumb are present.
    expect(screen.getByText('User List')).toBeTruthy()
    expect(screen.getByText('User Management')).toBeTruthy()
  })

  test('show-groups-badges', async () => {
    renderUsers()
    await screen.findByText('Alice')
    // Alice's 'dev' group renders as a badge in her row.
    expect(screen.getByText('dev')).toBeTruthy()
  })

  test('search-filters-rows', async () => {
    const user = userEvent.setup()
    renderUsers()
    await screen.findByText('Alice')
    // The DataTables search box is present (aria-label "Search").
    const search = screen.getByLabelText(/search/i)
    await user.type(search, 'alice')
    await waitFor(() => expect(screen.queryByText('Dev')).toBeNull())
    expect(screen.getByText('Alice')).toBeTruthy()
  })

  test('create-user-posts-and-closes', async () => {
    const user = userEvent.setup()
    const createSpy = vi.fn()
    server.use(
      http.post('*/api/v1/admin/users', async ({ request }) => {
        createSpy(await request.json())
        return HttpResponse.json({ sub: 'local:jdoe@e', user_type: 'Local' }, { status: 201 })
      }),
    )
    renderUsers()
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '+ Add User' }))
    await user.type(screen.getByLabelText('Create username'), 'jdoe')
    await user.type(screen.getByLabelText('Create email'), 'jdoe@e')
    await user.type(screen.getByLabelText('Create password'), 's3cret')
    await user.click(screen.getByRole('button', { name: 'Add User' }))
    await waitFor(() =>
      expect(createSpy).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'jdoe', email: 'jdoe@e', password: 's3cret', role: 'user' }),
      ),
    )
  })

  test('delete-user-calls-delete-and-hides-for-bootstrap', async () => {
    const user = userEvent.setup()
    const deleteSpy = vi.fn()
    server.use(
      http.delete('*/api/v1/admin/users/2', () => {
        deleteSpy()
        return HttpResponse.json({ sub: 'oidc-alice', deleted: true })
      }),
    )
    renderUsers()
    await screen.findByText('Alice')
    // The bootstrap admin row has NO delete button (hidden for local: subs).
    const adminRowDelete = screen.queryAllByRole('button', { name: 'Delete local:admin@kubedash.local' })
    expect(adminRowDelete.length).toBe(0)
    // Alice (non-bootstrap) has a delete button; clicking it fires DELETE.
    await user.click(screen.getByRole('button', { name: 'Delete oidc-alice' }))
    await waitFor(() => expect(deleteSpy).toHaveBeenCalled())
  })

  test('edit-user-patches-role-status', async () => {
    const user = userEvent.setup()
    const patchSpy = vi.fn()
    server.use(
      http.patch('*/api/v1/admin/users/2', async ({ request }) => {
        patchSpy(await request.json())
        return HttpResponse.json(USERS[2])
      }),
    )
    renderUsers()
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: 'Edit oidc-alice' }))
    // Edit controls appear in the user detail panel.
    const roleSelect = await screen.findByLabelText('Edit role')
    await user.selectOptions(roleSelect, 'admin')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(patchSpy).toHaveBeenCalledWith(expect.objectContaining({ role: 'admin' })),
    )
  })

  // --- existing behaviors (BindModal + redirect + 403) ---------------------

  test('bind-submits-user-cluster-namespace-template', async () => {
    const user = userEvent.setup()
    const bindSpy = vi.fn()
    server.use(
      http.post('*/api/v1/admin/permissions/bind', async ({ request }) => {
        bindSpy(await request.json())
        return HttpResponse.json({
          cluster: 'prod',
          namespace: 'team-a',
          template: 'viewer',
          created_at: '2026-10-19T00:00:00Z',
        })
      }),
    )
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <BindModal
            user="oidc-alice"
            clusters={CLUSTERS}
            templates={TEMPLATES}
            onClose={() => {}}
            onSuccess={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    const [clusterSelect, templateSelect] = screen.getAllByRole('combobox')
    await user.selectOptions(clusterSelect, 'prod')
    await user.selectOptions(templateSelect, 'viewer')
    await user.type(screen.getByLabelText(/namespace/i), 'team-a')
    await user.click(screen.getByRole('button', { name: /submit/i }))
    await waitFor(() => expect(bindSpy).toHaveBeenCalledWith(
      expect.objectContaining({ user: 'oidc-alice', cluster: 'prod', namespace: 'team-a', template: 'viewer' }),
    ))
  })

  test('user-detail-opens-with-groups-and-bind', async () => {
    const user = userEvent.setup()
    renderUsers()
    await screen.findByText('Alice')
    await user.click(screen.getByText('Alice'))
    expect(await screen.findByText(/per-user binding listing is not available/i)).toBeTruthy()
    expect(screen.getByRole('button', { name: /^bind$/i })).toBeTruthy()
  })

  test('non-admin-redirected-away-from-users', async () => {
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
    renderUsersGate()
    expect(await screen.findByText('Home page')).toBeTruthy()
  })

  test('users-403-surfaced-as-text-danger', async () => {
    server.use(
      http.get('*/api/v1/admin/users', () =>
        HttpResponse.json({ error: { code: 'RBAC_DENIED', message: 'admin role required' } }, { status: 403 }),
      ),
    )
    renderUsers()
    expect(await screen.findByText(/admin role required/i, { selector: '.text-danger' })).toBeTruthy()
  })
})
