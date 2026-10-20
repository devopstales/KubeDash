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
  },
]

const withUsersHandlers = () =>
  server.use(
    http.get('*/api/v1/admin/users', () => HttpResponse.json(USERS)),
    http.get('*/api/v1/admin/permissions/templates', () => HttpResponse.json(TEMPLATES)),
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

describe('UsersView', () => {
  beforeEach(() => {
    localStorage.setItem('kd_token', 'test-token')
    withUsersHandlers()
  })
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('lists-users-from-the-admin-api', async () => {
    renderUsers()
    expect(await screen.findByText('Alice')).toBeTruthy()
    expect(screen.getByText('oidc-alice')).toBeTruthy()
    expect(screen.getByText('admin@kubedash.local')).toBeTruthy()
    expect(screen.getByText('local:admin@kubedash.local')).toBeTruthy()
  })

  // --- SATISFIES admin-binds-a-template-from-the-admin-view ---

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

  test('namespace-field-hides-for-cluster-scoped-templates', async () => {
    const user = userEvent.setup()
    const clusterScoped: import('../../src/lib/types').RBACTemplate = {
      ...TEMPLATES[0],
      id: 2,
      name: 'cluster-admin',
      scope: 'cluster',
    }
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <BindModal
            user="oidc-alice"
            clusters={CLUSTERS}
            templates={[TEMPLATES[0], clusterScoped]}
            onClose={() => {}}
            onSuccess={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    const [clusterSelect, templateSelect] = screen.getAllByRole('combobox')
    await user.selectOptions(clusterSelect, 'prod')
    // namespace-scoped: the field is present
    expect(screen.getByLabelText(/namespace/i)).toBeTruthy()
    await user.selectOptions(templateSelect, 'cluster-admin')
    // cluster-scoped: hidden
    expect(screen.queryByLabelText(/namespace/i)).toBeNull()
  })

  test('unbind-deletes-a-binding-row', async () => {
    const user = userEvent.setup()
    const unbindSpy = vi.fn()
    // my-access is the CALLER's (u1 per the default /auth/me handler) — the
    // view only lists the caller's rows, so the test clicks the caller row.
    server.use(
      http.get('*/api/v1/permissions/my-access', () =>
        HttpResponse.json([
          { cluster: 'prod', namespace: 'team-a', template: 'viewer', created_at: '2026-10-19T00:00:00Z' },
        ]),
      ),
      http.delete('*/api/v1/admin/permissions/bind', async ({ request }) => {
        unbindSpy(await request.json())
        return HttpResponse.json({})
      }),
    )
    renderUsers()
    await screen.findByText('Dev')
    await user.click(screen.getByText('u1'))
    const button = await screen.findByRole('button', { name: /unbind/i })
    await user.click(button)
    await waitFor(() => expect(unbindSpy).toHaveBeenCalledWith(
      expect.objectContaining({ user: 'u1', cluster: 'prod', namespace: 'team-a' }),
    ))
  })

  test('user-detail-opens-with-bind-control-and-binding-limitation-note', async () => {
    const user = userEvent.setup()
    renderUsers()
    await screen.findByText('Alice')
    await user.click(screen.getByText('Alice'))
    expect(await screen.findByText(/per-user binding listing is not available/i)).toBeTruthy()
    expect(screen.getByRole('button', { name: /^bind$/i })).toBeTruthy()
  })

  // --- SATISFIES the-admin-view-shows-api-errors-as-messages ---

  test('bind-409-surfaced-as-message-without-unhandled-rejection', async () => {
    const user = userEvent.setup()
    const onUncaught = vi.fn()
    window.addEventListener('unhandledrejection', onUncaught)
    server.use(
      http.post('*/api/v1/admin/permissions/bind', () =>
        HttpResponse.json(
          { error: { code: 'CLUSTER_ALREADY_EXISTS', message: 'binding already exists' } },
          { status: 409 },
        ),
      ),
    )
    renderUsers()
    await screen.findByText('Alice')
    await user.click(screen.getByText('Alice'))
    await user.click(screen.getByRole('button', { name: /^bind$/i }))
    const [clusterSelect, templateSelect] = await screen.findAllByRole('combobox')
    await user.selectOptions(clusterSelect, 'prod')
    await user.selectOptions(templateSelect, 'viewer')
    await user.type(screen.getByLabelText(/namespace/i), 'team-a')
    await user.click(screen.getByRole('button', { name: /submit/i }))
    expect(await screen.findByText(/binding already exists/i)).toBeTruthy()
    await waitFor(() => expect(onUncaught).not.toHaveBeenCalled())
    window.removeEventListener('unhandledrejection', onUncaught)
  })

  // --- SATISFIES a-non-admin-is-redirected-away-from-the-admin-view ---

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
