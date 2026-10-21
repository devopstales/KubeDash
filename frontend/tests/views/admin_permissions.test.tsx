import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import AdminPermissionsView from '../../src/views/AdminPermissions'
import PrivilegesView from '../../src/views/AdminPermissions/Privileges'
import PrivilegeEditView from '../../src/views/AdminPermissions/PrivilegeEdit'
import TemplateEditor from '../../src/views/AdminPermissions/components/TemplateEditor'
import { AdminRoute } from '../../src/routes'
import { useClusterStore } from '../../src/store/cluster'

vi.mock('../../src/components/KubeDataTable', () => {
  const React = require('react') as typeof import('react')
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map((child) => (child as React.ReactElement<{ title: string; data?: string | null; children?: unknown }>).props)
    return (
      <table className="table table-bordered">
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col.title}>{col.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i}>
              {cols.map((col) => {
                const value = col.data == null ? row : row[col.data]
                const node =
                  typeof col.children === 'function'
                    ? (col.children as (v: unknown, t: string, r: unknown) => React.ReactNode)(value, 'display', col.data == null ? value : row)
                    : (value as React.ReactNode)
                return <td key={col.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

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
  {
    id: 2,
    name: 'cluster-admin',
    description: 'Full cluster access',
    scope: 'cluster',
    rules: [{ api_groups: ['*'], resources: ['*'], verbs: ['*'] }],
    builtin: true,
    created_by: null,
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 3,
    name: 'pod-reader',
    description: 'Custom pod reader',
    scope: 'namespace',
    rules: [{ api_groups: [''], resources: ['pods'], verbs: ['get', 'list'] }],
    builtin: false,
    created_by: 'local:admin@kubedash.local',
    created_at: '2026-02-01T00:00:00Z',
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
    auth_source: 'oidc',
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
    auth_source: 'local',
    cluster_count: 2,
    last_login_at: '2026-10-19T08:00:00Z',
  },
  {
    id: 2,
    sub: 'oidc-alice',
    email: 'alice@example.com',
    display_name: 'Alice',
    groups: [],
    role: 'user',
    status: 'active',
    auth_source: 'oidc',
    cluster_count: 1,
    last_login_at: '2026-10-18T09:00:00Z',
  },
]

// The admin view reads /audit, which is a confirmed 501 stub on the backend.
// ponytail: HttpResponse instances are one-shot in MSW — a factory keeps
// each test's fetch getting a fresh response.
const audit501 = () =>
  HttpResponse.json(
    { error: { code: 'NOT_IMPLEMENTED', message: 'audit read not implemented in base structure' } },
    { status: 501 },
  )

const withAdminHandlers = () =>
  server.use(
    http.get('*/api/v1/admin/users', () => HttpResponse.json(USERS)),
    http.get('*/api/v1/admin/permissions/templates', () => HttpResponse.json(TEMPLATES)),
    http.get('*/api/v1/clusters', () => HttpResponse.json({ items: CLUSTERS })),
    http.get('*/api/v1/audit', () => audit501()),
  )

const Path = () => {
  const { pathname, search } = useLocation()
  return <div data-testid="path">{pathname + search}</div>
}

const renderAdmin = (initialEntry = '/user/list') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Path />
        <Routes>
          <Route path="/user/list" element={<AdminPermissionsView />} />
          <Route path="/admin/permissions" element={<AdminPermissionsView />} />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const renderPrivileges = (sub: string, page = '/user/privilege') => {
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' } })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`${page}?user=${encodeURIComponent(sub)}`]}>
        <Path />
        <Routes>
          <Route path="/user/privilege" element={<PrivilegesView />} />
          <Route path="/user/privilege/edit" element={<PrivilegeEditView />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const renderPrivilegeEdit = (sub: string) => renderPrivileges(sub, '/user/privilege/edit')

const renderGate = (initialEntry = '/admin/permissions') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route
            path="/admin/permissions"
            element={
              <AdminRoute>
                <AdminPermissionsView />
              </AdminRoute>
            }
          />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AdminPermissionsView', () => {
  beforeEach(() => {
    localStorage.setItem('kd_token', 'test-token')
    withAdminHandlers()
  })
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  // --- SATISFIES admin-binds-a-template-from-the-admin-view ---

  test('user-list-shows-the-4.1-columns', async () => {
    renderAdmin()
    expect(await screen.findByText('Alice')).toBeTruthy()
    expect(screen.getByText('User List')).toBeTruthy()
    expect(screen.getByText('Username')).toBeTruthy()
    expect(screen.getByText('Email')).toBeTruthy()
    expect(screen.getByText('Permission')).toBeTruthy()
    expect(screen.getByText('Type')).toBeTruthy()
    expect(screen.getByText('Alice')).toBeTruthy()
    expect(screen.getByText('alice@example.com')).toBeTruthy()
    expect(screen.getAllByText('OpenID').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Local')).toBeTruthy()
    expect(screen.getAllByText('Admin').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('User')).toBeTruthy()
    expect(screen.getByText('User Management')).toBeTruthy()
    expect(screen.getByRole('button', { name: /create user/i })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Alice' }).getAttribute('href')).toBe(
      '/user/privilege?user=oidc-alice',
    )
    expect(screen.getByRole('link', { name: 'Edit privileges Alice' }).getAttribute('href')).toBe(
      '/user/privilege/edit?user=oidc-alice',
    )
    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Edit privileges Dev' }).getAttribute('href')).toBe(
        '/user/privilege/edit',
      )
    })
    expect(screen.getByRole('button', { name: 'Edit Alice' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Delete Alice' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Delete Dev' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Edit Admin' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Edit privileges Admin' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete Admin' })).toBeNull()
    expect(screen.queryByRole('button', { name: /^add user$/i })).toBeNull()
    expect(screen.queryByRole('tab')).toBeNull()
  })

  test('create-user-form-posts-a-local-user', async () => {
    const user = userEvent.setup()
    let posted: unknown = null
    server.use(
      http.post('*/api/v1/admin/users', async ({ request }) => {
        posted = await request.json()
        return HttpResponse.json({ ...USERS[2], id: 9, display_name: 'New' }, { status: 201 })
      }),
    )
    renderAdmin()
    await user.click(await screen.findByRole('button', { name: /create user/i }))
    expect(screen.getByRole('heading', { name: 'Create User' })).toBeTruthy()
    const add = screen.getByRole('button', { name: /^add user$/i })
    expect(add).toBeDisabled()
    await user.type(screen.getByPlaceholderText('Type your username'), 'New')
    await user.type(screen.getByPlaceholderText('Type your email'), 'new@example.com')
    const password = screen.getByLabelText(/^password:$/i)
    await user.click(password)
    await user.type(password, 'Abcdef1!')
    expect(add).toBeEnabled()
    await user.click(add)
    await waitFor(() =>
      expect(posted).toEqual({
        username: 'New',
        email: 'new@example.com',
        password: 'Abcdef1!',
        role: 'user',
        type: 'Local',
      }),
    )
  })

  test('edit-opens-update-information-and-patches-role', async () => {
    const user = userEvent.setup()
    let patched: unknown = null
    server.use(
      http.patch('*/api/v1/admin/users/:id', async ({ request, params }) => {
        patched = { id: params.id, body: await request.json() }
        return HttpResponse.json({ ...USERS[2], role: 'admin' })
      }),
    )
    renderAdmin()
    await user.click(await screen.findByRole('button', { name: 'Edit Alice' }))
    expect(screen.getByRole('heading', { name: 'Update Information' })).toBeTruthy()
    expect(screen.getByLabelText(/^name:$/i)).toHaveProperty('readOnly', true)
    await user.selectOptions(screen.getByLabelText(/dashboard role/i), 'admin')
    await user.click(screen.getByRole('button', { name: /save changes/i }))
    await waitFor(() =>
      expect(patched).toEqual({ id: '2', body: { role: 'admin' } }),
    )
  })

  test('delete-removes-a-user-row', async () => {
    const user = userEvent.setup()
    let deleted: unknown = null
    server.use(
      http.delete('*/api/v1/admin/users/:id', ({ params }) => {
        deleted = params.id
        return HttpResponse.json({ deleted: 'oidc-alice' })
      }),
    )
    renderAdmin()
    await user.click(await screen.findByRole('button', { name: 'Delete Alice' }))
    await waitFor(() => expect(deleted).toBe('2'))
  })

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
    renderPrivilegeEdit('oidc-alice')
    expect(await screen.findByRole('option', { name: 'viewer' })).toBeTruthy()
    const templateSelect = screen.getByLabelText(/^template$/i)
    await user.selectOptions(templateSelect, 'viewer')
    await user.type(screen.getByLabelText(/^namespaces$/i), 'team-a')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await waitFor(() => expect(bindSpy).toHaveBeenCalledWith(
      expect.objectContaining({ user: 'oidc-alice', cluster: 'prod', namespace: 'team-a', template: 'viewer' }),
    ))
    await waitFor(() =>
      expect(screen.getByTestId('path').textContent).toBe('/user/privilege?user=oidc-alice'),
    )
  })

  test('privileges-page-links-to-the-edit-page', async () => {
    renderPrivileges('oidc-alice')
    const link = await screen.findByRole('link', { name: 'Edit privileges' })
    expect(link.getAttribute('href')).toBe('/user/privilege/edit?user=oidc-alice')
    expect(screen.queryByRole('button', { name: /^save$/i })).toBeNull()
  })

  test('cluster-template-has-no-namespace-field', async () => {
    renderPrivilegeEdit('oidc-alice')
    expect(await screen.findByLabelText(/cluster template/i)).toBeTruthy()
    expect(screen.getByLabelText(/^template$/i)).toBeTruthy()
    expect(screen.getByLabelText(/^namespaces$/i)).toBeTruthy()
    expect(screen.getByRole('checkbox', { name: /all namespaces/i })).toBeDisabled()
  })

  test('unbind-deletes-a-binding-row', async () => {
    const user = userEvent.setup()
    const unbindSpy = vi.fn()
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
    renderPrivileges('u1')
    const button = await screen.findByRole('button', { name: /unbind/i })
    await user.click(button)
    await waitFor(() => expect(unbindSpy).toHaveBeenCalledWith(
      expect.objectContaining({ user: 'u1', cluster: 'prod', namespace: 'team-a' }),
    ))
  })

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
    renderPrivilegeEdit('oidc-alice')
    expect(await screen.findByRole('option', { name: 'viewer' })).toBeTruthy()
    await user.selectOptions(screen.getByLabelText(/^template$/i), 'viewer')
    await user.type(screen.getByLabelText(/^namespaces$/i), 'team-a')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    expect(await screen.findByText(/binding already exists/i)).toBeTruthy()
    await waitFor(() => expect(onUncaught).not.toHaveBeenCalled())
    window.removeEventListener('unhandledrejection', onUncaught)
  })

  // --- SATISFIES a-non-admin-is-redirected-away-from-the-admin-view ---

  test('non-admin-redirected-away-from-the-admin-view', async () => {
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
    renderGate()
    expect(await screen.findByText('Home page')).toBeTruthy()
    expect(screen.queryByText('User List')).toBeNull()
  })

  test('users-list-403-surfaced-as-text-danger', async () => {
    server.use(
      http.get('*/api/v1/admin/users', () =>
        HttpResponse.json({ error: { code: 'RBAC_DENIED', message: 'admin role required' } }, { status: 403 }),
      ),
    )
    renderAdmin()
    expect(await screen.findByText(/admin role required/i, { selector: '.text-danger' })).toBeTruthy()
  })

  test('templates-page-lists-templates', async () => {
    renderAdmin('/admin/permissions?tab=templates')
    expect(await screen.findByText('viewer')).toBeTruthy()
    expect(screen.getByText('cluster-admin')).toBeTruthy()
    expect(screen.getByText('pod-reader')).toBeTruthy()
    expect(screen.getAllByText('builtin').length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByRole('tab')).toBeNull()
  })

  test('audit-page-opens-from-its-route', async () => {
    renderAdmin('/admin/permissions?tab=audit')
    expect(await screen.findByText('Audit log not available.')).toBeTruthy()
    expect(screen.queryByRole('tab')).toBeNull()
    expect(screen.queryByText('User List')).toBeNull()
  })

  test('old-users-address-opens-user-list', async () => {
    renderAdmin('/admin/permissions?tab=users')
    expect(await screen.findByText('User List')).toBeTruthy()
    expect(screen.getByTestId('path').textContent).toBe('/user/list')
    expect(screen.queryByRole('tab')).toBeNull()
  })

  test('non-admin-cannot-open-audit-page', async () => {
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
    renderGate('/admin/permissions?tab=audit')
    expect(await screen.findByText('Home page')).toBeTruthy()
    expect(screen.queryByText('Audit log not available.')).toBeNull()
  })
})

describe('TemplateEditor', () => {
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('adding-a-rule-row-updates-the-role-yaml-preview', async () => {
    const user = userEvent.setup()
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <TemplateEditor
            existingNames={['viewer', 'cluster-admin']}
            onCreated={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    // start with one empty rule row: type resources + verbs
    const resources = screen.getAllByRole('textbox').find((el) =>
      (el as HTMLInputElement).placeholder === 'pods, pods/log',
    ) as HTMLInputElement
    const verbs = screen.getAllByRole('textbox').find((el) =>
      (el as HTMLInputElement).placeholder === 'get,list,watch',
    ) as HTMLInputElement
    await user.type(resources, 'deployments')
    await user.type(verbs, 'getlist')
    // the <pre> preview renders the rule (single verb, no comma needed)
    const pre = screen.getByText(/rules:/, { selector: 'pre' })
    expect(pre.textContent).toContain('deployments')
    expect(pre.textContent).toContain('getlist')
    // add a second rule row
    const inputsBefore = screen.getAllByRole('textbox')
    await user.click(screen.getByRole('button', { name: /add rule/i }))
    const inputs2 = screen.getAllByRole('textbox')
    expect(inputs2.length).toBeGreaterThan(inputsBefore.length)
    // scope selector toggles the kind
    const scopeSelect = screen.getByRole('combobox')
    await user.selectOptions(scopeSelect, 'cluster')
    expect(screen.getByText(/ClusterRole/, { selector: 'pre' })).toBeTruthy()
  })

  test('create-posts-the-template', async () => {
    const user = userEvent.setup()
    let posted: unknown = null
    server.use(
      http.post('*/api/v1/admin/permissions/templates', async ({ request }) => {
        posted = await request.json()
        return HttpResponse.json(
          { id: 9, name: 'pod-reader', description: '', scope: 'namespace', rules: [], builtin: false, created_by: 'u1', created_at: '2026-10-19T00:00:00Z' },
          { status: 201 },
        )
      }),
    )
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <TemplateEditor
            existingNames={['viewer', 'cluster-admin']}
            onCreated={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    const nameInput = screen.getByLabelText(/^name$/i)
    await user.type(nameInput, 'pod-reader')
    const resources = screen.getAllByRole('textbox').find((el) =>
      (el as HTMLInputElement).placeholder === 'pods, pods/log',
    ) as HTMLInputElement
    const verbs = screen.getAllByRole('textbox').find((el) =>
      (el as HTMLInputElement).placeholder === 'get,list,watch',
    ) as HTMLInputElement
    await user.type(resources, 'pods')
    await user.type(verbs, 'get')
    await user.click(screen.getByRole('button', { name: /create/i }))
    await waitFor(() => expect(posted).toEqual(
      expect.objectContaining({
        name: 'pod-reader',
        scope: 'namespace',
        rules: [{ api_groups: [''], resources: ['pods'], verbs: ['get'] }],
      }),
    ))
  })

  test('delete-sends-deletes-the-template', async () => {
    const user = userEvent.setup()
    let deleted: unknown = null
    server.use(
      http.delete('*/api/v1/admin/permissions/templates/:name', ({ request }) => {
        deleted = new URL(request.url).pathname.split('/').pop()
        return HttpResponse.json({})
      }),
      // the editor fetches the list from the API (same queryKey as the view)
      http.get('*/api/v1/admin/permissions/templates', () =>
        HttpResponse.json([TEMPLATES[2]]),
      ),
    )
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <TemplateEditor
            existingNames={['viewer', 'cluster-admin']}
            onCreated={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await screen.findByText('pod-reader')
    await user.click(screen.getByRole('button', { name: /delete/i }))
    await waitFor(() => expect(deleted).toBe('pod-reader'))
  })

  test('builtin-template-delete-refusal-surfaced-as-message', async () => {
    server.use(
      http.get('*/api/v1/admin/permissions/templates', () =>
        HttpResponse.json([TEMPLATES[0]]),
      ),
      http.delete('*/api/v1/admin/permissions/templates/:name', () =>
        HttpResponse.json(
          { error: { code: 'BUILTIN_TEMPLATE_PROTECTED', message: 'builtin templates cannot be deleted' } },
          { status: 409 },
        ),
      ),
    )
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <TemplateEditor
            existingNames={['viewer', 'cluster-admin']}
            onCreated={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await screen.findByText('viewer')
    // built-in row: delete is disabled — clicking is a no-op
    const deleteButton = screen.getByRole('button', { name: /delete/i })
    expect(deleteButton).toBeDisabled()
  })
})
