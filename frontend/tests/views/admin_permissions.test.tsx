import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import AdminPermissionsView from '../../src/views/AdminPermissions'
import BindModal from '../../src/views/AdminPermissions/components/BindModal'
import TemplateEditor from '../../src/views/AdminPermissions/components/TemplateEditor'
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
    groups: [],
    role: 'user',
    status: 'active',
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

const renderAdmin = (initialEntry = '/admin/permissions') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/admin/permissions" element={<AdminPermissionsView />} />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

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

  test('users-tab-lists-users-from-the-admin-api', async () => {
    renderAdmin()
    expect(await screen.findByText('Alice')).toBeTruthy()
    expect(screen.getByText('oidc-alice')).toBeTruthy()
    expect(screen.getByText('admin@kubedash.local')).toBeTruthy()
    expect(screen.getByText('local:admin@kubedash.local')).toBeTruthy()
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
    renderAdmin()
    await screen.findByText('Alice')
    await user.click(screen.getByText('u1'))
    const button = await screen.findByRole('button', { name: /unbind/i })
    await user.click(button)
    await waitFor(() => expect(unbindSpy).toHaveBeenCalledWith(
      expect.objectContaining({ user: 'u1', cluster: 'prod', namespace: 'team-a' }),
    ))
  })

  test('user-detail-opens-with-bind-control-and-binding-limitation-note', async () => {
    const user = userEvent.setup()
    renderAdmin()
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
    renderAdmin()
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
    expect(screen.queryByText(/users/i, { selector: '.c-tabs' })).toBeNull()
  })

  // --- SATISFIES the-admin-view-shows-api-errors-as-messages ---

  test('users-tab-403-surfaced-as-text-danger', async () => {
    server.use(
      http.get('*/api/v1/admin/users', () =>
        HttpResponse.json({ error: { code: 'RBAC_DENIED', message: 'admin role required' } }, { status: 403 }),
      ),
    )
    renderAdmin()
    expect(await screen.findByText(/admin role required/i, { selector: '.text-danger' })).toBeTruthy()
  })

  test('templates-tab-lists-templates', async () => {
    const user = userEvent.setup()
    renderAdmin()
    await screen.findByText('Alice')
    const templatesTab = screen.getByText('Templates', { selector: 'button' })
    await user.click(templatesTab)
    expect(await screen.findByText('viewer')).toBeTruthy()
    expect(screen.getByText('cluster-admin')).toBeTruthy()
    expect(screen.getByText('pod-reader')).toBeTruthy()
    // built-in rows are marked
    expect(screen.getAllByText('builtin').length).toBeGreaterThanOrEqual(2)
  })

  test('audit-tab-renders-empty-state-on-501', async () => {
    const user = userEvent.setup()
    renderAdmin()
    await screen.findByText('Alice')
    // ponytail: CButton's role/active props don't compose cleanly with
    // userEvent in jsdom — use fireEvent.click for the tab switch.
    const auditTab = screen.getByText('Audit', { selector: 'button' })
    fireEvent.click(auditTab)
    expect(await screen.findByText(/audit log not available/i)).toBeTruthy()
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
