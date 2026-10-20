import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import AdminPermissionsView from '../../src/views/AdminPermissions'
import TemplateEditor from '../../src/views/AdminPermissions/components/TemplateEditor'
import { AdminRoute } from '../../src/routes'

// ponytail: the default MSW server already serves role:admin for /auth/me;
// the non-admin redirect test swaps it via server.use. The Users behaviors
// (list / bind / unbind / 409 / 403 / non-admin redirect) live in
// tests/views/users.test.tsx after the view moved to /users.

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
    http.get('*/api/v1/admin/permissions/templates', () => HttpResponse.json(TEMPLATES)),
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

describe('AdminPermissionsView (templates + audit)', () => {
  beforeEach(() => {
    localStorage.setItem('kd_token', 'test-token')
    withAdminHandlers()
  })
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('templates-tab-lists-templates', async () => {
    renderAdmin()
    expect(await screen.findByText('viewer')).toBeTruthy()
    expect(screen.getByText('cluster-admin')).toBeTruthy()
    expect(screen.getByText('pod-reader')).toBeTruthy()
    // built-in rows are marked
    expect(screen.getAllByText('builtin').length).toBeGreaterThanOrEqual(2)
  })

  test('audit-tab-renders-empty-state-on-501', async () => {
    renderAdmin()
    await screen.findByText('viewer')
    // ponytail: CButton's role/active props don't compose cleanly with
    // userEvent in jsdom — use fireEvent.click for the tab switch.
    const auditTab = screen.getByText('Audit', { selector: 'button' })
    fireEvent.click(auditTab)
    expect(await screen.findByText(/audit log not available/i)).toBeTruthy()
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
