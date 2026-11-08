import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import NamespacesView from '../../src/views/Cluster/Namespaces'
import NamespaceDataView from '../../src/views/Cluster/NamespaceData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

const ITEMS = [
  {
    metadata: {
      name: 'team-a',
      creation_timestamp: '2026-10-20T10:00:00Z',
      labels: { team: 'platform' },
      annotations: {
        'kubedash.io/repository': 'https://git.example/team-a',
        'kubedash.io/pipeline': 'javascript:alert(1)',
      },
    },
    status: { phase: 'Active' },
  },
  {
    metadata: { name: 'default', creation_timestamp: '2026-10-19T10:00:00Z' },
    status: { phase: 'Active' },
  },
]

const renderNamespaces = (
  role: 'admin' | 'user',
  extraHandlers: Parameters<typeof server.use>[0][] = [],
) => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: null,
  })
  server.use(
    ...extraHandlers,
    http.get('*/api/v1/auth/me', () =>
      HttpResponse.json({
        sub: `${role}-sub`,
        email: `${role}@example.com`,
        display_name: role,
        groups: [],
        role,
        auth_source: 'oidc',
        kubeconfig_source: null,
        last_login_at: null,
      }),
    ),
    http.get('*/api/v1/clusters', () => HttpResponse.json({ items: [{ id: 1, name: 'prod' }] })),
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json({ items: ITEMS, kind: 'namespaces', cluster: 'prod' }),
    ),
  )
  // ADR-0040: render through ObjectRoute so the click→detail flow is the
  // real one (the ref is the active pointer; the URL never carries identity).
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={['/cluster/namespace']}>
        <Routes>
          <Route
            path="/cluster/namespace"
            element={
              <ObjectRoute
                kind="namespace"
                listRoute="/cluster/namespace"
                list={<NamespacesView />}
                detail={(p) => <NamespaceDataView name={p.name} />}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  document.cookie = 'kd_session=1; path=/'
})

afterEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('renders-the-4.1-columns-and-safe-annotation-links', async () => {
  renderNamespaces('admin')
  expect(await screen.findByText('team-a')).toBeTruthy()
  for (const title of ['Status', 'Namespace', 'Repository', 'Pipeline', 'Created', 'Action']) {
    expect(screen.getByRole('columnheader', { name: title })).toBeTruthy()
  }
  expect(screen.getByRole('link', { name: 'Repository' }).getAttribute('href')).toBe(
    'https://git.example/team-a',
  )
  expect(screen.queryByRole('link', { name: 'Pipeline' })).toBeNull()
})

test('admin-creates-a-namespace-and-refreshes-the-shared-query', async () => {
  const user = userEvent.setup()
  const posted = vi.fn()
  server.use(
    http.post('*/api/v1/clusters/1/resources/namespaces', async ({ request }) => {
      posted(await request.json())
      return HttpResponse.json({ name: 'team-b' }, { status: 201 })
    }),
  )
  renderNamespaces('admin')
  expect(await screen.findByText('team-a')).toBeTruthy()
  await user.click(screen.getByRole('button', { name: /add namespace/i }))
  await user.click(screen.getByLabelText(/^namespace$/i))
  await user.paste('team-b')
  const addButtons = screen.getAllByRole('button', { name: /^add namespace$/i })
  await user.click(addButtons[addButtons.length - 1])
  await waitFor(() => expect(posted).toHaveBeenCalledWith({ name: 'team-b' }))
})

test('admin-confirms-delete-and-clears-the-selected-namespace', async () => {
  const user = userEvent.setup()
  const deleted = vi.fn()
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  useClusterStore.setState({ selectedNamespace: 'team-a' })
  server.use(
    http.delete(
      '*/api/v1/clusters/1/resources/namespaces/team-a',
      () => (deleted(), HttpResponse.json({ name: 'team-a' })),
    ),
  )
  renderNamespaces('admin')
  await user.click(await screen.findByRole('button', { name: /delete team-a/i }))
  await waitFor(() => expect(deleted).toHaveBeenCalled())
  expect(useClusterStore.getState().selectedNamespace).toBeNull()
})

test('non-admin-does-not-see-mutation-controls', async () => {
  renderNamespaces('user')
  expect(await screen.findByText('team-a')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /add namespace/i })).toBeNull()
  expect(screen.queryByRole('button', { name: /delete team-a/i })).toBeNull()
})

test('mutation-error-renders-inline', async () => {
  const user = userEvent.setup()
  server.use(
    http.post('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json(
        { error: { code: 'CLUSTER_ALREADY_EXISTS', message: 'namespace already exists' } },
        { status: 409 },
      ),
    ),
  )
  renderNamespaces('admin')
  expect(await screen.findByText('team-a')).toBeTruthy()
  await user.click(screen.getByRole('button', { name: /add namespace/i }))
  await user.click(screen.getByLabelText(/^namespace$/i))
  await user.paste('team-a')
  const addButtons = screen.getAllByRole('button', { name: /^add namespace$/i })
  await user.click(addButtons[addButtons.length - 1])
  expect(await screen.findByText(/namespace already exists/i)).toBeTruthy()
})

test('list-error-renders-inline', async () => {
  renderNamespaces('user', [
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list denied' } },
        { status: 403 },
      ),
    ),
  ])
  expect(await screen.findByText(/list denied/i, { selector: '.text-danger' })).toBeTruthy()
})

// ADR-0040: the name cell is a button (not a Link) — clicking it opens the
// detail via openObject on the clean list route (R1).
test('namespace-name-click-renders-the-object-detail', async () => {
  const user = userEvent.setup()
  renderNamespaces('user')
  await user.click(await screen.findByRole('button', { name: 'team-a' }))
  // "Namespace Data" appears only in the detail header — the list renders
  // "Namespace List". The created-timestamp cell confirms team-a's row.
  expect(await screen.findByText('Namespace Data')).toBeTruthy()
  expect(screen.getByText('2026-10-20T10:00:00Z')).toBeTruthy()
  // R1: the URL is clean — no query string.
  expect(window.location.search).toBe('')
})

test('empty-list-renders-without-the-table', async () => {
  renderNamespaces('user', [
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json({ items: [], kind: 'namespaces', cluster: 'prod' }),
    ),
  ])
  expect(await screen.findByText('No namespaces found')).toBeTruthy()
  expect(screen.queryByRole('table')).toBeNull()
})
