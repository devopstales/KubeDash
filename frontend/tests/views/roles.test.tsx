import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import RoleView from '../../src/views/ClusterPermission/Role'
import RoleDataView from '../../src/views/ClusterPermission/RoleData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/cluster-permission/role') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/cluster-permission/role"
            element={
              <ObjectRoute
                kind="role"
                listRoute="/cluster-permission/role"
                list={<RoleView />}
                detail={(p) => <RoleDataView name={p.name} namespace={p.namespace ?? ''} />}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Render the data view directly (no ObjectRoute) for view-level state
// assertions; the legacy /data route and the ObjectRoute detail both feed it
// the same props.
const renderDataAt = (name: string, namespace: string, path = '/cluster-permission/role/data') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <RoleDataView name={name} namespace={namespace} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

const editRole = {
  metadata: {
    name: 'edit',
    namespace: 'team-a',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"Role"}',
      owner: 'platform',
    },
  },
  rules: [
    {
      api_groups: ['', 'apps'],
      resource_names: ['web'],
      resources: ['pods', 'deployments'],
      verbs: ['get', 'list'],
    },
  ],
}

test('lists-roles-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'roles',
        cluster: 'prod',
        items: [editRole, { metadata: { name: 'view', namespace: 'team-a' }, rules: [] }],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<RoleView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref and navigates; the URL stays clean (R1).
  const nameButton = await screen.findByRole('button', { name: 'edit' })
  expect(requested).toBe('team-a')
  expect(screen.getByText('Roles List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(window.location.search).toBe('')
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Labels',
    'Annotations',
  ])
  expect(nameButton.closest('tr')?.textContent).not.toContain('/data?name=')
  expect(screen.getByText('app: web')).toBeTruthy()
  expect(screen.getByText('owner: platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByRole('button', { name: 'view' })).toBeTruthy()
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderAt(<RoleView />)

  expect(await screen.findByText('No roles found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on roles' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<RoleView />)

  expect(await screen.findByText(/Error loading roles: RBAC_DENIED: list on roles/)).toBeTruthy()
})

test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [editRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<RoleView />)

  // Clicking the name button opens the detail via openObject; the URL never
  // carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'edit' })
  await user.click(nameButton)

  expect(await screen.findByText('Rule List')).toBeTruthy()
  // R1: the URL stays clean — no identity params.
  expect(window.location.search).toBe('')
  expect(screen.getByText('pods')).toBeTruthy()
})

test('shows-role-rules', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [editRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('edit', 'team-a')

  expect(await screen.findByText('pods')).toBeTruthy()
  expect(screen.getByText('Rule List')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Roles' }).getAttribute('href')).toBe(
    '/cluster-permission/role',
  )
  expect(screen.getByText('edit')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'API Groups',
    'Non Resources',
    'Resources',
    'Verbs',
  ])
  expect(screen.getByText('apps')).toBeTruthy()
  expect(screen.getByText('web')).toBeTruthy()
  expect(screen.getByText('deployments')).toBeTruthy()
  expect(screen.getByText('get')).toBeTruthy()
  expect(screen.getByText('list')).toBeTruthy()
  // R1: the URL stays clean on the data view (identity is props, R8).
  expect(window.location.search).toBe('')
})

test('role-data-requires-a-name', async () => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('', 'team-a')

  expect(await screen.findByText('Error: Role name not provided')).toBeTruthy()
})
