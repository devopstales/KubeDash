import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ClusterRoleView from '../../src/views/ClusterPermission/ClusterRole'
import ClusterRoleDataView from '../../src/views/ClusterPermission/ClusterRoleData'
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
const renderAt = (_ui: ReactElement, path = '/cluster-permission/cluster-role') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/cluster-permission/cluster-role"
            element={
              <ObjectRoute
                kind="clusterrole"
                listRoute="/cluster-permission/cluster-role"
                list={<ClusterRoleView />}
                detail={(p) => <ClusterRoleDataView name={p.name} />}
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
const renderDataAt = (name: string, path = '/cluster-permission/cluster-role/data') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <ClusterRoleDataView name={name} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

const editClusterRole = {
  metadata: {
    name: 'edit',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"ClusterRole"}',
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

test('lists-cluster-roles-for-selected-cluster', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', ({ request }) => {
      requested = new URL(request.url).search
      return HttpResponse.json({
        kind: 'clusterroles',
        cluster: 'prod',
        items: [editClusterRole, { metadata: { name: 'view' }, rules: [] }],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref and navigates; the URL stays clean (R1).
  const nameButton = await screen.findByRole('button', { name: 'edit' })
  expect(requested).toBe('')
  expect(screen.getByText('Cluster Role List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getByText('Cluster Role')).toBeTruthy()
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

test('shows-empty-cluster-role-list', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  expect(await screen.findByText('No cluster roles found')).toBeTruthy()
})

test('shows-cluster-role-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on clusterroles' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  expect(
    await screen.findByText(/Error loading cluster roles: RBAC_DENIED: list on clusterroles/),
  ).toBeTruthy()
})

test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [editClusterRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  // Clicking the name button opens the detail via openObject; the URL never
  // carries identity (R1). Cluster-scoped: no namespace anywhere.
  const nameButton = await screen.findByRole('button', { name: 'edit' })
  await user.click(nameButton)

  expect(await screen.findByText('Rule List')).toBeTruthy()
  // R1: the URL stays clean — no identity params.
  expect(window.location.search).toBe('')
  expect(screen.getByText('pods')).toBeTruthy()
})

test('shows-cluster-role-rules', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [editClusterRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('edit')

  expect(await screen.findByText('pods')).toBeTruthy()
  expect(screen.getByText('Rule List')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Cluster Role' }).getAttribute('href')).toBe(
    '/cluster-permission/cluster-role',
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

test('cluster-role-data-requires-a-name', async () => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('')

  expect(await screen.findByText('Error: Cluster role name not provided')).toBeTruthy()
})
