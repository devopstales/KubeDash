import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import RoleBindingView from '../../src/views/ClusterPermission/RoleBinding'
import RoleView from '../../src/views/ClusterPermission/Role'
import RoleDataView from '../../src/views/ClusterPermission/RoleData'
import ClusterRoleView from '../../src/views/ClusterPermission/ClusterRole'
import ClusterRoleDataView from '../../src/views/ClusterPermission/ClusterRoleData'
import ServiceAccountsView from '../../src/views/ClusterPermission/ServiceAccounts'
import ServiceAccountDataView from '../../src/views/ClusterPermission/ServiceAccountData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: the binding list renders on its own route; its cross-kind
// targets (role / cluster-role / service-account) are ObjectRoute-wrapped
// routes so a click resolves on the TARGET kind's clean list route (the same
// wiring as App.tsx).
const renderView = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/cluster-permission/role-binding']}>
        <Routes>
          <Route path="/cluster-permission/role-binding" element={<RoleBindingView />} />
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
          <Route
            path="/cluster-permission/service-account"
            element={
              <ObjectRoute
                kind="serviceaccount"
                listRoute="/cluster-permission/service-account"
                list={<ServiceAccountsView />}
                detail={(p) => (
                  <ServiceAccountDataView name={p.name} namespace={p.namespace ?? ''} />
                )}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

const editRole = {
  metadata: { name: 'edit', namespace: 'team-a' },
  rules: [{ api_groups: [''], resource_names: [], resources: ['pods'], verbs: ['get'] }],
}

const editBinding = {
  metadata: { name: 'edit-binding', namespace: 'team-a' },
  role_ref: { kind: 'Role', name: 'edit', api_group: 'rbac.authorization.k8s.io' },
  subjects: [
    { kind: 'User', name: 'jane' },
    { kind: 'User', name: 'bob' },
    { kind: 'Group', name: 'devs' },
    { kind: 'ServiceAccount', name: 'builder', namespace: 'ci' },
  ],
}

test('lists-role-bindings-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'rolebindings',
        cluster: 'prod',
        items: [
          editBinding,
          {
            metadata: { name: 'view-binding', namespace: 'team-a' },
            role_ref: { kind: 'ClusterRole', name: 'view' },
            subjects: [{ kind: 'Group', name: 'readers' }],
          },
        ],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText('edit-binding')).toBeTruthy()
  expect(requested).toBe('team-a')
  expect(screen.getByText('Role Bindings List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  // R1: the URL never carries object identity on the list route.
  expect(window.location.search).toBe('')
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Role',
    'User',
    'Group',
    'ServiceAccount',
  ])
  // ADR-0040: cross-kind role targets are buttons (openObject with the
  // target kind), not Links.
  expect(screen.getByRole('button', { name: 'edit' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'view' })).toBeTruthy()
  expect(screen.getByText('jane')).toBeTruthy()
  expect(screen.getByText('bob')).toBeTruthy()
  expect(screen.getByText('devs')).toBeTruthy()
  expect(screen.getByText('readers')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'builder' })).toBeTruthy()
  expect(screen.getByText('view-binding')).toBeTruthy()
})

test('service-account-link-selects-its-namespace', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json({ kind: 'rolebindings', cluster: 'prod', items: [editBinding] }),
    ),
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({
        kind: 'serviceaccounts',
        cluster: 'prod',
        items: [
          { metadata: { name: 'builder', namespace: 'ci' }, secrets: null, image_pull_secrets: null },
        ],
      }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  // Cross-kind click: the header namespace follows the account's namespace
  // (4.1 behavior) and the target kind's detail renders on its clean route.
  await user.click(await screen.findByRole('button', { name: 'builder' }))
  expect(useClusterStore.getState().selectedNamespace).toBe('ci')
  expect(await screen.findByText('Service Account Data')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('role-link-opens-the-role-detail', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json({ kind: 'rolebindings', cluster: 'prod', items: [editBinding] }),
    ),
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [editRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  // Cross-kind click: the ROLE kind's detail renders on its clean list route.
  await user.click(await screen.findByRole('button', { name: 'edit' }))
  expect(await screen.findByText('Rule List')).toBeTruthy()
  expect(screen.getByText('pods')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'rolebindings', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderView()

  expect(await screen.findByText('No role bindings found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on rolebindings' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(
    await screen.findByText(/Error loading role bindings: RBAC_DENIED: list on rolebindings/),
  ).toBeTruthy()
})

test('ignores-empty-subjects-and-unknown-role-kinds', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json({
        kind: 'rolebindings',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'bare', namespace: 'team-a' },
            role_ref: { kind: 'SomethingElse', name: 'custom' },
            subjects: null,
          },
        ],
      }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText('bare')).toBeTruthy()
  expect(screen.getByText('custom')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'custom' })).toBeNull()
})
