import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ClusterRoleBindingView from '../../src/views/ClusterPermission/ClusterRoleBinding'
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
      <MemoryRouter initialEntries={['/cluster-permission/cluster-role-binding']}>
        <Routes>
          <Route
            path="/cluster-permission/cluster-role-binding"
            element={<ClusterRoleBindingView />}
          />
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

const editClusterRole = {
  metadata: { name: 'cluster-admin' },
  rules: [],
}

const adminBinding = {
  metadata: { name: 'cluster-admin' },
  role_ref: { kind: 'ClusterRole', name: 'cluster-admin', api_group: 'rbac.authorization.k8s.io' },
  subjects: [
    { kind: 'User', name: 'jane' },
    { kind: 'User', name: 'bob' },
    { kind: 'Group', name: 'system:masters' },
    { kind: 'ServiceAccount', name: 'builder', namespace: 'ci' },
  ],
}

test('lists-cluster-role-bindings-without-a-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', ({ request }) => {
      requested = request.url
      return HttpResponse.json({
        kind: 'clusterrolebindings',
        cluster: 'prod',
        items: [
          adminBinding,
          {
            metadata: { name: 'view-binding' },
            role_ref: { kind: 'Role', name: 'edit' },
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

  // the binding row (Name column) carries 'cluster-admin'; the Role column's
  // button is the other match — scope the text lookup to the first column.
  expect(await screen.findByRole('button', { name: 'cluster-admin' })).toBeTruthy()
  const url = new URL(requested)
  expect(url.pathname).toBe('/api/v1/clusters/1/resources/clusterrolebindings')
  expect(url.search).toBe('')
  expect(screen.getByText('Cluster Role Binding List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getByText('Cluster Role Bindings')).toBeTruthy()
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
  expect(screen.getByRole('button', { name: 'cluster-admin' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'edit' })).toBeTruthy()
  expect(screen.getByText('jane')).toBeTruthy()
  expect(screen.getByText('bob')).toBeTruthy()
  expect(screen.getByText('system:masters')).toBeTruthy()
  expect(screen.getByText('readers')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'builder' })).toBeTruthy()
  expect(screen.getByText('view-binding')).toBeTruthy()
})

test('list-shows-every-binding-row', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({
        kind: 'clusterrolebindings',
        cluster: 'prod',
        items: [adminBinding, { metadata: { name: 'view-binding' }, role_ref: { kind: 'Role', name: 'edit' }, subjects: [] }],
      }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  // the Name column is plain text (the binding kind is list-only) — both rows
  // render as text, not as buttons.
  const rows = await screen.findAllByRole('row')
  expect(rows.some((row) => row.textContent?.includes('cluster-admin'))).toBe(true)
  expect(rows.some((row) => row.textContent?.includes('view-binding'))).toBe(true)
})

test('cluster-role-link-opens-the-cluster-role-detail', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({ kind: 'clusterrolebindings', cluster: 'prod', items: [adminBinding] }),
    ),
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [editClusterRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  // Cross-kind click: the CLUSTERROLE kind's detail renders on its clean
  // list route (the empty-rules state renders, like the real page).
  await user.click(await screen.findByRole('button', { name: 'cluster-admin' }))
  expect(await screen.findByText('No rules found')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('service-account-link-selects-its-namespace', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({ kind: 'clusterrolebindings', cluster: 'prod', items: [adminBinding] }),
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

test('shows-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({ kind: 'clusterrolebindings', cluster: 'prod', items: [] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText('No cluster role bindings found')).toBeTruthy()
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on clusterrolebindings' } },
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
    await screen.findByText(
      /Error loading cluster role bindings: RBAC_DENIED: list on clusterrolebindings/,
    ),
  ).toBeTruthy()
})

test('ignores-empty-subjects-and-unknown-role-kinds', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({
        kind: 'clusterrolebindings',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'bare' },
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
