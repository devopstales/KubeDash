import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import DeploymentsWorkloadView from '../../src/views/Workload/Deployments'
import DeploymentDataView from '../../src/views/Workload/DeploymentData'
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
const renderAt = (_ui: ReactElement, path = '/workload/deployments') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/workload/deployments"
            element={
              <ObjectRoute
                kind="deployment"
                listRoute="/workload/deployments"
                list={<DeploymentsWorkloadView />}
                detail={(p) => (
                  <DeploymentDataView name={p.name} namespace={p.namespace ?? ''} />
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
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case (a generated apps/v1 model),
// spec/status intact.
const webDeployment = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { app: 'web' },
    annotations: {},
  },
  spec: {
    replicas: 3,
    selector: { match_labels: { tier: 'frontend' } },
    template: {
      spec: {
        service_account_name: 'web-sa',
        security_context: { run_as_non_root: true },
        containers: [
          {
            name: 'web',
            image: 'nginx:1.25',
            env: [
              { name: 'PORT', value: '8080' },
              { name: 'DB', value_from: { secret_key_ref: { name: 'db-secret' } } },
            ],
          },
        ],
        init_containers: [{ name: 'init', image: 'busybox' }],
        volumes: [
          { config_map: { name: 'web-cm' } },
          { secret: { secret_name: 'tls-secret' } },
          { persistent_volume_claim: { claim_name: 'web-pvc' } },
        ],
        image_pull_secrets: [{ name: 'registry-pull' }],
      },
    },
  },
  status: {
    replicas: 3,
    ready_replicas: 2,
    updated_replicas: 3,
    conditions: [
      {
        type: 'Available',
        reason: 'MinimumReplicasAvailable',
        message: 'Deployment has minimum availability.',
        last_transition_time: '2026-01-02T03:04:06Z',
      },
    ],
  },
}

// A fresh deployment before the controller reports status: the 4.1
// `<desired>/<ready>` cell renders 0/0 (each defaulting to 0).
const freshDeployment = {
  ...webDeployment,
  status: {},
}

const cells = (tr: Element | null) => Array.from(tr?.querySelectorAll('td') ?? [])

// deployments-list-renders-rows-with-data-links
test('list-renders-deployment-rows-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'deployments', cluster: 'prod', items: [webDeployment] })
    }),
  )
  selectProd()
  renderAt(<DeploymentsWorkloadView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean (R1).
  const nameButton = await screen.findByRole('button', { name: 'web' })
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/deployments')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Deployments List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Workloads → Deployments List.
  expect(screen.getByText('Workloads')).toBeTruthy()
  // columns: 4.1's deployment list columns + the 5.0 Name/Namespace-first
  // order.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Status',
    'Created',
  ])
  const nameCell = nameButton.closest('tr')
  // row: the namespace is shown (the namespaced kind).
  expect(nameCell?.textContent).toContain('team-a')
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json({ kind: 'deployments', cluster: 'prod', items: [webDeployment] }),
    ),
  )
  renderAt(<DeploymentsWorkloadView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'web' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('Deployment Data')).toBeTruthy()
  // The URL is clean: no query string (R1).
  expect(window.location.search).toBe('')
})

// deployments-list-status-and-created-cells
test('list-status-and-created-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json({ kind: 'deployments', cluster: 'prod', items: [webDeployment] }),
    ),
  )
  selectProd()
  renderAt(<DeploymentsWorkloadView />)

  const nameButton = await screen.findByRole('button', { name: 'web' })
  // row: 4.1's `<desired>/<ready>` (status.replicas / status.ready_replicas,
  // each defaulting to 0) and the created cell rendered by formatTimestamp
  // (no raw ISO 'T').
  expect(cells(nameButton.closest('tr')).map((td) => td.textContent).slice(1)).toEqual([
    'team-a',
    '3/2',
    expect.stringContaining('2026'),
  ])
  expect(nameButton.closest('tr')?.textContent).not.toContain('2026-01-02T03:04:05Z')
})

// deployments-list-fresh-deployment-zero-status
test('list-fresh-deployment-zero-status', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json({ kind: 'deployments', cluster: 'prod', items: [freshDeployment] }),
    ),
  )
  selectProd()
  renderAt(<DeploymentsWorkloadView />)

  const nameButton = await screen.findByRole('button', { name: 'web' })
  // no status reported: both halves default to 0 (4.1's cell).
  expect(cells(nameButton.closest('tr')).map((td) => td.textContent)).toContain('0/0')
})

// deployments-list-no-cluster-state
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<DeploymentsWorkloadView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// deployments-list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on deployments' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<DeploymentsWorkloadView />)

  expect(
    await screen.findByText(/Error loading deployments: RBAC_DENIED: list on deployments/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'web' })).toHaveLength(0)
})

// deployments-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json({ kind: 'deployments', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<DeploymentsWorkloadView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No deployments found')).toBeTruthy()
})
