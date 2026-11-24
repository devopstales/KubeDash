import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PodsWorkloadView from '../../src/views/Workload/Pods'
import PodDataView from '../../src/views/Workload/PodData'
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
const renderAt = (_ui: ReactElement, path = '/workload/pods') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/workload/pods"
            element={
              <ObjectRoute
                kind="pod"
                listRoute="/workload/pods"
                list={<PodsWorkloadView />}
                detail={(p) => <PodDataView name={p.name} namespace={p.namespace ?? ''} />}
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

// kubernetes to_dict shape: snake_case (a generated core/v1 model),
// spec/status intact.
const webPod = {
  apiVersion: 'v1',
  kind: 'Pod',
  metadata: {
    name: 'web-1',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: {},
    owner_references: [{ kind: 'ReplicaSet', name: 'web-abc', api_version: 'apps/v1' }],
  },
  spec: {
    node_name: 'node-1',
    service_account_name: 'default',
    security_context: { run_as_non_root: true },
    containers: [{ name: 'web', image: 'nginx:1.25' }],
    volumes: [{ config_map: { name: 'web-cm' } }],
  },
  status: {
    phase: 'Running',
    pod_ip: '10.0.0.5',
    container_statuses: [{ name: 'web', restart_count: 1, state: { running: {} } }],
    conditions: [{ type: 'Ready', status: 'True' }],
  },
}

// A pod that is phase Running but mid-deletion: 4.1's effective-phase rule
// overrides the badge to Terminated.
const terminatingPod = {
  ...webPod,
  metadata: {
    ...webPod.metadata,
    name: 'web-2',
    deletion_timestamp: '2026-01-02T03:05:00Z',
  },
}

// Phase Pending, no pod_ip yet (unscheduled-ish).
const pendingPod = {
  ...webPod,
  metadata: { ...webPod.metadata, name: 'web-3', owner_references: [] },
  spec: { ...webPod.spec, node_name: null },
  status: { phase: 'Pending', conditions: [] },
}

const cells = (tr: Element | null) => Array.from(tr?.querySelectorAll('td') ?? [])

// pods-list-renders-rows-with-data-links
test('list-renders-pod-rows-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [webPod] })
    }),
  )
  selectProd()
  renderAt(<PodsWorkloadView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean (R1).
  const nameButton = await screen.findByRole('button', { name: 'web-1' })
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/pods')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Pod List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Workloads → Pod List.
  expect(screen.getByText('Workloads')).toBeTruthy()
  // columns: 4.1's pod list columns + the 5.0 Name/Namespace-first order.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Status',
    'Pod IP',
    'Owner',
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
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [webPod] }),
    ),
  )
  renderAt(<PodsWorkloadView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'web-1' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('Pod Data')).toBeTruthy()
  // The URL is clean: no query string (R1).
  expect(window.location.search).toBe('')
})

// pods-list-status-badge-and-owner-cells
test('list-status-badge-and-owner-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [webPod, pendingPod] }),
    ),
  )
  selectProd()
  renderAt(<PodsWorkloadView />)

  const webLink = await screen.findByRole('button', { name: 'web-1' })
  // row: status badge, pod IP, owner as PLAIN TEXT kind.lower()/name
  // (ratified deviation 6 — the owning-workload views are not yet landed).
  expect(cells(webLink.closest('tr')).map((td) => td.textContent).slice(1)).toEqual([
    'team-a',
    'Running',
    '10.0.0.5',
    'replicaset/web-abc',
  ])
  const statusCell = cells(webLink.closest('tr'))[2]
  // the status is a badge (4.1's four-tier mapping), not bare text.
  expect(statusCell.querySelector('.badge')?.textContent).toBe('Running')
  // Owner is plain text: no link element inside the Owner cell.
  const ownerCell = cells(webLink.closest('tr'))[4]
  expect(ownerCell.querySelector('a')).toBeNull()

  // the pending pod: phase Pending badge, no pod IP yet.
  const pendingLink = await screen.findByRole('button', { name: 'web-3' })
  const pendingCells = cells(pendingLink.closest('tr')).map((td) => td.textContent)
  expect(pendingCells).toContain('Pending')
  expect(pendingCells).toContain('—') // pod_ip absent
  expect(pendingCells).toContain('—') // no owner reference
})

// pods-list-terminated-on-deletion
test('list-terminated-on-deletion', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [terminatingPod] }),
    ),
  )
  selectProd()
  renderAt(<PodsWorkloadView />)

  const link = await screen.findByRole('button', { name: 'web-2' })
  // 4.1's effective-phase rule: deletion_timestamp set → Terminated even
  // though status.phase is still Running.
  expect(cells(link.closest('tr')).map((td) => td.textContent)).toContain('Terminated')
})

// pods-list-no-cluster-state
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<PodsWorkloadView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// pods-list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on pods' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<PodsWorkloadView />)

  expect(
    await screen.findByText(/Error loading pods: RBAC_DENIED: list on pods/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'web-1' })).toHaveLength(0)
})

// pods-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<PodsWorkloadView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No pods found')).toBeTruthy()
})
