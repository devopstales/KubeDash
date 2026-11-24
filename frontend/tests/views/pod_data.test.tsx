import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PodDataView from '../../src/views/Workload/PodData'
import PodsWorkloadView from '../../src/views/Workload/Pods'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
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

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string, namespace: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({
      [token]: { kind: 'pod', name, namespace, ts: Date.now(), origin: 'click' },
    }),
  )
  sessionStorage.setItem('kd_object_active', token)
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

// A pod whose secret rides on an env value_from ref (the Related Resources
// deep-link target) plus a volume secret.
const secretPod = {
  ...webPod,
  spec: {
    ...webPod.spec,
    containers: [
      {
        name: 'web',
        image: 'nginx:1.25',
        env: [{ name: 'DB', value_from: { secret_key_ref: { name: 'db-secret' } } }],
      },
    ],
    volumes: [
      { config_map: { name: 'web-cm' } },
      { secret: { secret_name: 'tls-secret' } },
    ],
  },
}

const servePod = (items: unknown[]) =>
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', cluster: 'prod', items }),
    ),
  )

// pod-data-renders-detail
test('data-renders-detail', async () => {
  const fetched: string[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/pods', ({ request }) => {
      fetched.push(new URL(request.url).href)
      return HttpResponse.json({ kind: 'pods', cluster: 'prod', items: [webPod] })
    }),
  )
  selectProd()
  seedActiveRef('web-1', 'team-a')
  const { container } = renderAt(<PodDataView name="web-1" namespace="team-a" />)

  // Wait for the fetch to land before reading what the view asked for. The
  // highlighter splits tokens across <code class="hljs-*"> spans, so
  // findByText cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('"pod_ip"')
  })
  // single read: EXACTLY one ?name=&namespace= fetch (no 4.1
  // list-then-filter); the namespace is REQUIRED for the lookup.
  expect(fetched).toHaveLength(1)
  const url = new URL(fetched[0])
  expect(url.searchParams.get('name')).toBe('web-1')
  expect(url.searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Workloads → Pod List → name.
  const listLink = screen.getByRole('link', { name: 'Pod List' })
  expect(listLink.getAttribute('href')).toBe('/workload/pods')
  // metadata CTable: the item's fields are shown. The same values repeat in
  // the JSON block below, so scope to a table. (The Pod IP is NOT a data-
  // view row — it rides in the JSON block, asserted on the <pre> below.)
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('replicaset/web-abc')).toBe(true) // Owner: plain text
  expect(await inTable('1')).toBe(true) // Restarts: sum of restart_counts
  // the Node cell is a deep-link BUTTON to the LANDED Nodes view (ratified
  // deviation 4): cluster-scoped, no namespace.
  expect(await screen.findByRole('button', { name: 'node-1' })).toBeTruthy()
  // labels sub-table renders (the key is unique to the fixture);
  // annotations are empty → the pinned empty state.
  expect(await inTable('team')).toBe(true)
  expect(screen.getByText('No annotations')).toBeTruthy()
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"pod_ip": "10.0.0.5"')
})

// pod-data-containers-state-and-restarts
test('data-containers-state-and-restarts', async () => {
  servePod([webPod])
  selectProd()
  seedActiveRef('web-1', 'team-a')
  const { container } = renderAt(<PodDataView name="web-1" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('nginx:1.25')
  })
  // The Containers table renders the effective state + restart count
  // (spec.containers joined to status.container_statuses by name).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('nginx:1.25')).toBe(true)
  expect(screen.getByText('No init containers')).toBeTruthy()
  // the state badge (Running → 4.1's green mapping).
  const runningBadge = (await screen.findAllByText('Running')).find(
    (el) => el.closest('table') && el.classList.contains('badge'),
  )
  expect(runningBadge?.classList.contains('badge-success')).toBe(true)
  // the 4.1 header set for the containers table.
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  expect(headers).toContain('State')
  expect(headers).toContain('Restarts')
})

// pod-data-conditions
test('data-conditions', async () => {
  servePod([webPod])
  selectProd()
  seedActiveRef('web-1', 'team-a')
  const { container } = renderAt(<PodDataView name="web-1" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('Ready')
  })
  // one row per status.conditions[] entry (4.1's {type: status} dict).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('Ready')).toBe(true)
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  expect(headers).toContain('Condition')
  expect(headers).toContain('State')
})

// pod-data-related-resources-secret-deep-link
test('data-related-resources-secret-deep-link', async () => {
  servePod([secretPod])
  selectProd()
  seedActiveRef('web-1', 'team-a')
  const { container } = renderAt(<PodDataView name="web-1" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('web-cm')
  })
  // Refers To: image-pull secrets / service account / secrets (env +
  // volumes) / configmaps / PVCs from spec (ratified 2026-10-28 deep-link
  // set). Secrets are BUTTONS to the LANDED Secret view; the rest are
  // plain text (their views are not yet landed — the links would 404).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('default')).toBe(true) // ServiceAccount: plain text
  expect(await inTable('web-cm')).toBe(true) // Configmap: plain text
  expect(await screen.findByRole('button', { name: 'db-secret' })).toBeTruthy()
  expect(await screen.findByRole('button', { name: 'tls-secret' })).toBeTruthy()
  // the configmap cell is NOT a link.
  const cmCell = (await screen.findAllByText('web-cm')).find((el) => el.closest('table'))!
  expect(cmCell.closest('td')!.querySelector('a')).toBeNull()
  expect(cmCell.closest('td')!.querySelector('button')).toBeNull()
  // Refered By: the owner as plain text rows.
  expect(await inTable('replicaset')).toBe(true)
  expect(await inTable('web-abc')).toBe(true)
})

// pod-data-not-found-state
test('data-not-found-state', async () => {
  servePod([])
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<PodDataView name="ghost" namespace="team-a" />)

  // empty items upstream is a state, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No pod 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// pod-data-missing-name
test('data-missing-name', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PodDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: pod name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})

// pod-data-missing-status
test('data-missing-status', async () => {
  // A fresh pod before kubelet reports status: absent status fields render
  // the pinned literals (— for the phase badge / pod IP, 0 for restarts) —
  // the HPA's pdb-data-missing-status pin analog.
  const freshPod = {
    ...webPod,
    status: {},
  }
  servePod([freshPod])
  selectProd()
  seedActiveRef('web-1', 'team-a')
  const { container } = renderAt(<PodDataView name="web-1" namespace="team-a" />)

  // wait on a metadata timestamp (always present); the fresh pod's status
  // is {}, so the JSON block carries no pod_ip key to wait for.
  await waitFor(() => {
    expect(container.textContent).toContain('2026-01-02T03:04:05Z')
  })
  // the Status row renders the em-dash (no phase reported).
  const statusRow = screen.getByText('Status:').closest('tr')!
  expect(statusRow.querySelector('td')!.textContent).toBe('—')
  // no container_statuses → the Restarts sum is 0.
  const restartsRow = screen.getByText('Restarts:').closest('tr')!
  expect(restartsRow.querySelector('td')!.textContent).toBe('0')
})
