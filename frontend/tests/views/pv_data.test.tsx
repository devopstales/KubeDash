import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PvView from '../../src/views/Storage/Pv'
import PvDataView from '../../src/views/Storage/PvData'
import { useClusterStore } from '../../src/store/cluster'

// Render through ObjectRoute so the detail identity is the real one (the
// active ref; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/storage/pv') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/pv"
            element={
              <ObjectRoute
                kind="persistentvolume"
                listRoute="/storage/pv"
                list={<PvView />}
                detail={(p) => (<PvDataView name={p.name} />)}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's identity
// comes from ObjectRoute's ref, not the URL). Cluster-scoped: no namespace.
const seedActiveRef = (name: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind: 'persistentvolume', name, ts: Date.now(), origin: 'click' } }),
  )
  sessionStorage.setItem('kd_object_active', token)
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case. Cluster-scoped — no namespace field.
const pvHost = {
  metadata: {
    name: 'pv-host',
    creation_timestamp: '2026-01-02T03:04:05Z',
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"PersistentVolume"}',
      team: 'a',
    },
    labels: { app: 'data' },
  },
  spec: {
    capacity: { storage: '100Mi' },
    access_modes: ['ReadWriteOnce'],
    persistent_volume_reclaim_policy: 'Retain',
    volume_mode: 'Filesystem',
    storage_class_name: 'standard',
    claim_ref: { name: 'demo-pvc', namespace: 'kubedash-demo' },
    host_path: { path: '/var/local-path/pv-host' },
  },
  status: { phase: 'Bound' },
}

const pvCsi = {
  ...pvHost,
  metadata: { name: 'pv-csi', creation_timestamp: '2026-01-02T03:04:05Z' },
  spec: {
    ...pvHost.spec,
    host_path: undefined,
    csi: {
      driver: 'csi.example.com',
      fs_type: 'ext4',
      volume_attributes: { type: 'pd-ssd' },
    },
  },
}

// pv-data-renders-4-1-rows
test('data-renders-detail', async () => {
  selectProd()
  seedActiveRef('pv-host')
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvHost] }),
    ),
  )
  renderAt(<PvView />)

  expect(await screen.findByText('Persistent Volume Data')).toBeTruthy()
  // Await the first row so the single ?name= fetch has resolved.
  expect(await screen.findByText('Status:')).toBeTruthy()
  // 4.1 row set.
  for (const label of [
    'Name:',
    'Created:',
    'Annotations:',
    'Labels:',
    'StorageClass:',
    'Persistent Volume Claim:',
    'PVC Namespace:',
    'Access Mode:',
    'Volume Mode:',
    'Reclaim Policy:',
    'Capacity:',
  ]) {
    expect(screen.getByText(label)).toBeTruthy()
  }
  expect(screen.getByText('Bound')).toBeTruthy()
  // Name: the value renders in the row (it also appears in the breadcrumb
  // crumb, so assert on the row, not a bare text match).
  const nameRow = screen.getByText('Name:').closest('tr')
  expect(nameRow?.textContent).toContain('pv-host')
  expect(screen.getByText('standard')).toBeTruthy()
  expect(screen.getByText('demo-pvc')).toBeTruthy()
  expect(screen.getByText('kubedash-demo')).toBeTruthy()
  expect(screen.getByText('ReadWriteOnce')).toBeTruthy()
  expect(screen.getByText('Filesystem')).toBeTruthy()
  expect(screen.getByText('Retain')).toBeTruthy()
  expect(screen.getByText('100Mi')).toBeTruthy()
  // 4.1 XOR: hostPath PV → Local Path row, no CSI rows.
  expect(screen.getByText('Local Path:')).toBeTruthy()
  expect(screen.getByText('/var/local-path/pv-host')).toBeTruthy()
  expect(screen.queryByText('CSI Driver:')).toBeNull()
  expect(screen.queryByText('Filesystem Type:')).toBeNull()
})

// storage-data-annotations-trim-last-applied (the pv data view leg)
test('data-annotations-trim-last-applied', async () => {
  selectProd()
  seedActiveRef('pv-host')
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvHost] }),
    ),
  )
  renderAt(<PvView />)

  const annotationsRow = (await screen.findByText('Annotations:')).closest('tr')
  // The machine-managed key is out of the annotations table…
  expect(annotationsRow?.textContent).not.toContain('last-applied-configuration')
  // …but the real annotation renders, and the JSON block keeps the full
  // object (the key is there).
  expect(annotationsRow?.textContent).toContain('team')
  expect(screen.getByText('Persistent Volume').closest('div')?.parentElement?.textContent)
    .toContain('last-applied-configuration')
})

// pv-data-hostpath-vs-csi (the CSI leg)
test('data-csi-pv', async () => {
  selectProd()
  seedActiveRef('pv-csi')
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvCsi] }),
    ),
  )
  renderAt(<PvView />)

  expect(await screen.findByText('CSI Driver:')).toBeTruthy()
  expect(screen.getByText('csi.example.com')).toBeTruthy()
  expect(screen.getByText('Filesystem Type:')).toBeTruthy()
  expect(screen.getByText('ext4')).toBeTruthy()
  // The dynamic Volume Attributes table.
  expect(screen.getByText('Volume Attributes')).toBeTruthy()
  expect(screen.getByText('pd-ssd')).toBeTruthy()
  // 4.1 XOR: CSI PV → no Local Path row.
  expect(screen.queryByText('Local Path:')).toBeNull()
})

// pv-data-terminating
test('data-terminating', async () => {
  selectProd()
  seedActiveRef('pv-del')
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({
        items: [
          {
            ...pvHost,
            metadata: {
              ...pvHost.metadata,
              name: 'pv-del',
              deletion_timestamp: '2026-01-03T04:05:06Z',
            },
            status: { phase: 'Terminating' },
          },
        ],
      }),
    ),
  )
  renderAt(<PvView />)

  expect(await screen.findByText('Terminating')).toBeTruthy()
  // The Deleted row appears only while deleting.
  expect(screen.getByText('Deleted:')).toBeTruthy()
})

// pv-data-not-found-is-state
test('data-not-found-state', async () => {
  selectProd()
  seedActiveRef('ghost')
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [] }),
    ),
  )
  renderAt(<PvView />)

  expect(await screen.findByText("No PersistentVolume 'ghost' found")).toBeTruthy()
})
