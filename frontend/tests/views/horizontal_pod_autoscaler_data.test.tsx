import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import HorizontalPodAutoscalerDataView from '../../src/views/OtherResource/HorizontalPodAutoscalerData'
import HorizontalPodAutoscalerView from '../../src/views/OtherResource/HorizontalPodAutoscaler'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/other-resource/horizontal-pod-autoscaler') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/horizontal-pod-autoscaler"
            element={
              <ObjectRoute
                kind="horizontalpodautoscaler"
                listRoute="/other-resource/horizontal-pod-autoscaler"
                list={<HorizontalPodAutoscalerView />}
                detail={(p) => (
                  <HorizontalPodAutoscalerDataView name={p.name} namespace={p.namespace ?? ''} />
                )}
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
      [token]: { kind: 'horizontalpodautoscaler', name, namespace, ts: Date.now(), origin: 'click' },
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

// kubernetes to_dict shape: snake_case (a generated core-API model),
// spec/status intact.
const webHpa = {
  apiVersion: 'autoscaling/v1',
  kind: 'HorizontalPodAutoscaler',
  metadata: {
    name: 'web-hpa',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: {},
  },
  spec: {
    scale_target_ref: { kind: 'Deployment', name: 'web', api_version: 'apps/v1' },
    min_replicas: 2,
    max_replicas: 10,
    target_cpu_utilization_percentage: 80,
  },
  status: {
    current_replicas: 3,
    desired_replicas: 3,
    current_cpu_utilization_percentage: 50,
    conditions: [
      {
        type: 'AbleToScale',
        status: 'True',
        last_transition_time: '2026-01-02T03:04:06Z',
        reason: 'SuccessfulRescale',
        message: 'Ready to scale',
      },
    ],
  },
}

// A legacy HPA with NO status.conditions but the 4.1-era
// autoscaling.alpha.kubernetes.io/conditions annotation (a JSON list — the
// live 4.1 shape is camelCase; 5.0's typed table renders the snake_case
// to_dict form, and this fixture pins that rendering).
const legacyCondHpa = {
  ...webHpa,
  metadata: {
    ...webHpa.metadata,
    annotations: {
      'autoscaling.alpha.kubernetes.io/conditions': JSON.stringify([
        {
          type: 'AbleToScale',
          status: 'True',
          last_transition_time: '2026-01-02T03:04:06Z',
          reason: 'SuccessfulRescale',
          message: 'Ready to scale',
        },
      ]),
    },
  },
  status: { current_replicas: 3, desired_replicas: 3, current_cpu_utilization_percentage: 50 },
}

// Neither status.conditions nor the legacy annotation.
const noCondHpa = {
  ...webHpa,
  metadata: { ...webHpa.metadata, annotations: {} },
  status: { current_replicas: 3, desired_replicas: 3, current_cpu_utilization_percentage: 50 },
}

const serveHpa = (items: unknown[]) =>
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', () =>
      HttpResponse.json({ kind: 'horizontalpodautoscalers', cluster: 'prod', items }),
    ),
  )

// hpa-data-renders-detail
test('data-renders-detail', async () => {
  const fetched: string[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', ({ request }) => {
      fetched.push(new URL(request.url).href)
      return HttpResponse.json({ kind: 'horizontalpodautoscalers', cluster: 'prod', items: [webHpa] })
    }),
  )
  selectProd()
  seedActiveRef('web-hpa', 'team-a')
  const { container } = renderAt(<HorizontalPodAutoscalerDataView name="web-hpa" namespace="team-a" />)

  // Wait for the fetch to land before reading what the view asked for. The
  // highlighter splits tokens across <code class="hljs-*"> spans, so
  // findByText cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('"min_replicas"')
  })
  // single read: EXACTLY one ?name=&namespace= fetch (no 4.1
  // list-then-filter); the namespace is REQUIRED for the lookup.
  expect(fetched).toHaveLength(1)
  const url = new URL(fetched[0])
  expect(url.searchParams.get('name')).toBe('web-hpa')
  expect(url.searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Other Resources → Horizontal Pod Autoscaler List → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Horizontal Pod Autoscaler List' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/horizontal-pod-autoscaler')
  // metadata CTable: the item's fields are shown. The same values repeat in
  // the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('web')).toBe(true) // Owner: scale_target_ref name
  expect(await inTable('50 / 80 %')).toBe(true) // Metrics
  expect(await inTable('2')).toBe(true) // Min Replicas
  expect(await inTable('10')).toBe(true) // Max Replicas
  expect(await inTable('3 Current / 3 Desired')).toBe(true) // Replicas
  // labels/annotations sub-tables render: the label key is unique to the
  // fixture (its VALUE 'a' also appears in the JSON block); annotations
  // are empty → the pinned empty state.
  expect(await inTable('team')).toBe(true)
  expect(screen.getByText('No annotations')).toBeTruthy()
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"min_replicas": 2')
})

// hpa-data-conditions-from-status
test('data-conditions-from-status', async () => {
  serveHpa([webHpa])
  selectProd()
  seedActiveRef('web-hpa', 'team-a')
  const { container } = renderAt(<HorizontalPodAutoscalerDataView name="web-hpa" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('AbleToScale')
  })
  // The Conditions table is a typed row from status.conditions (4.1 read
  // ONLY the legacy annotation; modern HPAs carry them on status).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('AbleToScale')).toBe(true)
  expect(await inTable('2026-01-02T03:04:06Z')).toBe(true)
  expect(await inTable('SuccessfulRescale')).toBe(true)
  expect(await inTable('Ready to scale')).toBe(true)
  // the Conditions header is present and distinct from the metadata table.
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  expect(headers).toContain('Type')
  expect(headers).toContain('Status')
  expect(headers).toContain('Last Transition Time')
  expect(headers).toContain('Reason')
  expect(headers).toContain('Message')
})

// hpa-data-conditions-from-legacy-annotation
test('data-conditions-from-legacy-annotation', async () => {
  serveHpa([legacyCondHpa])
  selectProd()
  seedActiveRef('web-hpa', 'team-a')
  const { container } = renderAt(<HorizontalPodAutoscalerDataView name="web-hpa" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('AbleToScale')
  })
  // 4.1's source: the legacy annotation is the ONLY condition source here —
  // the typed row must still render from it.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('AbleToScale')).toBe(true)
  expect(await inTable('Ready to scale')).toBe(true)
  expect(screen.queryByText('No conditions')).toBeNull()
})

// hpa-data-missing-conditions
test('data-missing-conditions', async () => {
  serveHpa([noCondHpa])
  selectProd()
  seedActiveRef('web-hpa', 'team-a')
  const { container } = renderAt(<HorizontalPodAutoscalerDataView name="web-hpa" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('"min_replicas"')
  })
  expect(screen.getByText('No conditions')).toBeTruthy()
})

// hpa-data-not-found-state
test('data-not-found-state', async () => {
  serveHpa([])
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<HorizontalPodAutoscalerDataView name="web-hpa" namespace="team-a" />)

  // empty items upstream is a state, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No HorizontalPodAutoscaler 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// hpa-data-missing-name
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
        <HorizontalPodAutoscalerDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: horizontal pod autoscaler name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
