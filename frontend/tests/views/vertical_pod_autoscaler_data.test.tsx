import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import VerticalPodAutoscalerDataView from '../../src/views/OtherResource/VerticalPodAutoscalerData'
import { useClusterStore } from '../../src/store/cluster'

const renderAt = (ui: ReactElement, path: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
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

// The VPA CRD's full custom object: camelCase (the custom-object wire form).
const webVpa = {
  apiVersion: 'autoscaling.k8s.io/v1',
  kind: 'VerticalPodAutoscaler',
  metadata: {
    name: 'web-vpa',
    namespace: 'team-a',
    creationTimestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'vpa.kubernetes.io/managed-by': 'kubedash' },
  },
  spec: {
    targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' },
    updatePolicy: { updateMode: 'Auto' },
    resourcePolicy: {
      containerPolicies: [
        {
          containerName: 'app',
          controlledValues: 'RequestsLimits',
          mode: 'Auto',
          minAllowed: { memory: '128Mi' },
          maxAllowed: { memory: '1Gi' },
          controlledResources: ['cpu', 'memory'],
        },
      ],
    },
  },
  status: {
    conditions: [
      {
        type: 'RecommendationProvided',
        status: 'True',
        lastTransitionTime: '2026-01-02T03:04:06Z',
        reason: 'RecommendationAvailable',
        message: 'ok',
      },
    ],
  },
}

const dataPath = '/other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a'

test('vpa-data-renders-detail', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [webVpa] })
    }),
  )
  selectProd()
  const { container } = renderAt(<VerticalPodAutoscalerDataView />, dataPath)

  // Wait for the fetch to land before reading what the view asked for. The
  // highlighter splits tokens across <code class="hljs-*"> spans, so
  // findByText cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('"updateMode"')
  })
  // single read: EXACTLY one ?name=&namespace= fetch (no 4.1
  // list-then-filter). The namespace is REQUIRED for the lookup.
  expect(searchParams.get('name')).toBe('web-vpa')
  expect(searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Other Resources → Vertical Pod Autoscaler List → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Vertical Pod Autoscaler List' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/vertical-pod-autoscaler')
  // metadata CTable: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('Auto')).toBe(true)
  // labels/annotations render (keys are unique to the fixture).
  expect(await inTable('team')).toBe(true)
  expect(await inTable('vpa.kubernetes.io/managed-by')).toBe(true)
  // Container Policies table: header + the fixture's policy row.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toContain('Controlled Values')
  expect(await inTable('app')).toBe(true)
  expect(await inTable('RequestsLimits')).toBe(true)
  expect(await inTable('memory: 128Mi')).toBe(true)
  expect(await inTable('memory: 1Gi')).toBe(true)
  expect(await inTable('cpu, memory')).toBe(true)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"updateMode": "Auto"')
})

test('vpa-data-conditions-from-status', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [webVpa] }),
    ),
  )
  selectProd()
  const { container } = renderAt(<VerticalPodAutoscalerDataView />, dataPath)

  await waitFor(() => {
    expect(container.textContent).toContain('RecommendationProvided')
  })
  // The Conditions row is sourced from status.conditions — 4.1's top-level
  // `conditions` key was never populated by its read function (a dead
  // table); assert the typed row renders.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('RecommendationProvided')).toBe(true)
  expect(await inTable('RecommendationAvailable')).toBe(true)
  expect(await inTable('2026-01-02T03:04:06Z')).toBe(true)
  // the Conditions header is present and distinct from the metadata table.
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  expect(headers).toContain('Last Transition Time')
  expect(headers).toContain('Reason')
})

test('vpa-data-container-policies', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [webVpa] }),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerDataView />, dataPath)

  await screen.findByText('app', { selector: 'td' })
  // Min/Max Allowed render "resource: value" lines; Controlled Resources
  // joined by ", ".
  expect(screen.getByText('memory: 128Mi')).toBeTruthy()
  expect(screen.getByText('memory: 1Gi')).toBeTruthy()
  expect(screen.getByText('cpu, memory')).toBeTruthy()
})

test('vpa-data-empty-vs-absent-bounds', async () => {
  // A present-but-empty minAllowed object is NOT an absent bound: it
  // renders —, while a truly absent bound renders 4.1's N/A literal.
  // Max Allowed is absent here (triangulation: both branches, one row).
  const emptyBounds = {
    ...webVpa,
    spec: {
      ...webVpa.spec,
      resourcePolicy: {
        containerPolicies: [
          {
            containerName: 'app',
            controlledValues: 'RequestsLimits',
            mode: 'Auto',
            minAllowed: {},
            controlledResources: ['cpu', 'memory'],
          },
        ],
      },
    },
    status: {},
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [emptyBounds] }),
    ),
  )
  selectProd()
  const { container } = renderAt(<VerticalPodAutoscalerDataView />, dataPath)

  await waitFor(() => {
    expect(container.textContent).toContain('"targetRef"')
  })
  // The policy row: container name, mode, and controlled resources render.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('app')).toBe(true)
  // present-but-empty minAllowed → — (not N/A).
  const emptyBoundCells = (await screen.findAllByText('—')).filter((el) => el.closest('table'))
  expect(emptyBoundCells.length).toBeGreaterThanOrEqual(1)
  // absent maxAllowed → N/A in the same row.
  expect(await inTable('N/A')).toBe(true)
})

test('vpa-data-missing-policy', async () => {
  // No resourcePolicy and no status.conditions: both tables degrade to
  // their pinned empty states (certainty rule: never guess).
  const bare = {
    ...webVpa,
    spec: { targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' } },
    status: {},
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [bare] }),
    ),
  )
  selectProd()
  const { container } = renderAt(<VerticalPodAutoscalerDataView />, dataPath)

  await waitFor(() => {
    expect(container.textContent).toContain('"targetRef"')
  })
  expect(screen.getByText('No container policies')).toBeTruthy()
  expect(screen.getByText('No conditions')).toBeTruthy()
  // Update Mode is absent from spec: 4.1's N/A literal.
  expect(screen.getByText('N/A')).toBeTruthy()
})

test('vpa-data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  const { container } = renderAt(
    <VerticalPodAutoscalerDataView />,
    '/other-resource/vertical-pod-autoscaler/data?name=ghost&namespace=team-a',
  )

  // empty items upstream is a state, not an error: pinned copy, no
  // error styling (also the CRD-absent state — the backend returns []
  // in both cases).
  expect(await screen.findByText("No VerticalPodAutoscaler 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

test('vpa-data-missing-name', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerDataView />, '/other-resource/vertical-pod-autoscaler/data')

  expect(await screen.findByText('Error: vertical pod autoscaler name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
