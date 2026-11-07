import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import VerticalPodAutoscalerView from '../../src/views/OtherResource/VerticalPodAutoscaler'
import VerticalPodAutoscalerDataView from '../../src/views/OtherResource/VerticalPodAutoscalerData'
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
const renderAt = (_ui: ReactElement, path = '/other-resource/vertical-pod-autoscaler') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/vertical-pod-autoscaler"
            element={
              <ObjectRoute
                kind="verticalpodautoscaler"
                listRoute="/other-resource/vertical-pod-autoscaler"
                list={<VerticalPodAutoscalerView />}
                detail={(p) => (<VerticalPodAutoscalerDataView name={p.name} namespace={p.namespace ?? ''} />)}
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

const vpaListResponse = (items: unknown[]) =>
  HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items })


// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      HttpResponse.json({ items: [webVpa] }),
    ),
  )
  renderAt(<VerticalPodAutoscalerView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'web-vpa' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched) and the URL is
  // clean: no query string (R1).
  expect(await screen.findByText('Vertical Pod Autoscaler Data')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('vpa-list-renders-rows-with-data-links', async () => {
  let fetchedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', ({ request }) => {
      fetchedUrl = new URL(request.url).pathname + new URL(request.url).search
      return vpaListResponse([webVpa])
    }),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL never
  // carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'web-vpa' })
  // fetch URL EXACTLY: the namespaced CRD kind with the header's namespace.
  expect(fetchedUrl).toBe('/api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a')
  // card title EXACTLY (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Vertical Pod Autoscaler List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Other Resources.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns, in order.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Target Kind',
    'Target Name',
    'Update Mode',
    'Min Memory',
    'Max Memory',
    'Created',
  ])
  // created is rendered by formatTimestamp (no raw ISO 'T' in the row).
  const row = nameButton.closest('tr')
  expect(row?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(row?.textContent).toMatch(/2026/)
})

test('vpa-list-target-and-memory-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([webVpa]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  await screen.findByRole('button', { name: 'web-vpa' })
  const row = screen.getByRole('button', { name: 'web-vpa' }).closest('tr')
  // Target Kind from spec.targetRef.kind; Update Mode from
  // spec.updatePolicy.updateMode; Min/Max Memory from the container policy.
  expect(row?.textContent).toContain('Deployment')
  expect(row?.textContent).toContain('Auto')
  expect(row?.textContent).toContain('128Mi')
  expect(row?.textContent).toContain('1Gi')
  // Target Name (spec.targetRef.name) is PLAIN TEXT: 4.1 linked it to a
  // workload page 5.0 does not have yet — only the VPA name is clickable
  // (the row's single button).
  expect(row?.querySelectorAll('button')).toHaveLength(1)
  expect(screen.getByText('web')).not.toHaveAttribute('href')
})

test('vpa-list-last-container-memory-semantics', async () => {
  // 4.1's {% set %} overwrite: the LAST container policy that defines the
  // key wins (the first 64Mi must not survive).
  const twoPolicies = {
    ...webVpa,
    metadata: { ...webVpa.metadata, name: 'two-vpa' },
    spec: {
      ...webVpa.spec,
      resourcePolicy: {
        containerPolicies: [
          { containerName: 'first', minAllowed: { memory: '64Mi' }, maxAllowed: { memory: '512Mi' } },
          { containerName: 'second', minAllowed: { memory: '256Mi' } },
        ],
      },
    },
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([twoPolicies]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  const nameButton = await screen.findByRole('button', { name: 'two-vpa' })
  const row = nameButton.closest('tr')
  expect(row?.textContent).toContain('256Mi')
  expect(row?.textContent).not.toContain('64Mi')
  expect(row?.textContent).toContain('512Mi')
})

test('vpa-list-missing-update-policy', async () => {
  const noPolicy = {
    ...webVpa,
    metadata: { ...webVpa.metadata, name: 'no-upd' },
    spec: {
      targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' },
      // no updatePolicy
    },
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([noPolicy]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  const nameButton = await screen.findByRole('button', { name: 'no-upd' })
  const row = nameButton.closest('tr')
  // 4.1's literal for the absent value: N/A (certainty rule: never guess).
  expect(row?.textContent).toContain('N/A')
})

test('vpa-list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<VerticalPodAutoscalerView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

test('vpa-list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  // Also the CRD-absent state: the page does not distinguish "no VPAs"
  // from "operator not installed" — one pinned empty-state copy.
  expect(await screen.findByText('No vertical pod autoscalers found')).toBeTruthy()
})
