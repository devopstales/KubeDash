import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import GatewayConverter from '../../src/views/Network/GatewayConverter'
import { toYaml } from '../../src/lib/yaml'
import { apiFetch } from '../../src/lib/api'
import { useClusterStore } from '../../src/store/cluster'

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

const renderAt = (ui: ReactElement) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/ingress']}>
        <Routes>
          <Route path="/network/ingress" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// The converter's fixture response (the backend GatewayConvertOut shape):
// envoy provider -> the `eg` GatewayClass + one Gateway, one dropped
// annotation.
const convertFixture = {
  cluster: 'prod',
  namespace: 'team-a',
  source: 'ingress',
  gatewayClassName: 'eg',
  resources: [
    {
      kind: 'GatewayClass',
      apiVersion: 'gateway.networking.k8s.io/v1',
      metadata: { name: 'eg' },
      spec: { controllerName: 'gateway.envoyproxy.io/gatewayclass-controller' },
    },
    {
      kind: 'Gateway',
      apiVersion: 'gateway.networking.k8s.io/v1',
      metadata: { name: 'web-eg', namespace: 'team-a' },
      spec: {
        gatewayClassName: 'eg',
        listeners: [
          {
            name: 'http',
            protocol: 'HTTP',
            port: 80,
            allowedRoutes: { namespaces: { from: 'All' } },
          },
        ],
      },
    },
  ],
  warnings: ['nginx.kubernetes.io/limit-rps'],
}

// to-yaml: the display serializer (pure; the apply path sends raw dicts).
test('to-yaml-scalar-quoting', () => {
  expect(toYaml({ a: 1, b: true, c: null })).toBe('a: 1\nb: true\nc: null')
  // Reserved words and number-shaped strings are double-quoted (JSON quoting
  // is valid YAML), as is anything outside the plain-safe set (slashes
  // included); safe identifiers stay plain.
  expect(toYaml({ a: 'true', b: '123', c: 'web-1.a/b' })).toBe(
    'a: "true"\nb: "123"\nc: "web-1.a/b"',
  )
})

test('to-yaml-nested-blocks', () => {
  expect(toYaml({ list: [{ name: 'web', port: 80 }, 'plain'], empty: {}, arr: [] })).toBe(
    'list:\n  - name: web\n    port: 80\n  - plain\nempty: {}\narr: []',
  )
})

// converter-renders-controls
test('converter-renders-controls', () => {
  selectProd()
  renderAt(<GatewayConverter name="web" namespace="team-a" />)
  expect(screen.getByText('Convert to Gateway API')).toBeTruthy()
  expect(screen.getByRole('combobox', { name: 'Gateway API provider' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Convert' })).toBeTruthy()
})

// converter-convert-renders-yaml-tabs-and-warnings
test('converter-convert-renders-yaml-tabs-and-warnings', async () => {
  selectProd()
  server.use(
    http.post('*/api/v1/clusters/1/gateway-api/convert', () =>
      HttpResponse.json(convertFixture),
    ),
  )
  renderAt(<GatewayConverter name="web" namespace="team-a" />)
  fireEvent.click(screen.getByRole('button', { name: 'Convert' }))
  // Per-resource tabs.
  await screen.findByText('GatewayClass eg')
  expect(screen.getByText('Gateway web-eg')).toBeTruthy()
  // The YAML preview of the active tab (the highlighter splits tokens, so
  // assert on the whole <code> text, not a single token; the value renders
  // double-quoted — the emitter quotes any scalar containing a slash).
  await waitFor(() => {
    const code = document.querySelector('pre code')
    expect(code?.textContent).toContain(
      'controllerName: "gateway.envoyproxy.io/gatewayclass-controller"',
    )
  })
  // The warnings (the dropped annotations, one line each).
  expect(
    screen.getByText('1 annotation has no Gateway API equivalent and were dropped:'),
  ).toBeTruthy()
  expect(screen.getByText('nginx.kubernetes.io/limit-rps')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Apply' })).toBeTruthy()
})

// converter-convert-error-surface
test('converter-convert-error-surface', async () => {
  selectProd()
  server.use(
    http.post('*/api/v1/clusters/1/gateway-api/convert', () =>
      HttpResponse.json({ error: { code: 'RBAC_DENIED', message: 'get on ingresses' } }, { status: 403 }),
    ),
  )
  renderAt(<GatewayConverter name="web" namespace="team-a" />)
  fireEvent.click(screen.getByRole('button', { name: 'Convert' }))
  await screen.findByText('RBAC_DENIED: get on ingresses')
  expect(screen.queryByRole('button', { name: 'Apply' })).toBeNull()
})

// converter-apply-shows-per-object-result (partial failure: one created, one error)
test('converter-apply-shows-per-object-result', async () => {
  selectProd()
  server.use(
    http.post('*/api/v1/clusters/1/gateway-api/convert', () =>
      HttpResponse.json(convertFixture),
    ),
    http.post('*/api/v1/clusters/1/resources/apply', () =>
      HttpResponse.json({
        applied: [{ kind: 'GatewayClass', name: 'eg', namespace: null, status: 'created' }],
        errors: [{ kind: 'Gateway', name: 'web-eg', message: 'namespace not found' }],
      }),
    ),
  )
  renderAt(<GatewayConverter name="web" namespace="team-a" />)
  fireEvent.click(screen.getByRole('button', { name: 'Convert' }))
  await screen.findByText('Gateway web-eg')
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
  await screen.findByText('GatewayClass eg: created')
  expect(screen.getByText('Gateway web-eg: namespace not found')).toBeTruthy()
})

// converter-apply-invalidates-gateway-api-tab-queries: an active query keyed
// ['gateway-api', ...] (the tabs' key prefix) re-fetches after a successful
// apply — the applied resources appear without a manual refresh.
test('converter-apply-invalidates-gateway-api-tab-queries', async () => {
  selectProd()
  const fetches: number[] = []
  server.use(
    http.post('*/api/v1/clusters/1/gateway-api/convert', () =>
      HttpResponse.json(convertFixture),
    ),
    http.post('*/api/v1/clusters/1/resources/apply', () =>
      HttpResponse.json({
        applied: [
          { kind: 'GatewayClass', name: 'eg', namespace: null, status: 'created' },
          { kind: 'Gateway', name: 'web-eg', namespace: 'team-a', status: 'created' },
        ],
        errors: [],
      }),
    ),
    http.get('*/api/v1/clusters/1/resources/gateways', () => {
      fetches.push(1)
      return HttpResponse.json({ kind: 'gateways', items: [] })
    }),
  )
  // The probe observes the tabs' key prefix — the same query the Gateway API
  // tabs register.
  const Probe = () => {
    useQuery({
      queryKey: ['gateway-api', 'gateways', 1],
      queryFn: async () => {
        const r = await apiFetch('/api/v1/clusters/1/resources/gateways?namespace=team-a')
        if (r.error) throw new Error(r.error.code)
        return r.data
      },
    })
    return <span>probe</span>
  }
  renderAt(
    <>
      <Probe />
      <GatewayConverter name="web" namespace="team-a" />
    </>,
  )
  // Initial fetch (the probe is active on mount).
  await waitFor(() => expect(fetches.length).toBe(1))
  fireEvent.click(screen.getByRole('button', { name: 'Convert' }))
  await screen.findByText('Gateway web-eg')
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
  await screen.findByText('Gateway web-eg: created')
  // The invalidation re-fetches the active ['gateway-api', ...] query.
  await waitFor(() => expect(fetches.length).toBeGreaterThanOrEqual(2))
})
