import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import IngressClassView from '../../src/views/Network/IngressClass'
import GatewayClassDataView from '../../src/views/Network/GatewayClassData'
import { useClusterStore } from '../../src/store/cluster'

// 2026-11-07 menu merge (ADR-0022 amendment): the standalone GatewayClass
// page is gone — GatewayClasses is a TAB of the tabbed Ingress Class page
// (IngressClasses | GatewayClasses). This file tests the tabbed page with
// the focus on the GatewayClasses tab; the old /network/gateway-class URL
// redirects to /network/ingress-class (App.tsx).

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/network/ingress-class') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/ingress-class"
            element={
              <ObjectRoute
                kind="gatewayclass"
                listRoute="/network/ingress-class"
                list={<IngressClassView />}
                detail={(p) => <GatewayClassDataView name={p.name} />}
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

// FULL custom object (camelCase — the CRD seam). Cluster-scoped — no
// namespace field. ~3 days old so the Age column is a stable '3d'.
const traefikClass = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'GatewayClass',
  metadata: {
    name: 'traefik',
    creationTimestamp: new Date(Date.now() - 3 * 86400 * 1000).toISOString(),
  },
  spec: {
    controllerName: 'traefik.io/gatewayclass',
    conditions: [{ type: 'Accepted', status: 'True', reason: 'Accepted', message: 'ok' }],
  },
}

// FULL kubernetes object (snake_case — the API seam) for the IngressClasses
// tab. A populated item makes the tab's table render (the KubeDataTable
// mock mounts no table for empty tabs).
const nginxClass = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'IngressClass',
  metadata: { name: 'nginx', creation_timestamp: '2026-10-26T10:00:00Z' },
  spec: { controller: 'k8s.io/ingress-nginx' },
}

// CTabPanel mounts both tabs, so every page-level test also serves the
// IngressClasses endpoint (unhandled → bypass → the other tab in error).
const ingressClassesHandler = (items: unknown[] = [nginxClass]) =>
  http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
    HttpResponse.json({ kind: 'ingressclasses', cluster: 'prod', items }),
  )

// list-renders-gateway-classes (the GatewayClasses tab of the merged page)
test('list-renders-gateway-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'gatewayclasses',
        cluster: 'prod',
        items: [traefikClass],
      })
    }),
    ingressClassesHandler(),
  )
  selectProd()
  renderAt(<IngressClassView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'traefik' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/gatewayclasses')
  expect(requestedUrl).not.toContain('namespace')

  // The merged page: card title 'IngressClass List' (the 5.0 `<Kind> List`
  // convention) + both tabs (CTab = button[role=tab]).
  expect(screen.getByRole('heading', { name: 'IngressClass List' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'IngressClasses' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'GatewayClasses' })).toBeTruthy()
  // breadcrumb: Network → IngressClass List.
  expect(screen.getByText('Network')).toBeTruthy()
  // columns, in tab order (both tables mounted): the IngressClasses tab
  // (Name/Controller/Created) then the GatewayClasses tab (Name/Controller/
  // Age).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Controller',
    'Created',
    'Name',
    'Controller',
    'Age',
  ])
  // row: controller rendered from spec.controllerName (camelCase CRD seam).
  expect(screen.getByText('traefik.io/gatewayclass')).toBeTruthy()
  // age: human-readable (the full timestamp lives in the data view + JSON).
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain(traefikClass.metadata.creationTimestamp)
  expect(nameCell?.textContent).toMatch(/3d/)
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [traefikClass] }),
    ),
    ingressClassesHandler(),
  )
  renderAt(<IngressClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'traefik' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('GatewayClass Data')).toBeTruthy()
  // The URL is clean: no query string (R1).
  expect(window.location.search).toBe('')
})

// list-no-cluster-state
test('list-no-cluster-state', async () => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderAt(<IngressClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on gatewayclasses' } },
        { status: 403 },
      ),
    ),
    ingressClassesHandler(),
  )
  selectProd()
  renderAt(<IngressClassView />)

  expect(
    await screen.findByText(/Error loading gateway classes: RBAC_DENIED: list on gatewayclasses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'traefik' })).toHaveLength(0)
})

// list-crd-absent-empty-state (the VPA absence contract: CRD not installed
// is the same pinned empty state as "none exist", never an error).
test('list-crd-absent-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [] }),
    ),
    ingressClassesHandler(),
  )
  selectProd()
  renderAt(<IngressClassView />)

  expect(await screen.findByText('No gateway classes found')).toBeTruthy()
})
