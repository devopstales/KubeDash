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
import IngressClassDataView from '../../src/views/Network/IngressClassData'
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
                kind="ingressclass"
                listRoute="/network/ingress-class"
                list={<IngressClassView />}
                detail={(p) => <IngressClassDataView name={p.name} />}
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

// kubernetes to_dict shape: snake_case. Cluster-scoped — no namespace field.
const nginxClass = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'IngressClass',
  metadata: {
    name: 'nginx',
    creation_timestamp: '2026-10-26T10:00:00Z',
  },
  spec: {
    controller: 'k8s.io/ingress-nginx',
    parameters: { api_version: 'networking.k8s.io/v1', kind: 'Parameters', name: 'params' },
  },
}

// list-renders-ingress-classes
test('list-renders-ingress-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'ingressclasses',
        cluster: 'prod',
        items: [nginxClass],
      })
    }),
  )
  selectProd()
  renderAt(<IngressClassView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'nginx' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/ingressclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'IngressClass List' })).toBeTruthy()
  // breadcrumb: Network → IngressClass List.
  expect(screen.getByText('Network')).toBeTruthy()
  // columns: name, controller, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Controller',
    'Created',
  ])
  // row: controller rendered from spec.controller.
  expect(screen.getByText('k8s.io/ingress-nginx')).toBeTruthy()
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-10-26T10:00:00Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
      HttpResponse.json({ kind: 'ingressclasses', cluster: 'prod', items: [nginxClass] }),
    ),
  )
  renderAt(<IngressClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'nginx' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('IngressClass Data')).toBeTruthy()
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
    http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on ingressclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<IngressClassView />)

  expect(
    await screen.findByText(/Error loading ingress classes: RBAC_DENIED: list on ingressclasses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'nginx' })).toHaveLength(0)
})

// list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
      HttpResponse.json({ kind: 'ingressclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<IngressClassView />)

  expect(await screen.findByText('No ingress classes found')).toBeTruthy()
})
