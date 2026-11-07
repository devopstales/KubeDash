import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import LimitRangeView from '../../src/views/OtherResource/LimitRange'
import LimitRangeDataView from '../../src/views/OtherResource/LimitRangeData'
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
const renderAt = (_ui: ReactElement, path = '/other-resource/limit-range') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/limit-range"
            element={
              <ObjectRoute
                kind="limitrange"
                listRoute="/other-resource/limit-range"
                list={<LimitRangeView />}
                detail={(p) => (<LimitRangeDataView name={p.name} namespace={p.namespace ?? ''} />)}
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

// kubernetes to_dict shape: snake_case. Namespaced (core group).
const limits = {
  apiVersion: 'v1',
  kind: 'LimitRange',
  metadata: {
    name: 'default',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { app: 'limits' },
  },
  spec: {
    limits: [
      {
        type: 'Container',
        max: { cpu: '2', memory: '4Gi' },
        min: { cpu: '500m', memory: '1Gi' },
        default: { cpu: '1', memory: '2Gi' },
        defaultRequest: { cpu: '250m', memory: '512Mi' },
        maxLimitRequestRatio: { cpu: '2', memory: '4' },
      },
    ],
  },
}

// list-renders-limit-ranges

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json({ items: [limits] }),
    ),
  )
  renderAt(<LimitRangeView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'default' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched) and the URL is
  // clean: no query string (R1).
  expect(await screen.findByText('Limit Range Data')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('list-renders-limit-ranges', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [limits] })
    }),
  )
  selectProd()
  renderAt(<LimitRangeView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL never
  // carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'default' })
  // namespaced kind: the fetch URL is EXACTLY the kind URL + the selected
  // namespace (the Secret/NetworkPolicy pattern).
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/limitranges')
  expect(requestedUrl).toBe(
    'http://localhost/api/v1/clusters/1/resources/limitranges?namespace=team-a',
  )

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Limit Ranges' })).toBeTruthy()
  // breadcrumb: Other Resources → Limit Ranges.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: name, namespace, created (4.1's exact list column set).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Created',
  ])
  // row: the namespace cell, and the created cell rendered by
  // formatTimestamp (no raw ISO 'T').
  expect(screen.getByText('team-a')).toBeTruthy()
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// list-namespace-falls-back-to-default
test('list-namespace-falls-back-to-default', async () => {
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', ({ request }) => {
      requestedUrl = new URL(request.url).href
      return HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: null,
  })
  renderAt(<LimitRangeView />)

  await screen.findByText('No limit ranges found')
  expect(requestedUrl).toBe('http://localhost/api/v1/clusters/1/resources/limitranges?namespace=default')
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
  renderAt(<LimitRangeView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on limitranges' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<LimitRangeView />)

  expect(
    await screen.findByText(/Error loading limit ranges: RBAC_DENIED: list on limitranges/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'default' })).toHaveLength(0)
})

// list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<LimitRangeView />)

  // an empty list is a first-class state, not an error.
  expect(await screen.findByText('No limit ranges found')).toBeTruthy()
})
