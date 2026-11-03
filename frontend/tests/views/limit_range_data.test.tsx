import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import LimitRangeDataView from '../../src/views/OtherResource/LimitRangeData'
import LimitRangeView from '../../src/views/OtherResource/LimitRange'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
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

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string, namespace: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({
      [token]: { kind: 'limitrange', name, namespace, ts: Date.now(), origin: 'click' },
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

// kubernetes to_dict renders `defaultRequest`/`maxLimitRequestRatio` in
// snake_case (default_request / max_limit_request_ratio) — the view reads
// the to_dict keys, so the fixture mirrors the API's actual serialization.
const limitsSnake = {
  ...limits,
  spec: {
    limits: [
      {
        type: 'Container',
        max: { cpu: '2', memory: '4Gi' },
        min: { cpu: '500m', memory: '1Gi' },
        default: { cpu: '1', memory: '2Gi' },
        default_request: { cpu: '250m', memory: '512Mi' },
        max_limit_request_ratio: { cpu: '2', memory: '4' },
      },
    ],
  },
}

// data-renders-detail
test('data-renders-detail', async () => {
  const urls: string[] = []
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', ({ request }) => {
      const u = new URL(request.url)
      urls.push(u.href)
      searchParams = u.searchParams
      return HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [limitsSnake] })
    }),
  )
  selectProd()
  seedActiveRef('default', 'team-a')
  const { container } = renderAt(<LimitRangeDataView name="default" namespace="team-a" />)

  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('"kind": "LimitRange"')
  })
  // single read: EXACTLY ONE fetch, with ?name= AND ?namespace=.
  expect(urls).toHaveLength(1)
  expect(searchParams.get('name')).toBe('default')
  expect(searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Other Resources → Limit Ranges → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Limit Ranges' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/limit-range')
  // metadata table rows: Name, Namespace, Kind, Created. The same values
  // repeat in the JSON block below, so scope to the metadata table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('default')).toBe(true)
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('LimitRange')).toBe(true)
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row
  // (mirrors resource_quota_data.test.tsx; the JSON block keeps the raw
  // timestamp but it is not a table cell).
  const createdCells = (await screen.findAllByText(/2026/)).filter((el) => el.closest('table'))
  expect(createdCells.length).toBeGreaterThanOrEqual(1)
  expect(createdCells[0].textContent).not.toContain('T03:04:05Z')
  // labels sub-table: the `app` key and `limits` value render.
  expect(await inTable('app')).toBe(true)
  expect(await inTable('limits')).toBe(true)
  // absent annotations → the pinned empty copy.
  expect(await screen.findByText('No annotations')).toBeTruthy()
  // the full object is rendered as a JSON-highlighted block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"kind": "LimitRange"')
})

// R8: the detail's namespace comes from the ref (authoritatively), never
// from the header store. Header on `default`, ref for `team-a` → the read
// is for `team-a`.
test('data-reads-the-ref-namespace-not-the-header', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [limitsSnake] })
    }),
  )
  // header selectedNamespace = 'default' (NOT team-a)
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'default' })
  // the ref (and the detail's namespace prop) is team-a
  seedActiveRef('default', 'team-a')
  renderAt(<LimitRangeDataView name="default" namespace="team-a" />)

  expect(await screen.findByText('Limit Range Data')).toBeTruthy()
  expect(requested).toBe('team-a')
  // the namespace row shows the ref's namespace, not the header's (`default`
  // must not appear as the namespace value).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
})

// data-limits-table
test('data-limits-table', async () => {
  // The data view fetches ONE name; to exercise the absent-field cells,
  // serve a single item whose second limits entry (type Pod) has only
  // max.cpu — its remaining columns must render None (4.1's pinned copy).
  const twoEntries = {
    ...limitsSnake,
    spec: {
      limits: [
        ...limitsSnake.spec.limits,
        { type: 'Pod', max: { cpu: '4' } },
      ],
    },
  }
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [twoEntries] }),
    ),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('default', 'team-a')
  const { container } = renderAt(<LimitRangeDataView name="default" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('Container Limits')
  })
  // the Container Limits table renders the entry's `type` as Resource with
  // the cpu / memory pairs (4.1 parity).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('Container')).toBe(true)
  expect(await inTable('500m / 1Gi')).toBe(true)
  expect(await inTable('2 / 4Gi')).toBe(true)
  expect(await inTable('1 / 2Gi')).toBe(true)
  expect(await inTable('250m / 512Mi')).toBe(true)
  expect(await inTable('2 / 4')).toBe(true)
  // the Pod entry's absent fields render None (4.1's pinned copy):
  // min/default/default_request/max_limit_request_ratio are all absent.
  // The Pod row carries 4 `None` cells next to its `4` maximum.
  const podRow = [...container.querySelectorAll('tr')].find((tr) =>
    tr.textContent?.includes('Pod'),
  )
  expect(podRow?.textContent).toContain('4')
  expect(podRow?.textContent).toContain('None')
})

// data-limits-absent
test('data-limits-absent', async () => {
  const noLimits = {
    apiVersion: 'v1',
    kind: 'LimitRange',
    metadata: { name: 'default', namespace: 'team-a' },
    spec: {},
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [noLimits] }),
    ),
  )
  selectProd()
  seedActiveRef('default', 'team-a')
  const { container } = renderAt(<LimitRangeDataView name="default" namespace="team-a" />)

  // an empty limits spec renders no limit rows — not an error.
  await waitFor(() => {
    expect(container.textContent).toContain('"kind": "LimitRange"')
  })
  expect(container.textContent).not.toContain('Error')
})

// data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/limitranges', () =>
      HttpResponse.json({ kind: 'limitranges', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<LimitRangeDataView name="default" namespace="team-a" />)

  // empty items upstream is a state, not an error: pinned copy, muted, no
  // error styling.
  expect(await screen.findByText("No LimitRange 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
  expect(container.querySelectorAll('.text-danger').length).toBe(0)
})

// data-missing-name
test('data-missing-name', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <LimitRangeDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: limit range name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
