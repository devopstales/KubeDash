import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PriorityClassView from '../../src/views/OtherResource/PriorityClass'
import PriorityClassDataView from '../../src/views/OtherResource/PriorityClassData'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// name comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path: string, name?: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/priorityclass"
            element={
              <ObjectRoute
                kind="priorityclass"
                listRoute="/other-resource/priorityclass"
                list={<PriorityClassView />}
                detail={(p) => <PriorityClassDataView name={p.name} />}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's name now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind: 'priorityclass', name, ts: Date.now(), origin: 'click' } }),
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

// kubernetes to_dict shape: snake_case. Cluster-scoped — no namespace field.
const high = {
  apiVersion: 'scheduling.k8s.io/v1',
  kind: 'PriorityClass',
  metadata: {
    name: 'high',
    creation_timestamp: '2026-10-26T10:00:00Z',
    labels: { env: 'prod' },
    annotations: { note: 'kept for upgrades' },
  },
  value: 1000,
  global_default: false,
  preemption_policy: 'PreemptLowerPriority',
  description: 'High priority',
}

// detail-renders-priority-class-yaml
test('detail-renders-priority-class-yaml', async () => {
  let searchParams = new URLSearchParams()
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/priorityclasses', ({ request }) => {
      const u = new URL(request.url)
      searchParams = u.searchParams
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'priorityclasses',
        cluster: 'prod',
        items: [high],
      })
    }),
  )
  selectProd()
  // ADR-0040: the detail is ref-driven — seed the active ref, render at the
  // clean route, and assert the URL stays clean (R1).
  seedActiveRef('high')
  const { container } = renderAt(<PriorityClassDataView name="high" />, '/other-resource/priorityclass')

  // R1: the URL never carries identity.
  expect(window.location.search).toBe('')
  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('preemption_policy')
  })
  // single read: EXACTLY the cluster-scoped ?name= URL (no list, no dispatch).
  expect(searchParams.get('name')).toBe('high')
  // cluster-scoped: the fetched URL has no namespace substring at all
  // (the kind is cluster-scoped; the list URL and the data link carry none).
  expect(requestedUrl).not.toContain('namespace')
  expect(searchParams.get('namespace')).toBeNull()
  // breadcrumb: Other Resources → Priority Classes → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Priority Classes' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/priorityclass')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the YAML block below, so scope to the metadata table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('1000')).toBe(true)
  expect(await inTable('PreemptLowerPriority')).toBe(true)
  expect(await inTable('false')).toBe(true)
  expect(await inTable('High priority')).toBe(true)
  // labels/annotations render. The keys `env`/`note` are unique; the label
  // VALUE `prod` also appears in the breadcrumb cluster + YAML block, so
  // assert its presence rather than uniqueness.
  expect(await inTable('env')).toBe(true)
  expect(await inTable('note')).toBe(true)
  expect(screen.getAllByText('prod').length).toBeGreaterThanOrEqual(1)
  // the full object is rendered as highlighted YAML containing the class name.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('high')
  expect(pre!.textContent).toContain('preemption_policy')
})

// detail-not-found-state
test('detail-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/priorityclasses', () =>
      HttpResponse.json({ kind: 'priorityclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost')
  const { container } = renderAt(<PriorityClassDataView name="ghost" />, '/other-resource/priorityclass')

  // R1: the URL stays clean even for a not-found object.
  expect(window.location.search).toBe('')
  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No PriorityClass 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

// ADR-0040: with no active ref, ObjectRoute renders the list (not the
// detail), so the missing-name error state is unreachable through the route
// (R6). The data view itself still guards an empty name for the legacy
// /data route (TICKET-07 keeps it working until the contract pass).
test('data-view-empty-name-client-error', async () => {
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
        <PriorityClassDataView name="" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: priority class name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})

test('detail-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  seedActiveRef('high')
  renderAt(<PriorityClassDataView name="high" />, '/other-resource/priorityclass')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
