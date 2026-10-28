import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import PriorityClassDataView from '../../src/views/OtherResource/PriorityClassData'
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
  const { container } = renderAt(<PriorityClassDataView />, '/other-resource/priorityclass/data?name=high')

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
  const { container } = renderAt(<PriorityClassDataView />, '/other-resource/priorityclass/data?name=ghost')

  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No PriorityClass 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

// detail-missing-name-client-error
test('detail-missing-name-client-error', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  renderAt(<PriorityClassDataView />, '/other-resource/priorityclass/data')

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
  renderAt(<PriorityClassDataView />, '/other-resource/priorityclass/data?name=high')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
