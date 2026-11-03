import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PodDisruptionBudgetDataView from '../../src/views/OtherResource/PodDisruptionBudgetData'
import PodDisruptionBudgetView from '../../src/views/OtherResource/PodDisruptionBudget'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/other-resource/pod-disruption-budget') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/pod-disruption-budget"
            element={
              <ObjectRoute
                kind="poddisruptionbudget"
                listRoute="/other-resource/pod-disruption-budget"
                list={<PodDisruptionBudgetView />}
                detail={(p) => (<PodDisruptionBudgetDataView name={p.name} namespace={p.namespace ?? ''} />)}
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
      [token]: { kind: 'poddisruptionbudget', name, namespace, ts: Date.now(), origin: 'click' },
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

// kubernetes to_dict shape: snake_case, namespaced, policy/v1.
const web = {
  apiVersion: 'policy/v1',
  kind: 'PodDisruptionBudget',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'pdb.kubernetes.io/managed-by': 'kubedash' },
  },
  spec: {
    min_available: 3,
    selector: { match_labels: { app: 'web', tier: 'frontend' } },
    unhealthy_pod_eviction_policy: 'AlwaysAllow',
  },
  status: {
    observed_generation: 1,
    current_healthy: 4,
    desired: 3,
    total_pods: 4,
    expected_pods: 3,
    disruptions_allowed: 1,
    conditions: [
      {
        type: 'Available',
        status: 'True',
        reason: 'SufficientPods',
        message: 'PodDisruptionBudget is available',
      },
    ],
  },
}

// A fresh PDB has no status (the controller fills it); 4.1's Jinja would
// UndefinedError on `status.disruptions_allowed`.
const freshBudget = { ...web, status: undefined }

// pdb-data-renders-detail
test('data-renders-detail', async () => {
  let fetchCount = 0
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', ({ request }) => {
      fetchCount++
      const u = new URL(request.url)
      if (u.searchParams.get('name') !== 'web' || u.searchParams.get('namespace') !== 'team-a') {
        return HttpResponse.json({ error: { code: 'UNEXPECTED', message: u.href } }, { status: 500 })
      }
      return HttpResponse.json({ kind: 'poddisruptionbudgets', cluster: 'prod', items: [web] })
    }),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<PodDisruptionBudgetDataView name="web" namespace="team-a" />)

  // Wait for the fetch to land (the highlighter splits tokens across spans,
  // so poll the DOM text instead of findByText on a token).
  await waitFor(() => {
    expect(container.textContent).toContain('"min_available": 3')
  })
  // single read: EXACTLY the ?name=&namespace= URL.
  expect(fetchCount).toBe(1)
  // card title.
  expect(screen.getByText('Pod Disruption Budget Data')).toBeTruthy()
  // breadcrumb: Other Resources → Pod Disruption Budget List → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Pod Disruption Budget List' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/pod-disruption-budget')
  // CTable rows: Name / Namespace / Selector / labels / annotations. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('web')).toBe(true)
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('team')).toBe(true)
  expect(await inTable('pdb.kubernetes.io/managed-by')).toBe(true)
  expect(await inTable('kubedash')).toBe(true)
  // Selector: match_labels as `key: value` lines. The "key: value" is split
  // into multiple text nodes (key, ": ", value) so use the row's textContent.
  const rows = Array.from(document.querySelectorAll('tbody tr'))
  const selectorRow = rows.find((r) => r.textContent?.startsWith('Selector:'))
  expect(selectorRow?.textContent).toContain('app: web')
  expect(selectorRow?.textContent).toContain('tier: frontend')
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row.
  const createdCells = (await screen.findAllByText(/2026/)).filter((el) => el.closest('table'))
  expect(createdCells.length).toBeGreaterThanOrEqual(1)
  expect(createdCells[0].textContent).not.toContain('T03:04:05Z')
  // Status table (Key / Value): the controller-computed values.
  expect(await inTable('Allowed disruptions')).toBe(true)
  expect(await inTable('Current healthy')).toBe(true)
  expect(await inTable('Desired')).toBe(true)
  const statusTable = Array.from(document.querySelectorAll('table')).find((t) =>
    t.textContent?.includes('Allowed disruptions'),
  )
  expect(statusTable).toBeTruthy()
  const statusRows = Array.from(statusTable!.querySelectorAll('tbody tr')).map((r) =>
    Array.from(r.querySelectorAll('td')).map((td) => td.textContent),
  )
  expect(statusRows).toContainEqual(['Allowed disruptions', '1'])
  expect(statusRows).toContainEqual(['Current healthy', '4'])
  expect(statusRows).toContainEqual(['Desired', '3'])
  // Conditions table (Type / Status / Reason / Message): one row per
  // status condition.
  expect(await inTable('SufficientPods')).toBe(true)
  expect(await inTable('PodDisruptionBudget is available')).toBe(true)
  // the full object is rendered as a JSON-highlighted block (truthful
  // classifier: the block is JSON.stringify of the to_dict item).
  expect(container.textContent).toContain('"min_available": 3')
  expect(container.querySelector('pre')).not.toBeNull()
})

// pdb-data-selector-and-eviction-policy
test('data-selector-and-eviction-policy', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({ kind: 'poddisruptionbudgets', cluster: 'prod', items: [web] }),
    ),
  )
  selectProd()
  // Wait for the data to land (the card title renders during loading too,
  // so wait for a value that only appears after the fetch).
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<PodDisruptionBudgetDataView name="web" namespace="team-a" />)
  await waitFor(() => {
    expect(container.textContent).toContain('AlwaysAllow')
  })
  // the Selector row shows the match_labels as `key: value` lines (4.1 read
  // ONLY match_labels; the full selector is in the JSON block). "key: value"
  // splits across text nodes (the "key: " and value are separate nodes), so
  // check the row's textContent.
  const rows = Array.from(document.querySelectorAll('tbody tr'))
  const selectorRow = rows.find((r) => r.textContent?.startsWith('Selector:'))
  expect(selectorRow?.textContent).toContain('app: web')
  expect(selectorRow?.textContent).toContain('tier: frontend')
  // the Eviction Policy row shows spec.unhealthy_pod_eviction_policy as a
  // proper value (4.1's trailing-comma tuple bug is dropped).
  const evictionRow = rows.find((r) => r.textContent?.startsWith('Eviction Policy:'))
  expect(evictionRow?.textContent).toContain('AlwaysAllow')
})

// pdb-data-missing-status
test('data-missing-status', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({ kind: 'poddisruptionbudgets', cluster: 'prod', items: [freshBudget] }),
    ),
  )
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<PodDisruptionBudgetDataView name="web" namespace="team-a" />)

  // Wait for the fetch to land.
  await waitFor(() => {
    expect(container.textContent).toContain('"min_available": 3')
  })
  // certainty rule: a fresh PDB has no status; 4.1 would UndefinedError —
  // 5.0 renders "—" for all three Status rows, never throws.
  const statusTable = Array.from(document.querySelectorAll('table')).find((t) =>
    t.textContent?.includes('Allowed disruptions'),
  )
  expect(statusTable).toBeTruthy()
  const statusRows = Array.from(statusTable!.querySelectorAll('tbody tr')).map((r) =>
    Array.from(r.querySelectorAll('td')).map((td) => td.textContent),
  )
  expect(statusRows).toContainEqual(['Allowed disruptions', '—'])
  expect(statusRows).toContainEqual(['Current healthy', '—'])
  expect(statusRows).toContainEqual(['Desired', '—'])
  // no conditions either: the pinned copy, not an error.
  expect(container.textContent).toContain('No conditions')
})

// pdb-data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({ kind: 'poddisruptionbudgets', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<PodDisruptionBudgetDataView name="web" namespace="team-a" />)

  // empty items upstream is a STATE, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No PodDisruptionBudget 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// pdb-data-missing-name
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
        <PodDisruptionBudgetDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: pod disruption budget name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
