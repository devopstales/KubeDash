import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PriorityClassView from '../../src/views/OtherResource/PriorityClass'
import PriorityClassDataView from '../../src/views/OtherResource/PriorityClassData'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as secrets.test.tsx: renders the real row
// mapping (children-as-render-fns included) so cell assertions test the
// view's `toRow` output, not DataTables' DOM. The factory is async: a
// hoisted mock may not touch module-scope consts, so react is imported
// inline (`vi.mock` calls are hoisted above the imports below).
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = (await import('react')) as typeof import('react')
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (
            child as React.ReactElement<{
              title: string
              data: string | null
              children?: unknown
            }>
          ).props,
      )
    return (
      <table>
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col.title}>{col.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i}>
              {cols.map((col) => {
                // `data={null}` hands the render fn the whole row (the
                // datatables.net-react contract, see Namespaces.tsx).
                const value = col.data === null ? row : row[col.data]
                const node =
                  typeof col.children === 'function'
                    ? (col.children as (v: unknown) => React.ReactNode)(value)
                    : (value as React.ReactNode)
                return <td key={col.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/other-resource/priorityclass') => {
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
  },
  value: 1000,
  global_default: false,
  preemption_policy: 'PreemptLowerPriority',
  description: 'High priority',
}

// list-renders-priority-classes
test('list-renders-priority-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/priorityclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'priorityclasses',
        cluster: 'prod',
        items: [high],
      })
    }),
  )
  selectProd()
  renderAt(<PriorityClassView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'high' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/priorityclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Priority Classes' })).toBeTruthy()
  // breadcrumb: Other Resources → Priority Classes.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: name, value, preemption policy, global default, description, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Value',
    'Preemption Policy',
    'Global Default',
    'Description',
    'Created',
  ])
  // row: value, preemption policy, global default, description.
  expect(screen.getByText('1000')).toBeTruthy()
  expect(screen.getByText('PreemptLowerPriority')).toBeTruthy()
  expect(screen.getByText('false')).toBeTruthy()
  expect(screen.getByText('High priority')).toBeTruthy()
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-10-26T10:00:00Z')
  expect(nameCell?.textContent).toMatch(/2026/)
  // ADR-0040: the share button is in the name cell (row affordance).
  expect(screen.getByRole('button', { name: 'Share high' })).toBeTruthy()
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/priorityclasses', () =>
      HttpResponse.json({ kind: 'priorityclasses', cluster: 'prod', items: [high] }),
    ),
  )
  renderAt(<PriorityClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'high' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('Priority Class Data')).toBeTruthy()
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
  renderAt(<PriorityClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/priorityclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on priorityclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<PriorityClassView />)

  expect(
    await screen.findByText(/Error loading priority classes: RBAC_DENIED: list on priorityclasses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'high' })).toHaveLength(0)
})
