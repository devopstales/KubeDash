import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import DashboardView from '../../src/views/Cluster/Dashboard'
import { useClusterStore } from '../../src/store/cluster'

// ponytail: the dashboard test asserts structure and the certainty rule,
// not chart pixels — so ConcentricDonut is stubbed to render its `used`
// prop (null → "unknown") as DOM text. The donut's own canvas behavior
// (rings, center text, overflow bar, themes) stays covered in
// tests/components/ConcentricDonut.test.tsx. KubeDataTable is mocked to a
// plain table so row-order assertions are stable; the real DataTables init
// (CoreUI, ADR-0023) is out of scope here.
vi.mock('../../src/components/ConcentricDonut', () => ({
  default: ({
    used,
    label,
    ariaLabel,
  }: {
    used: number | null
    label?: string
    ariaLabel: string
  }) => (
    <div aria-label={ariaLabel} data-testid="donut" role="img">
      {label ? `${label}: ` : ''}
      {used === null ? 'unknown' : `${used}`}
    </div>
  ),
}))

vi.mock('../../src/components/KubeDataTable', () => {
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const columns = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (
            child as React.ReactElement<{ title: string; data?: string | null }>
          ).props,
      )
    return (
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.title}>{column.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column.title}>{row[column.data!] as React.ReactNode}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

const SUMMARY_OK = {
  cluster: 'prod',
  metrics_available: true,
  cpu: { capacity_millicores: 4000, used_millicores: 800, requests_millicores: 2000, limits_millicores: 0 },
  memory: { capacity_bytes: 8589934592, used_bytes: 4294967296, requests_bytes: 2147483648, limits_bytes: 0 },
  pods: { capacity: 110, running: 10, pending: 2, completed: 1 },
}

const EVENTS = [
  {
    type: 'Warning',
    reason: 'BackOff',
    involved_object: { kind: 'Pod', name: 'api-abc', namespace: 'default' },
    message: 'Back-off restarting failed container',
    count: 3,
    last_timestamp: '2026-10-22T10:00:00Z',
  },
  {
    type: 'Normal',
    reason: 'Scheduled',
    involved_object: { kind: 'Pod', name: 'web-xyz', namespace: 'team-a' },
    message: 'Successfully assigned team-a/web-xyz to node-1',
    count: 1,
    last_timestamp: '2026-10-22T09:00:00Z',
  },
]

const renderDashboard = (
  handlers: Parameters<typeof server.use>[0][] = [],
  cluster: { id: number; name: string } | null = { id: 1, name: 'prod' },
) => {
  useClusterStore.setState({ selectedCluster: cluster, selectedNamespace: null })
  // ponytail: MSW 3.0.3 serves a request that lands before any server.use()
  // override has ever been registered as 'fetch failed' — the afterEach
  // resetHandlers() in msw.ts clears the initial handler array, so the
  // default handlers only take effect once an override round-trip has
  // happened. Existing tests never hit this because they all call
  // server.use() first. Seed a no-op so the defaults are live.
  if (handlers.length > 0) {
    server.use(...handlers)
  } else {
    server.use(http.get('*/api/v1/no-op', () => HttpResponse.json(null)))
  }
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <DashboardView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  localStorage.setItem('kd_token', 'test-token')
})

afterEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('dashboard-renders-rows: summary + events → donut row and events table, newest-first as-is', async () => {
  renderDashboard()

  // Row 1: the three donut cards (CPU/Pemory are ConcentricDonut, Pods is a
  // stat list in its own card — no used/requests/limits to ring).
  expect(await screen.findByRole('img', { name: /CPU/i })).toBeTruthy()
  expect(screen.getByRole('img', { name: /Memory/i })).toBeTruthy()
  expect(screen.getByText('Pods')).toBeTruthy()

  // Row 2: the events table renders the endpoint's newest-first order as-is.
  const table = await screen.findByRole('table')
  const rows = Array.from(table.querySelectorAll('tbody tr'))
  expect(rows.length).toBe(2)
  expect(rows[0].textContent).toContain('BackOff')
  expect(rows[0].textContent).toContain('api-abc')
  expect(rows[1].textContent).toContain('Scheduled')

  // The flat endpoint list has no total — no "N newest of M" footer.
  expect(screen.queryByText(/newest of/i)).toBeNull()

  expect(screen.queryByText(/live/i)).toBeNull()
})

test('dashboard-unknown-used: metrics_available false → used unknown, declared state still renders', async () => {
  const summary = {
    ...SUMMARY_OK,
    metrics_available: false,
    cpu: { ...SUMMARY_OK.cpu, used_millicores: null },
    memory: { ...SUMMARY_OK.memory, used_bytes: null },
  }
  renderDashboard([
    http.get('http://localhost/api/v1/clusters/1/metrics/summary', () =>
      HttpResponse.json(summary),
    ),
    http.get('http://localhost/api/v1/clusters/1/events', () => HttpResponse.json(EVENTS)),
  ])

  // Certainty rule: null used renders "unknown", never "0" and never a healthy tone.
  await screen.findByRole('img', { name: /CPU/i })
  expect(screen.getByRole('img', { name: /CPU/i }).textContent).toContain('unknown')
  expect(screen.getByRole('img', { name: /Memory/i }).textContent).toContain('unknown')
  expect(screen.queryByText('0:')).toBeNull()
})

test('dashboard-metrics-404-unknown: 404 from either endpoint → unknown, no red error', async () => {
  // Version skew (AGENTS.md): new frontend on an old backend — the route 404s.
  // A 404 is an EXPECTED state, not an error: used renders unknown.
  renderDashboard([
    http.get('http://localhost/api/v1/clusters/1/metrics/summary', () =>
      HttpResponse.json({ error: { code: 'NOT_FOUND', message: 'not found' } }, { status: 404 }),
    ),
    http.get('http://localhost/api/v1/clusters/1/events', () =>
      HttpResponse.json({ error: { code: 'NOT_FOUND', message: 'not found' } }, { status: 404 }),
    ),
  ])

  await screen.findByRole('img', { name: /CPU/i })
  expect(screen.getByRole('img', { name: /CPU/i }).textContent).toContain('unknown')
  expect(screen.getByRole('img', { name: /Memory/i }).textContent).toContain('unknown')
  // The pods counts come from the same summary — unknown, not a healthy 0.
  expect(screen.queryByText(/error/i)).toBeNull()
  await waitFor(() => expect(screen.queryByText(/not found/i)).toBeNull())
})

test('dashboard-events-404-unknown: events 404 alone → no red error on the events row', async () => {
  renderDashboard([
    http.get('http://localhost/api/v1/clusters/1/metrics/summary', () =>
      HttpResponse.json(SUMMARY_OK),
    ),
    http.get('http://localhost/api/v1/clusters/1/events', () =>
      HttpResponse.json({ error: { code: 'NOT_FOUND', message: 'not found' } }, { status: 404 }),
    ),
  ])

  await screen.findByRole('img', { name: /CPU/i })
  // Events 404: no table, no red error.
  expect(screen.queryByRole('table')).toBeNull()
  expect(screen.queryByText(/error/i)).toBeNull()
  // Summary still rendered — metrics are unaffected by the events 404.
  expect(screen.getByRole('img', { name: /CPU/i }).textContent).toContain('800')
})

test('dashboard-no-cluster: no cluster selected → message, no donuts', async () => {
  renderDashboard([], null)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(screen.queryByRole('img', { name: /CPU/i })).toBeNull()
  expect(screen.queryByRole('img', { name: /Memory/i })).toBeNull()
  expect(screen.queryByRole('img', { name: /Pods/i })).toBeNull()
})
