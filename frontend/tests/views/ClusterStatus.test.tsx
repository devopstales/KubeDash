/**
 * HA Status view (spec 2026-11-10-ha-status-page, /settings/cluster-status).
 *
 * MSW fixtures mirror the backend `HaStatusOut` shape: healthy, a down
 * cluster (n2 unreachable — the page degrades, it does not crash), a
 * no-leader election (degraded), the API-error banner, and the non-admin
 * route gate.
 */
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import ClusterStatusView from '../../src/views/ClusterStatus'
import { AdminRoute } from '../../src/routes'
import type { HaReport } from '../../src/views/ClusterStatus/types'

const NODE_N1 = {
  name: 'n1',
  reachable: true,
  probe_error: null,
  sub_statuses: [{ name: 'n2_to_n1', status: 'replicating' }],
  lag_bytes: 0,
  lag_interval_s: 0,
  apply_workers: 1,
  workers_streaming: true,
  conflicts: 0,
  exceptions_pending: 0,
  lock_held_locally: false,
  lock_holder_pid: null,
  lock_holder_state: null,
  elapsed_ms: 4,
  dsn: 'kdpg-n1:5432',
}

const NODE_N2_LOCK = {
  ...NODE_N1,
  name: 'n2',
  // the receive direction INTO n2 (the only direction a node exposes)
  sub_statuses: [{ name: 'n1_to_n2', status: 'replicating' }],
  lock_held_locally: true,
  lock_holder_pid: 7899,
  lock_holder_state: 'idle',
  dsn: 'localhost:16433',
}

const LEADER_OK = {
  replica_id: 'replica-1',
  fence: 3,
  heartbeat_age_s: 0.4,
  lock_verdict: 'held on n2 (pid 7899, idle)',
  token: 'tok',
  acquired_at: '2026-11-11 09:00:00',
  candidates: 2,
}

const QUEUE = {
  pending: 1,
  processing: 0,
  done: 12,
  oldest_pending_at: '2026-11-11 09:59:00',
}

const HEALTHY: HaReport = {
  probed_at: '2026-11-11T10:00:00',
  spock_version: '5.0.1',
  nodes: [NODE_N1, NODE_N2_LOCK],
  leader: LEADER_OK,
  queue: QUEUE,
  status: 'healthy',
  reasons: [],
  database: { status: 'healthy', reasons: [] },
  election: { status: 'healthy', reasons: [] },
}

const DOWN_N2: HaReport = {
  ...HEALTHY,
  nodes: [
    NODE_N1,
    { ...NODE_N2_LOCK, reachable: false, probe_error: 'connection_refused' },
  ],
  leader: { ...LEADER_OK, candidates: null },
  status: 'down',
  reasons: ['node_unreachable:n2'],
  database: { status: 'down', reasons: ['node_unreachable:n2'] },
  election: { status: 'healthy', reasons: [] },
}

const NO_LEADER: HaReport = {
  ...HEALTHY,
  nodes: [NODE_N1, NODE_N2_LOCK],
  leader: {
    ...LEADER_OK,
    heartbeat_age_s: 15.2,
    lock_verdict: 'not seen on any reachable node',
  },
  status: 'degraded',
  reasons: ['leader_heartbeat_stale', 'no_leader'],
  database: { status: 'healthy', reasons: [] },
  election: { status: 'degraded', reasons: ['leader_heartbeat_stale', 'no_leader'] },
}

const withHandlers = (report: HaReport) =>
  server.use(
    http.get('*/api/v1/admin/ha-status', () => HttpResponse.json(report)),
  )

const renderView = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/settings/cluster-status']}>
        <Routes>
          <Route path="/settings/cluster-status" element={<ClusterStatusView />} />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const renderGate = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/settings/cluster-status']}>
        <Routes>
          <Route
            path="/settings/cluster-status"
            element={
              <AdminRoute>
                <ClusterStatusView />
              </AdminRoute>
            }
          />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ClusterStatusView', () => {
  beforeEach(() => {
    document.cookie = 'kd_session=1; path=/'
  })

  afterEach(() => {
    localStorage.clear()
  })

  test('healthy-report-renders-banner-cards-leader-queue', async () => {
    withHandlers(HEALTHY)
    renderView()

    expect(await screen.findByText('HA healthy')).toBeTruthy()
    // one card per node
    expect(screen.getByText('n1')).toBeTruthy()
    expect(screen.getByText('n2')).toBeTruthy()
    // replication chip + dsns (host:port only, no credentials)
    expect(screen.getByText('n2_to_n1: replicating')).toBeTruthy()
    expect(screen.getByText('localhost:16433')).toBeTruthy()
    // leader election section
    expect(screen.getByText('replica-1')).toBeTruthy()
    expect(screen.getByText('held on n2 (pid 7899, idle)')).toBeTruthy()
    expect(screen.getByText('1 leader of 2 candidates')).toBeTruthy()
    // queue section
    expect(screen.getByText('Task Queue')).toBeTruthy()
    expect(screen.getByText('12')).toBeTruthy()
    // no reasons on a healthy banner
    expect(screen.queryByText(/node_unreachable/)).toBeNull()
  })

  test('down-report-renders-reason-and-unreachable-node', async () => {
    withHandlers(DOWN_N2)
    renderView()

    expect(await screen.findByText('HA down')).toBeTruthy()
    expect(screen.getByText(/node_unreachable:n2/)).toBeTruthy()
    expect(
      screen.getByText('Unreachable — connection_refused'),
    ).toBeTruthy()
    // the reachable node still renders its data
    expect(screen.getByText('n2_to_n1: replicating')).toBeTruthy()
    // candidates null -> no candidates line
    expect(screen.queryByText(/candidates/i)).toBeNull()
  })

  test('no-leader-renders-degraded-banner-with-reasons', async () => {
    withHandlers(NO_LEADER)
    renderView()

    expect(await screen.findByText('HA degraded')).toBeTruthy()
    expect(screen.getByText(/no_leader/)).toBeTruthy()
    expect(screen.getByText(/leader_heartbeat_stale/)).toBeTruthy()
  })

  test('api-error-renders-unavailable-banner', async () => {
    server.use(
      http.get('*/api/v1/admin/ha-status', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL_ERROR', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderView()

    expect(
      await screen.findByText(/Cluster status unavailable/),
    ).toBeTruthy()
  })

  test('non-admin-is-redirected-away', async () => {
    server.use(
      http.get('*/api/v1/auth/me', () =>
        HttpResponse.json({
          sub: 'u2',
          email: 'alice@example.com',
          display_name: 'Alice',
          groups: [],
          role: 'user',
        }),
      ),
    )
    renderGate()
    expect(await screen.findByText('Home page')).toBeTruthy()
    expect(screen.queryByText('HA healthy')).toBeNull()
  })
})
