/**
 * HA Status view (spec 2026-11-10-ha-status-page, /settings/cluster-status).
 *
 * MSW fixtures mirror the backend `HaStatusOut` shape: healthy, a down
 * cluster (n2 unreachable — the page degrades, it does not crash), a
 * no-leader election (degraded), the API-error banner, and the non-admin
 * route gate.
 *
 * The page-level HA banner (acceptance R5) leads the grid: "HA <status>"
 * + every reason; the node and section cards carry the per-section detail.
 */
import { render, screen, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import ClusterStatusView from '../../src/views/ClusterStatus'
import ClusterStatusCard from '../../src/views/ClusterStatus/ClusterStatusCard'
import { AdminRoute } from '../../src/routes'
import type { HaNode, HaReport } from '../../src/views/ClusterStatus/types'

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
  renew_at: '2026-11-11 09:59:59',
  lease_duration_s: 10,
  candidates: 2,
}

const QUEUE = {
  pending: 1,
  processing: 0,
  done: 12,
  failed: 0,
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
  warnings: [],
}

const DOWN_N2: HaReport = {
  ...HEALTHY,
  nodes: [NODE_N1, { ...NODE_N2_LOCK, reachable: false, probe_error: 'connection_refused' }],
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
  server.use(http.get('*/api/v1/admin/ha-status', () => HttpResponse.json(report)))

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

  test('healthy-report-renders-node-cards-leader-queue', async () => {
    withHandlers(HEALTHY)
    renderView()

    // page-level HA banner (acceptance R5): overall status, no reasons
    expect(await screen.findByText(/HA healthy/)).toBeTruthy()
    expect(await screen.findByText('Leader Election')).toBeTruthy()
    // one card per node
    expect(screen.getByText('n1')).toBeTruthy()
    expect(screen.getByText('n2')).toBeTruthy()
    // replication chip + dsns (host:port only, no credentials)
    expect(screen.getByText('n2_to_n1: replicating')).toBeTruthy()
    expect(screen.getByText('localhost:16433')).toBeTruthy()
    // every node card states the lock either way (n1 does not hold it)
    expect(screen.getByText('not held here')).toBeTruthy()
    expect(screen.getByText(/held here \(pid 7899, idle\)/)).toBeTruthy()
    // leader election section
    expect(screen.getByText('replica-1')).toBeTruthy()
    expect(screen.getByText('held on n2 (pid 7899, idle)')).toBeTruthy()
    // the lease object's own fields (Kubernetes Lease vocabulary)
    expect(screen.getByText('2026-11-11 09:00:00')).toBeTruthy()
    expect(screen.getByText('2026-11-11 09:59:59')).toBeTruthy()
    expect(screen.getByText('10 s')).toBeTruthy()
    // the KubeDash replica count (Deployment spec.replicas) is explicit
    expect(screen.getByText('KubeDash replicas')).toBeTruthy()
    expect(screen.getByText(/1 leader of 2/)).toBeTruthy()
    expect(screen.getByText('healthy')).toBeTruthy()
    // queue section (counts by status, including the dead-letter count)
    expect(screen.getByText('Task Queue')).toBeTruthy()
    expect(screen.getByText('12')).toBeTruthy()
    expect(screen.getByText('Failed')).toBeTruthy()
    // no reasons on a healthy banner
    expect(screen.queryByText(/node_unreachable/)).toBeNull()
  })

  test('down-report-renders-reason-and-unreachable-node', async () => {
    withHandlers(DOWN_N2)
    renderView()

    // page-level banner (acceptance R5): status + the reason, node-named
    expect(await screen.findByText(/HA down/)).toBeTruthy()
    expect(screen.getByText(/node_unreachable:n2/)).toBeTruthy()
    expect(await screen.findByText('Unreachable — connection_refused')).toBeTruthy()
    // the reachable node still renders its data; the healthy section shows
    // healthy inside its own card (the banner reason is overall-status)
    expect(screen.getByText('n2_to_n1: replicating')).toBeTruthy()
    // replica count: the fixture reports null (no Deployment read) -> the
    // configured fallback is what the backend sends instead
    expect(screen.getByText('KubeDash replicas')).toBeTruthy()
  })

  test('no-leader-renders-degraded-banner-with-reasons', async () => {
    withHandlers(NO_LEADER)
    renderView()

    // the page-level banner carries the overall status + every reason
    expect(await screen.findByText(/HA degraded/)).toBeTruthy()
    expect(screen.getByText('leader_heartbeat_stale, no_leader')).toBeTruthy()
    // the election card still carries the section state
    expect(screen.getByText('degraded')).toBeTruthy()
  })

  test('api-error-renders-unavailable-banner', async () => {
    server.use(
      http.get('*/api/v1/admin/ha-status', () =>
        HttpResponse.json({ error: { code: 'INTERNAL_ERROR', message: 'boom' } }, { status: 500 }),
      ),
    )
    renderView()

    expect(await screen.findByText(/Cluster status unavailable/)).toBeTruthy()
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
    expect(screen.queryByText('Leader Election')).toBeNull()
  })

  test('transient-refetch-failure-keeps-the-last-good-report', async () => {
    // W049f: a 500 on a LATER poll must not hide the report the page
    // already showed — the grid stays, a stale-data banner appears.
    let fail = false
    server.use(
      http.get('*/api/v1/admin/ha-status', () =>
        fail
          ? HttpResponse.json(
              { error: { code: 'INTERNAL_ERROR', message: 'boom' } },
              { status: 500 },
            )
          : HttpResponse.json(HEALTHY),
      ),
    )
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/settings/cluster-status']}>
          <Routes>
            <Route path="/settings/cluster-status" element={<ClusterStatusView />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByText(/HA healthy/)).toBeTruthy()

    fail = true
    await act(async () => {
      await qc.invalidateQueries()
    })

    expect(await screen.findByText(/last good report/)).toBeTruthy()
    // the grid is still rendered, not replaced by the error banner
    expect(screen.getByText('n1')).toBeTruthy()
    expect(screen.queryByText(/Cluster status unavailable/)).toBeNull()
  })

  test('tables-use-row-scoped-headers-and-the-banner-is-a-live-region', async () => {
    // W048: KV tables carry th scope=row labels; the page banner is a
    // polite live region so 5 s in-place updates are announced.
    withHandlers(HEALTHY)
    const { container } = renderView()
    expect(await screen.findByText(/HA healthy/)).toBeTruthy()
    expect(container.querySelectorAll('th[scope="row"]').length).toBeGreaterThanOrEqual(13)
    expect(screen.getByRole('status')).toBeTruthy()
  })

  test('stale-heartbeat-gets-a-text-marker-not-color-only', async () => {
    // W048: NO_LEADER carries heartbeat_age_s 15.2 (> the 10 s stale
    // threshold) — the stale state must not be color-only.
    withHandlers(NO_LEADER)
    renderView()
    expect(await screen.findByText(/HA degraded/)).toBeTruthy()
    expect(screen.getByText('15.2 s')).toBeTruthy()
    expect(screen.getByText('(stale)')).toBeTruthy()
  })

  test('config-warnings-render-below-the-banner', async () => {
    // W049d: a typo'd node_dsn_overrides name surfaces as a report
    // warning the page renders (not silently dropped config).
    withHandlers({
      ...HEALTHY,
      warnings: ["node_dsn_overrides: unknown node name 'typo' (not in spock.node)"],
    })
    renderView()
    expect(await screen.findByText(/HA healthy/)).toBeTruthy()
    expect(screen.getByText(/unknown node name 'typo'/)).toBeTruthy()
  })
})

describe('ClusterStatusCard lag boundary (W049e)', () => {
  // Every view fixture carries lag_bytes 0 — the KiB/MiB branch was
  // unobserved. Pin it at the boundary and around it.
  const withLag = (bytes: number): HaNode => ({
    ...NODE_N1,
    lag_bytes: bytes,
    lag_interval_s: 1.0,
  })

  test.each([
    [0, '—'],
    [512_000, '500.0 KiB'],
    [1_048_576, '1.0 MiB'], // exactly the KiB->MiB boundary
    [5_242_880, '5.0 MiB'],
  ])('lag %i renders %s', (bytes, expected) => {
    render(<ClusterStatusCard node={withLag(bytes)} />)
    expect(screen.getByText(new RegExp(expected))).toBeTruthy()
  })
})
