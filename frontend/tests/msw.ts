import { afterAll, afterEach, beforeAll } from 'vitest'
import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

/**
 * MSW node server for unit/component tests. Default handlers mirror the
 * backend v1 contract (see openapi.json) so views can render without
 * route-by-route stubs; per-test `server.use(...)` overrides win.
 */
export const server = setupServer(
  http.get('*/api/v1/auth/me', () =>
    HttpResponse.json({
      sub: 'u1',
      email: 'dev@kubedash.local',
      display_name: 'Dev',
      groups: [],
      role: 'admin',
    }),
  ),
  http.get('*/api/v1/clusters', () => HttpResponse.json({ items: [] })),
  http.post('*/api/v1/clusters', () =>
    HttpResponse.json({ id: 1, name: 'prod', status: 'unknown' }, { status: 201 }),
  ),
  http.get('*/api/v1/clusters/:id', () =>
    HttpResponse.json({ id: 1, name: 'prod', status: 'unknown' }),
  ),
  http.get('*/api/v1/clusters/:id/health', () => HttpResponse.json({ status: 'unknown' })),
  http.get('*/api/v1/clusters/:id/resources/:kind', () => HttpResponse.json({ items: [] })),
  // Cluster dashboard (2026-10-21-cluster-dashboard) — default healthy
  // shapes so view tests render without route-by-route stubs. Per-test
  // `server.use(...)` overrides win for the 404 / unknown / RBAC cases.
  http.get('*/api/v1/clusters/:id/metrics/summary', () =>
    HttpResponse.json({
      metrics_available: true,
      metrics_denied: false,
      cpu: {
        capacity_millicores: 4000,
        used_millicores: 800,
        requests_millicores: 2000,
        limits_millicores: 0,
      },
      memory: {
        capacity_bytes: 8589934592,
        used_bytes: 4294967296,
        requests_bytes: 2147483648,
        limits_bytes: 0,
      },
      pods: { capacity: 110, running: 10, pending: 2, completed: 1 },
    }),
  ),
  http.get('*/api/v1/clusters/:id/events', () =>
    HttpResponse.json([
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
    ]),
  ),
)

beforeAll(() => {
  // msw 3.0.3's listen() type is a PartialDeep of SharedOptions, which (as
  // released) does not include onUnhandledRequest — a known typing gap in
  // the 3.x line. The option itself is supported at runtime; keep it so an
  // unmatched request in jsdom is bypassed instead of failing the test.
  server.listen({ onUnhandledRequest: 'bypass' } as Parameters<typeof server.listen>[0])
})
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
