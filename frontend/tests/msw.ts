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
