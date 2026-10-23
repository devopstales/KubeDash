import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { apiFetch, resetRefreshForTests } from '../src/lib/api'
import { setLoginRedirectForTests } from '../src/lib/session'

// The brief's tests mock `global.fetch` directly; install the spy in each
// test (MSW is not involved in this suite — the seam is raw fetch).
const installFetch = () => {
  const mock = vi.fn()
  globalThis.fetch = mock
  return mock
}

const res = (status: number, body: unknown) => ({
  ok: status < 400,
  status,
  json: async () => body,
})

const hasSessionHint = () =>
  document.cookie
    .split(';')
    .map((part) => part.trim())
    .includes('kd_session=1')

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  localStorage.clear()
  document.cookie = 'kd_session=; Max-Age=0; path=/'
  resetRefreshForTests()
  fetchMock = installFetch()
})

afterEach(() => {
  setLoginRedirectForTests(null)
  vi.restoreAllMocks()
})

describe('apiFetch', () => {
  test('sends same-origin cookie credentials and no bearer header', async () => {
    fetchMock.mockResolvedValueOnce(res(200, { items: [] }))
    const r = await apiFetch('/api/v1/clusters')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    // ponytail: the vitest suite pins VITE_API_BASE (vite.config.ts) so the
    // fetch URL is hermetic under jsdom; in prod/CI the base is empty and
    // this asserts the bare relative path.
    expect(url).toBe(`${import.meta.env.VITE_API_BASE ?? ''}/api/v1/clusters`)
    // ADR-0025: the HttpOnly cookie is the credential; there is no token in
    // JS and therefore no Authorization header to assert.
    expect(init.credentials).toBe('same-origin')
    expect((init.headers as Record<string, string> | undefined)?.Authorization).toBeUndefined()
    expect(r.data).toEqual({ items: [] })
    expect(r.error).toBeNull()
  })

  test('401 triggers single refresh (cookie, empty body) then retry', async () => {
    fetchMock
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'server-owned' })) // refresh
      .mockResolvedValueOnce(res(200, { items: [1] }))
    const r = await apiFetch('/api/v1/clusters')
    expect(r.data).toEqual({ items: [1] })
    expect(fetchMock).toHaveBeenCalledTimes(3)
    const [refreshUrl, refreshInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(refreshUrl).toContain('/api/v1/auth/refresh')
    expect(refreshInit.credentials).toBe('same-origin')
    // The refresh token rides in the path-scoped cookie, not the body.
    expect(refreshInit.body).toBe('{}')
  })

  test('error envelope is surfaced, not thrown', async () => {
    fetchMock.mockResolvedValueOnce(res(403, { error: { code: 'RBAC_DENIED', message: 'nope' } }))
    const r = await apiFetch('/api/v1/clusters/1/resources/pods')
    expect(r.error?.code).toBe('RBAC_DENIED')
    expect(r.error?.message).toBe('nope')
    expect(r.data).toBeNull()
    expect(r.meta.status).toBe(403)
  })

  test('two sequential 401s each trigger exactly one refresh', async () => {
    fetchMock
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'a2' }))
      .mockResolvedValueOnce(res(200, { items: [1] }))
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'a3' }))
      .mockResolvedValueOnce(res(200, { items: [2] }))
    const r1 = await apiFetch('/api/v1/clusters')
    expect(r1.data).toEqual({ items: [1] })
    const r2 = await apiFetch('/api/v1/clusters')
    expect(r2.data).toEqual({ items: [2] })
    // Both refreshes left the tokens absent from localStorage (server-owned).
    expect(localStorage.getItem('kd_token')).toBeNull()
  })

  test('a dead session clears the hint after a failed refresh', async () => {
    document.cookie = 'kd_session=1; path=/'
    // The seam keeps jsdom from logging "Not implemented: navigation".
    const assign = vi.fn()
    setLoginRedirectForTests(assign)
    fetchMock
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
    const r = await apiFetch('/api/v1/clusters')
    expect(r.error?.code).toBe('UNAUTHORIZED')
    expect(hasSessionHint()).toBe(false)
    expect(assign).toHaveBeenCalledWith('/login')
  })
})
