import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { apiFetch, resetRefreshForTests } from '../src/lib/api'

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

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  localStorage.clear()
  resetRefreshForTests()
  fetchMock = installFetch()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('apiFetch', () => {
  test('attaches bearer token', async () => {
    fetchMock.mockResolvedValueOnce(res(200, { items: [] }))
    localStorage.setItem('kd_token', 'tok-1')
    const r = await apiFetch('/api/v1/clusters')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    // ponytail: the vitest suite pins VITE_API_BASE (vite.config.ts) so the
    // fetch URL is hermetic under jsdom; in prod/CI the base is empty and
    // this asserts the bare relative path.
    expect(url).toBe(`${import.meta.env.VITE_API_BASE ?? ''}/api/v1/clusters`)
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok-1')
    expect(r.data).toEqual({ items: [] })
    expect(r.error).toBeNull()
  })

  test('401 triggers single refresh then retry', async () => {
    fetchMock
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'tok-2' })) // refresh
      .mockResolvedValueOnce(res(200, { items: [1] }))
    localStorage.setItem('kd_token', 'tok-1')
    const r = await apiFetch('/api/v1/clusters')
    expect(r.data).toEqual({ items: [1] })
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(localStorage.getItem('kd_token')).toBe('tok-2')
  })

  test('error envelope is surfaced, not thrown', async () => {
    fetchMock.mockResolvedValueOnce(res(403, { error: { code: 'RBAC_DENIED', message: 'nope' } }))
    const r = await apiFetch('/api/v1/clusters/1/resources/pods')
    expect(r.error?.code).toBe('RBAC_DENIED')
    expect(r.error?.message).toBe('nope')
    expect(r.data).toBeNull()
    expect(r.meta.status).toBe(403)
  })

  test('second 401 uses the ROTATED refresh token (double rotation works)', async () => {
    fetchMock
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'tok-2', refresh: 'rt-2' }))
      .mockResolvedValueOnce(res(200, { items: [1] }))
      .mockResolvedValueOnce(res(401, { error: { code: 'UNAUTHORIZED', message: 'x' } }))
      .mockResolvedValueOnce(res(200, { access: 'tok-3', refresh: 'rt-3' }))
      .mockResolvedValueOnce(res(200, { items: [2] }))
    localStorage.setItem('kd_token', 'tok-1')
    localStorage.setItem('kd_refresh', 'rt-1')
    const r1 = await apiFetch('/api/v1/clusters')
    expect(r1.data).toEqual({ items: [1] })
    expect(localStorage.getItem('kd_refresh')).toBe('rt-2')
    const r2 = await apiFetch('/api/v1/clusters')
    expect(r2.data).toEqual({ items: [2] })
    expect(localStorage.getItem('kd_refresh')).toBe('rt-3')
  })
})
