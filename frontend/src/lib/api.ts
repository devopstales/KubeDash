/**
 * Single HTTP seam for the SPA: every request goes through `apiFetch`.
 *
 * - Sends the session as same-origin cookies (ADR-0025). The `kd_access` and
 *   `kd_refresh` cookies are HttpOnly, so this module never sees a token and
 *   an XSS payload cannot read one.
 * - On 401: a SINGLE in-flight `POST /api/v1/auth/refresh` (concurrent 401s
 *   share one refresh), then retries once. A 401 that survives the retry
 *   means the session is dead: the hint is cleared and the browser is sent to
 *   `/login`.
 * - Never throws on HTTP errors: returns the `{error: {code, message}}`
 *   envelope so views can surface it (R4's RBAC 403 path is where it pays
 *   off).
 *
 * Base origin: requests are fetched against `API_BASE` + path. Production/CI
 * builds bake no VITE_API_BASE (Flask serves the SPA at /, same-origin /api,
 * ADR-0006), so a relative fetch lands on the same origin the page loaded
 * from. ponytail: the vitest suite (frontend/tests) runs under jsdom with NO
 * dev server and NO vite proxy — a relative URL there would be fetched by
 * Node (no host → 'fetch failed') or, worse, hit the dev stack via the proxy
 * (test results coupled to the env). So tests pin VITE_API_BASE to
 * http://localhost in the VITEST-gated define block of vite.config.ts: the
 * page loads from http://localhost/ in the suite, and MSW intercepts every
 * request on that origin. A missing pin would surface as a 'fetch failed'
 * red error in the dashboard suite, not as a silent 404.
 */
import { clearSessionHint, redirectToLogin } from './session'

const API_BASE: string = import.meta.env.VITE_API_BASE ?? ''

let inFlightRefresh: Promise<string> | null = null

/** A 401 that survived the refresh: the cookies are gone or revoked. */
function deadSession(): void {
  clearSessionHint()
  redirectToLogin()
}

export interface ApiResult<T = unknown> {
  data: T | null
  error: { code: string; message: string } | null
  meta: { status: number }
}

export interface RefreshPair {
  access: string
  refresh?: string
}

async function refreshOnce(): Promise<string> {
  if (!inFlightRefresh) {
    inFlightRefresh = fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: 'POST',
      // The refresh token rides in the path-scoped HttpOnly cookie; the empty
      // JSON body keeps the request a non-simple one (no CSRF form post).
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
      .then((r) => {
        if (!r.ok) throw new Error('refresh failed')
        return r.json() as Promise<RefreshPair>
      })
      .then((j) => {
        // The server rotates AND re-sets both cookies; there is nothing for
        // the client to persist. `access` is returned only so callers can
        // keep the pre-ADR-0025 signature.
        return j.access
      })
      .finally(() => {
        inFlightRefresh = null
      })
  }
  return inFlightRefresh
}

export async function apiFetch<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  const doFetch = () =>
    fetch(`${API_BASE}${path}`, {
      ...init,
      // Same-origin: the SPA and the API ship in one container (ADR-0006), so
      // the cookies need neither CORS nor a cross-site credential mode.
      credentials: 'same-origin',
      headers: { ...(init.headers ?? {}) },
    })

  let res = await doFetch()
  if (res.status === 401) {
    try {
      await refreshOnce()
      res = await doFetch()
    } catch {
      /* fall through: a dead session redirects below */
    }
  }
  if (res.status === 401) deadSession()
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = (body as { error?: { code?: string; message?: string } }).error
    return {
      data: null,
      error: err
        ? { code: err.code ?? 'UNKNOWN', message: err.message ?? String(res.status) }
        : { code: 'UNKNOWN', message: String(res.status) },
      meta: { status: res.status },
    }
  }
  return { data: body as T, error: null, meta: { status: res.status } }
}

export interface DownloadResult {
  ok: boolean
  error: { code: string; message: string } | null
  status: number
}

/**
 * Binary-safe variant of apiFetch for file downloads (kubeconfig): attaches
 * the Bearer token, runs the SAME single-in-flight 401 refresh+retry, fetches
 * a Blob, and on success triggers a browser download of `filename`
 * (ObjectURL → <a download> click → revoke). On non-ok it parses the JSON
 * error envelope and returns it — the error body is NOT downloaded as a file.
 */
export async function downloadFile(path: string, filename: string): Promise<DownloadResult> {
  const doFetch = () => fetch(`${API_BASE}${path}`, { credentials: 'same-origin' })

  let res = await doFetch()
  if (res.status === 401) {
    try {
      await refreshOnce()
      res = await doFetch()
    } catch {
      /* fall through: a dead session redirects below */
    }
  }
  if (res.status === 401) deadSession()
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const err = (body as { error?: { code?: string; message?: string } }).error
    return {
      ok: false,
      error: err
        ? { code: err.code ?? 'UNKNOWN', message: err.message ?? String(res.status) }
        : { code: 'UNKNOWN', message: String(res.status) },
      status: res.status,
    }
  }
  const blob = await res.blob()
  // ponytail: no Content-Disposition parsing — the view passes the filename
  // explicitly (it matches the backend's attachment name, ADR-0011).
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  return { ok: true, error: null, status: res.status }
}

/** Test hook: drop a half-finished in-flight refresh (jsdom test isolation). */
export function resetRefreshForTests(): void {
  inFlightRefresh = null
}
