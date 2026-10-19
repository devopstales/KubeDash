/**
 * Single HTTP seam for the SPA: every request goes through `apiFetch`.
 *
 * - Attaches the Bearer token from localStorage (`kd_token`).
 * - On 401: a SINGLE in-flight `POST /api/v1/auth/refresh` (concurrent 401s
 *   share one refresh), stores the ROTATED access+refresh pair, retries once.
 * - Never throws on HTTP errors: returns the `{error: {code, message}}`
 *   envelope so views can surface it (R4's RBAC 403 path is where it pays
 *   off).
 */
const API_BASE: string = import.meta.env.VITE_API_BASE ?? ''

let inFlightRefresh: Promise<string> | null = null

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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: localStorage.getItem('kd_refresh') ?? '' }),
    })
      .then((r) => {
        if (!r.ok) throw new Error('refresh failed')
        return r.json() as Promise<RefreshPair>
      })
      .then((j) => {
        localStorage.setItem('kd_token', j.access)
        // The backend ALWAYS rotates the refresh token (R2); storing the
        // rotated value is what makes the second 401 refresh work.
        if (j.refresh) localStorage.setItem('kd_refresh', j.refresh)
        return j.access
      })
      .finally(() => {
        inFlightRefresh = null
      })
  }
  return inFlightRefresh
}

export async function apiFetch<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  const doFetch = (token: string | null) =>
    fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...(init.headers ?? {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    })

  let res = await doFetch(localStorage.getItem('kd_token'))
  if (res.status === 401) {
    try {
      const t = await refreshOnce()
      res = await doFetch(t)
    } catch {
      /* fall through to the error envelope below */
    }
  }
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
  const doFetch = (token: string | null) =>
    fetch(`${API_BASE}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })

  let res = await doFetch(localStorage.getItem('kd_token'))
  if (res.status === 401) {
    try {
      const t = await refreshOnce()
      res = await doFetch(t)
    } catch {
      /* fall through to the error envelope below */
    }
  }
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
