import { expect } from '@playwright/test'
import type { APIRequestContext, Page } from '@playwright/test'

/** The dev-stack origin the suites run against (playwright.config baseURL). */
const ORIGIN = process.env.E2E_BASE_URL ?? 'http://localhost:8080'

/**
 * Shared e2e helpers for the api-smoke + ui-smoke specs.
 *
 * ADMIN_EMAIL/ADMIN_PASSWORD match the dev-stack defaults (Taskfile.yaml vars
 * ADMIN_EMAIL/ADMIN_PASSWORD, consumed as KUBEDASH_BOOTSTRAP_ADMIN_*).
 */
export const ADMIN_EMAIL = 'admin@local'
export const ADMIN_PASSWORD = 'admin'

/** Minimal kubeconfig the smoke suite registers: valid YAML mapping,
 * unreachable API server — only the registry + binding gate is exercised. */
export const KIND_KUBECONFIG = [
  'apiVersion: v1',
  'clusters:',
  '- cluster:',
  '    server: https://127.0.0.1:6443',
  '  name: kind',
  'contexts:',
  '- context:',
  '    cluster: kind',
  '    user: kind-admin',
  '  name: kind',
  'current-context: kind',
  'kind: Config',
  'preferences: {}',
  'users:',
  '- name: kind-admin',
  '  user:',
  '    client-certificate-data: e30=',
  '    client-key-data: e30=',
].join('\n')

/** The registered smoke cluster's name — unique per run would fight the
 * 409-on-duplicate gate; the suite tolerates "already registered". */
export const SMOKE_CLUSTER = 'e2e-smoke'

/** Collect pageerror events so tests can assert the JS runtime didn't crash. */
export function attachErrorWatcher(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (err) => errors.push(err.message))
  return errors
}

/** Benign-browser-noise filter (favicon/manifest 404s on some builds). */
export function fatalErrors(errors: string[]): string[] {
  return errors.filter((e) => !e.includes('favicon') && !e.includes('Manifest'))
}

/** The 302 Location from POST /auth/local is the parked-token URL
 * (`/?token=…&refresh=…`, the JWT delivery contract). */
export function locationFromLocalLogin(resp: {
  status(): number
  headers(): Record<string, string>
}): string {
  expect([resp.status()]).toEqual([302])
  const location = resp.headers()['location']
  expect(location, 'auth/local 302 without a Location header').toBeTruthy()
  return location as string
}

/** Extract the access token from a parked-token URL. */
export function tokenFromLocation(location: string): string {
  return new URL(location, 'http://localhost').searchParams.get('token') ?? ''
}

/**
 * Log in as the bootstrap admin through the REAL local login flow:
 * POST /auth/local → 302 to /?token=…&refresh=… → the SPA parking effect
 * stores both in localStorage and strips the query.
 */
export async function loginAs(page: Page): Promise<void> {
  // The real login FORM (test 1) exercises the in-process 302 flow. This
  // helper is for mid-suite re-auth: POST /auth/local proves the credentials
  // still work, then we seed localStorage exactly as the Login view's
  // parkTokens does. We do NOT navigate to the parked ?token=… URL: / is
  // wrapped in DefaultLayout→ProtectedRoute, which bounces token-less
  // visitors to /login BEFORE the SPA can mount LoginView — the parked-URL
  // document-navigation path is the SSO path, and the SPA root that
  // consumes it only exists behind the auth gate.
  const resp = await page.request.post('/api/v1/auth/local', {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    maxRedirects: 0,
  })
  const location = locationFromLocalLogin(resp)
  const token = tokenFromLocation(location)
  const refresh = new URL(location, ORIGIN).searchParams.get('refresh') ?? ''
  expect(token, 'auth/local 302 without a token param').toBeTruthy()
  await page.goto(`${ORIGIN}/login`)
  await page.evaluate(
    ([t, r]) => {
      localStorage.setItem('kd_token', t)
      localStorage.setItem('kd_refresh', r)
    },
    [token, refresh],
  )
}

/** The access token, built through the same 302 flow. APIRequestContext has
 * no per-context auth header, so callers pass `Authorization` per request. */
export async function loginToken(base: APIRequestContext): Promise<string> {
  const resp = await base.post('/api/v1/auth/local', {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    maxRedirects: 0,
  })
  const token = tokenFromLocation(locationFromLocalLogin(resp))
  expect(token, 'auth/local 302 without a token param').toBeTruthy()
  return token
}

/** Bearer headers for an authenticated APIRequestContext call. */
export function authHeaders(token: string): { Authorization: string } {
  return { Authorization: `Bearer ${token}` }
}

/** The stable error-code contract: every error response is an envelope
 * `{"error": {"code": ..., "message": ...}}` (app/core/errors.py). */
export function errorCode(body: { error?: { code?: string } }): string {
  return body.error?.code ?? ''
}
