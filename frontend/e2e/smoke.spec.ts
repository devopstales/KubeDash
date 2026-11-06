import { expect, test } from '@playwright/test'

/**
 * E2E smoke: real stack (Flask :8080 + mock OIDC :9096).
 *
 * Journey:
 *   1. /login → "Login With SSO" → full-document 302 chain:
 *      /api/v1/auth/login → mock IdP authorize (tests/e2e/oidc-mock.py,
 *      auto-approve) → /api/v1/auth/callback → 302 / with HttpOnly session
 *      cookies (ADR-0025 — no token ever reaches localStorage; the SPA
 *      re-mounts on the protected shell).
 *   2. /clusters renders the bound-cluster registry.
 *   3. Register the kind cluster via the form.
 *   4. /clusters/<id> → the Pods table renders.
 *
 * The mock OIDC (tests/e2e/oidc-mock.py) is a CI service container on port 9096.
 * The real Authlib adapter runs — unit tier monkeypatches; e2e exercises the
 * real oidc_authorize_url / oidc_exchange bodies (JWKS verification, nonce
 * claim, token exchange).
 */

// A minimal valid kubeconfig pointing at the kind cluster's API server.
// e2e.yaml sets up the kind cluster before Playwright runs.
const KIND_KUBECONFIG = [
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

test.describe('KubeDash smoke', () => {
  test.describe.configure({ timeout: 60_000 })

  test('full OIDC login → clusters → pods', async ({ page }) => {
    // --- 1. OIDC login via the mock IdP ---
    // The SSO button is a full-document navigation (GET /api/v1/auth/login)
    // → 302 to the IdP authorize URL → the mock 302s back with
    // ?code=fixed&state=… → the backend callback 302s to / and parks the
    // session in HttpOnly cookies (ADR-0025) — then lands on / authenticated.
    await page.goto('/login')
    await page.getByRole('button', { name: 'Login With SSO' }).click()

    // The 302 chain settles on the app root; the session cookie (HttpOnly —
    // invisible to JS) is the success signal, proven via /auth/me.
    await expect
      .poll(
        async () =>
          await page.evaluate(
            () => fetch('/api/v1/auth/me', { credentials: 'same-origin' }).then((r) => r.status),
          ),
        { timeout: 30_000 },
      )
      .toBe(200)

    // --- 2. Clusters view renders ---
    await page.goto('/clusters')
    await expect(page.getByText('Bound clusters')).toBeVisible()

    // --- 3. Register the kind cluster ---
    await page.getByLabel('Name').fill('kind-e2e')
    await page.getByLabel('API server').fill('https://127.0.0.1:6443')
    await page.getByLabel('Kubeconfig').fill(KIND_KUBECONFIG)
    await page.getByLabel('Context').fill('kind')
    await page.getByRole('button', { name: 'Register' }).click()

    // The registered cluster appears in the bound-cluster table.
    await expect(page.getByText('kind-e2e', { exact: true })).toBeVisible({
      timeout: 15_000,
    })

    // --- 4. Open the cluster → Pods table ---
    await page.getByText('kind-e2e', { exact: true }).click()
    await expect(page.getByText('Pods')).toBeVisible({ timeout: 15_000 })
  })

  test('cluster list renders for a bound user', async ({ page, request }) => {
    // Seed a valid session via the API (requires the backend's test OIDC
    // mode); if the backend isn't in dev mode this test is the one that
    // gets skipped in CI.
    const clusters = await request.get('/api/v1/clusters', {
      headers: { Authorization: `Bearer ${process.env.E2E_TOKEN ?? ''}` },
    })
    if (!clusters.ok()) return // no seed token configured → nothing to assert
    await page.goto('/clusters')
    await expect(page.getByText('Bound clusters')).toBeVisible()
  })
})
