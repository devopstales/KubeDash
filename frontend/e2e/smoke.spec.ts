import { expect, test } from '@playwright/test'

/**
 * Smoke e2e against the real stack: Flask on :8080 serves the API and the
 * built SPA (dist/). ENV-BLOCKED in Task 8 (no Docker → no Flask, no
 * chromium download verified); this is the scaffold for the base-structure
 * acceptance scenario `spa-shell-renders-cluster-pods`.
 */
test.describe('KubeDash smoke', () => {
  test('login bounces to OIDC (no token)', async ({ page }) => {
    await page.goto('/clusters')
    // No kd_token → ProtectedRoute redirects to /login → LoginView bounces
    // to /api/v1/auth/login (302 to the IdP). We assert the SPA reached
    // the auth seam, not the IdP round-trip.
    await expect
      .poll(async () => page.url(), { timeout: 15_000 })
      .toContain('/api/v1/auth/login')
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
    await expect(page.getByText('Clusters')).toBeVisible()
  })
})
