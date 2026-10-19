import { defineConfig } from '@playwright/test'

/**
 * Playwright e2e config.
 *
 * Two specs, two targets:
 *   - auth-smoke.spec.ts → the real Flask backend on :8080 (task dev-up +
 *     wsgi.py with KUBEDASH_STATIC_DIR). No webServer — the backend serves
 *     the built SPA.
 *   - smoke.spec.ts      → the OIDC + kind-cluster journey (CI: kind +
 *     mock IdP service container).
 *
 * Run the local auth smoke (no kind needed):
 *   task dev-up
 *   # (one-time schema + backend start — see auth-smoke.spec.ts header)
 *   corepack pnpm exec playwright test e2e/auth-smoke.spec.ts
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
})
