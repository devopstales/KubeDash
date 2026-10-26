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
    // ADR-0026: the backstop target is https://kubedash.dev.local:443 (task
    // e2e-ssl sets E2E_BASE_URL). Playwright's bundled Chromium does NOT
    // inherit the host keychain — it keeps its own trust store, so
    // `sudo mkcert -install` alone is not enough and a fresh host would
    // fail with net::ERR_CERT_AUTHORITY_INVALID (a trust-store gap, not a
    // broken chain). Importing the mkcert rootCA via E2E_TLS_CA keeps TLS
    // verification strict — the config uses strict verification only.
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        // WHY: the bundled Chrome for Testing's NSS rejects the mkcert CA
        // (probed); the strict backstop therefore runs on the system Chrome
        // (host keychain), selected via this env. A no-op when unset.
        channel: process.env.E2E_BROWSER_CHANNEL || undefined,
        // The bundled Chromium's trust store is NOT the host keychain, so the
        // mkcert rootCA must be imported explicitly to trust the e2e-ssl
        // backstop cert; importing it keeps verification strict.
        launchOptions: {
          args: process.env.E2E_TLS_CA
            ? [`--import-certificate=${process.env.E2E_TLS_CA}`]
            : [],
        },
      },
    },
  ],
})
