import { defineConfig } from '@playwright/test'

/**
 * Playwright e2e config.
 *
 * ENV-BLOCKED in this task: e2e needs the real Flask backend on :8080
 * (no Docker in this environment) plus a downloaded chromium. The spec
 * is committed as the scaffold; run it once the backend is up:
 *
 *   corepack pnpm exec playwright test
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8080',
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'corepack pnpm exec vite preview --port 4173',
    port: 4173,
    reuseExistingServer: true,
  },
})
