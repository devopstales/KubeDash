/// <reference types="vitest" />
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'node:url'

const rootDir = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  // Absolute base: the SPA is served at / (the Flask app serves the whole
  // bundle at /, ADR-0006). Relative base ('./') rewrites /favicon.ico to
  // ./favicon.ico, which breaks the favicon on non-root URLs.
  base: '/',
  build: {
    // Task 9's Dockerfile bakes frontend/dist/; the template builds to
    // build/ but the base-structure contract is dist/.
    outDir: 'dist',
    emptyOutDir: true,
  },
  css: {
    postcss: {
      plugins: [autoprefixer({})],
    },
  },
  plugins: [react()],
  resolve: {
    alias: [
      {
        find: 'src/',
        replacement: `${path.resolve(rootDir, 'src')}/`,
      },
      {
        find: /^src\//,
        replacement: `${path.resolve(rootDir, 'src')}/`,
      },
    ],
    extensions: ['.mjs', '.js', '.ts', '.jsx', '.tsx', '.json', '.scss'],
  },
  server: {
    port: 3000,
    // Same-origin /api in dev. A cross-origin VITE_API_BASE leaves the
    // header with no cluster and an empty namespace select (CORS).
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [path.resolve(rootDir, 'tests/setup.ts')],
    include: ['tests/**/*.{test,spec}.{ts,tsx}'],
  },
  // ponytail: vitest 4's `test.env` does NOT inject import.meta.env, so the
  // suite's VITE_API_BASE pin lives here. Gated on VITEST so the production
  // build (mode 'production') stays free of the test origin. Without it,
  // api.ts fetches relative URLs and MSW's node interceptor resolves them
  // against the dev-server origin (localhost:3000) — where a running `task
  // dev` stack would ANSWER requests that should hit the MSW handlers (test
  // results coupled to the env). Pinning to localhost:80, which nothing in
  // the dev stack serves, keeps the suite hermetic.
  define:
    process.env.VITEST === 'true'
      ? { 'import.meta.env.VITE_API_BASE': JSON.stringify('http://localhost') }
      : undefined,
})
