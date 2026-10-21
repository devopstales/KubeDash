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
  // ponytail: the `as` cast — vitest 4's `defineConfig` generic doesn't
  // expose the vitest-inline options (maxWorkers) at the plain-object
  // literal position; runtime keys are the standard vitest 4 schema.
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [path.resolve(rootDir, 'tests/setup.ts')],
    include: ['tests/**/*.{test,spec}.{ts,tsx}'],
    // ponytail: jsdom + userEvent typing tests are slow under the default
    // parallel pool on small machines — a flaky full-suite run (timeouts in
    // TemplateEditor / BindModal tests) showed the flakes are load-related,
    // not logic-related (the same tests pass in isolation and most full
    // runs). Cap concurrency at 2 (vitest 4 top-level option; the old
    // test.poolOptions.threads was removed in 4).
    maxWorkers: 2,
  } as Record<string, unknown>,
})
