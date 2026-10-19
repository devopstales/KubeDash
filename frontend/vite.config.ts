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
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [path.resolve(rootDir, 'tests/setup.ts')],
    include: ['tests/**/*.{test,spec}.{ts,tsx}'],
  },
})
