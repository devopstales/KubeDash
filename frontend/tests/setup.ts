import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// jsdom lacks matchMedia; CoreUI's color-mode hook calls it.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// ponytail: apiFetch builds absolute URLs from VITE_API_BASE, so the jsdom
// document URL (about:blank by default) only matters if a test reaches fetch
// without it. VITE_API_BASE is pinned in vite.config.ts — the env: block
// below — so these stay inert. The old prototype-setter trick is gone: in
// jsdom 25 the own href descriptor is non-configurable and the setter
// triggers "Not implemented: navigation" without ever mutating the URL.

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})
