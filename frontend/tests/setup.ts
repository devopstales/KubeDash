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
// without it. VITE_API_BASE is pinned in the VITEST-gated define block of
// vite.config.ts, so these stay inert. The old prototype-setter trick is
// gone: in jsdom 25 the own href descriptor is non-configurable and the
// setter triggers "Not implemented: navigation" without ever mutating the
// URL.

// ADR-0040: postObjectToTab calls form.submit() to open the cross-tab
// relay tab. jsdom's HTMLFormElement.prototype.submit is not implemented —
// it logs "Not implemented" via the virtual console and does not navigate.
// Stub it once: a no-op is exactly what the unit tests need (the relay
// write and the form DOM are the contract, not the navigation).
Object.defineProperty(HTMLFormElement.prototype, 'submit', {
  configurable: true,
  writable: true,
  value: () => {},
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
  // ADR-0025: the session hint lives in a cookie, which jsdom keeps across
  // tests. Expire it so a "logged in" test cannot leak into the next one.
  document.cookie = 'kd_session=; Max-Age=0; path=/'
  // ADR-0040: object refs live in sessionStorage (per-tab) and a one-shot
  // localStorage relay (cross-tab handoff). Neither should leak between
  // tests: a "logged in" ref cannot leak into the next test's list render.
  sessionStorage.clear()
  localStorage.clear()
})
