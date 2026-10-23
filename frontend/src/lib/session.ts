/**
 * Browser session helpers (ADR-0025).
 *
 * The credentials themselves (`kd_access`, `kd_refresh`) are HttpOnly: this
 * module cannot read them, and neither can an XSS payload. `kd_session` is a
 * non-HttpOnly *hint* the server sets so the router can decide whether to
 * render the shell without a round-trip. It grants nothing — a forged hint
 * only renders a page whose API calls will 401.
 */
export const SESSION_HINT_COOKIE = 'kd_session'

export function hasSessionHint(): boolean {
  return document.cookie
    .split(';')
    .map((part) => part.trim())
    .includes(`${SESSION_HINT_COOKIE}=1`)
}

/** Expire the hint after a dead session. The HttpOnly pair is server-owned. */
export function clearSessionHint(): void {
  document.cookie = `${SESSION_HINT_COOKIE}=; Max-Age=0; path=/`
}

let navigate = (path: string): void => window.location.assign(path)

/** Test hook: jsdom's Location.assign is non-configurable, so spy here. */
export function setLoginRedirectForTests(fn: ((path: string) => void) | null): void {
  navigate = fn ?? ((path) => window.location.assign(path))
}

/** Full navigation (not router state): drops in-memory data from the dead session. */
export function redirectToLogin(): void {
  if (typeof window === 'undefined') return
  if (window.location.pathname === '/login') return
  navigate('/login')
}
