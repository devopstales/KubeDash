/**
 * Session object refs (ADR-0040).
 *
 * Object identity (kind/name/namespace) never rides the URL. The open
 * object is a token-keyed entry in a **tab-private** sessionStorage
 * registry with an active pointer; identity crosses tabs only through a
 * one-shot, token-scoped **localStorage relay** (`kd_ref_<token>` +
 * `kd_ref_<token>_exp`, 60 s, self-deleting on consumption) that a hidden
 * same-origin form POST (`name="o"`, the opaque token only) hands to the
 * fresh tab. The relay is a bus, not storage: nothing persists.
 *
 * This module is router-free: the navigate fn is registered once by the
 * caller (`openObject`), which keeps it unit-testable without jsdom
 * history or a router.
 */

export interface ObjectRef {
  kind: string
  name: string
  namespace?: string
  /** Date.now() when set (client time; lazy 15-min expiry, no timer). */
  ts: number
  origin: 'click' | 'link' | 'post'
}

export const REGISTRY_KEY = 'kd_object_refs' // sessionStorage: token -> ObjectRef
export const ACTIVE_KEY = 'kd_object_active' // sessionStorage: active token
export const RELAY_PREFIX = 'kd_ref_' // localStorage: cross-tab handoff
export const EXPIRY_MS = 15 * 60 * 1000 // in-tab ref lifetime
export const RELAY_TTL_MS = 60 * 1000 // cross-tab handoff window

type NavigateFn = (path: string) => void

// ---- Registry (sessionStorage; per-tab) ----------------------------------

export function readRegistry(): Record<string, ObjectRef> {
  const raw = sessionStorage.getItem(REGISTRY_KEY)
  if (!raw) return {}
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, ObjectRef>) : {}
  } catch {
    return {}
  }
}

export function writeRegistry(reg: Record<string, ObjectRef>): void {
  sessionStorage.setItem(REGISTRY_KEY, JSON.stringify(reg))
}

// ---- Token ----------------------------------------------------------------

/** 32-bit hex via crypto.getRandomValues — the only thing the form body
 *  and the URL may carry. */
export function mintToken(): string {
  const bytes = new Uint8Array(4)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

// ---- Active pointer (lazy expiry) ------------------------------------------

export function getActiveRef(): ObjectRef | null {
  const token = sessionStorage.getItem(ACTIVE_KEY)
  if (!token) return null
  const reg = readRegistry()
  const ref = reg[token]
  if (!ref) {
    clearActiveRef()
    return null
  }
  if (Date.now() - ref.ts > EXPIRY_MS) {
    // Lazy expiry: drop the entry and the pointer, render the list.
    delete reg[token]
    writeRegistry(reg)
    clearActiveRef()
    return null
  }
  return ref
}

export function setActiveRef(token: string): void {
  sessionStorage.setItem(ACTIVE_KEY, token)
}

export function clearActiveRef(): void {
  sessionStorage.removeItem(ACTIVE_KEY)
}

// ---- In-tab open (list row click) -------------------------------------------

/**
 * Registry entry + active pointer + list-route navigation. The navigate fn
 * is passed per call (registered by the route wrapper) so this module stays
 * router-free. No localStorage: in-tab opens never touch the relay.
 */
export function openObject(
  kind: string,
  name: string,
  namespace: string | undefined,
  listRoute: string,
  navigate: NavigateFn,
): void {
  const token = mintToken()
  const reg = readRegistry()
  const ref: ObjectRef = { kind, name, namespace, ts: Date.now(), origin: 'click' }
  reg[token] = ref
  writeRegistry(reg)
  setActiveRef(token)
  navigate(listRoute)
}

// ---- Cross-tab deep link (share action) --------------------------------------

/**
 * Hidden form POST to `routePath` in a new tab. The relay (localStorage,
 * token-scoped, 60 s) carries the identity; the form body carries only the
 * opaque token. `configure` receives the form before submit (test seam to
 * spy `form.submit`); production uses a no-op.
 */
export function postObjectToTab(
  kind: string,
  name: string,
  namespace: string | undefined,
  routePath: string,
  configure?: (form: HTMLFormElement) => void,
): void {
  const token = mintToken()
  const ref: ObjectRef = { kind, name, namespace, ts: Date.now(), origin: 'post' }
  localStorage.setItem(`${RELAY_PREFIX}${token}`, JSON.stringify(ref))
  localStorage.setItem(
    `${RELAY_PREFIX}${token}_exp`,
    String(Date.now() + RELAY_TTL_MS),
  )

  const form = document.createElement('form')
  form.method = 'POST'
  form.action = routePath
  form.target = '_blank'
  const input = document.createElement('input')
  input.type = 'hidden'
  input.name = 'o'
  input.value = token
  form.appendChild(input)
  form.style.display = 'none'
  document.body.appendChild(form)
  configure?.(form)
  // jsdom's HTMLFormElement.prototype.submit is not implemented: it logs a
  // "Not implemented" error (via jsdom's virtual console, not a thrown
  // exception) and does not navigate. A real browser's submit IS the POST
  // navigation. Wrap in a spy-friendly call so the unit test can observe
  // the dispatch without the jsdom noise.
  form.submit()
  form.remove()
}

// ---- New-tab mount consumption -------------------------------------------------

/**
 * Resolve `?o=` on the current document, read + validate + self-delete the
 * relay, hydrate the tab's registry, strip the param. A plain GET (no
 * `?o=`) returns null and never consumes a relay key. An expired or absent
 * relay is a miss — the list renders, never a wrong object.
 */
export function consumeIncoming(): ObjectRef | null {
  const params = new URLSearchParams(window.location.search)
  const token = params.get('o')
  if (!token) return null

  const stripParam = (): void => {
    params.delete('o')
    const qs = params.toString()
    window.history.replaceState(window.history.state, '', qs ? `?${qs}` : window.location.pathname)
  }

  const body = localStorage.getItem(`${RELAY_PREFIX}${token}`)
  const expRaw = localStorage.getItem(`${RELAY_PREFIX}${token}_exp`)
  const expired = expRaw === null || Date.now() > Number(expRaw)
  // Self-delete either way: the handoff window is over for this token.
  localStorage.removeItem(`${RELAY_PREFIX}${token}`)
  localStorage.removeItem(`${RELAY_PREFIX}${token}_exp`)

  if (!body || expired) {
    stripParam()
    return null
  }
  let ref: ObjectRef
  try {
    ref = JSON.parse(body) as ObjectRef
  } catch {
    stripParam()
    return null
  }
  const reg = readRegistry()
  reg[token] = ref
  writeRegistry(reg)
  setActiveRef(token)
  stripParam()
  return ref
}

// ---- Sweep ----------------------------------------------------------------------

/**
 * Remove expired (or orphaned, i.e. missing `_exp`) relay pairs. Called on
 * App mount; idempotent. Fresh relays are left for their consumer tab.
 */
export function sweepRelay(): void {
  const now = Date.now()
  const expiredBases: string[] = []
  const keys = Object.keys(localStorage) // snapshot: the loop mutates storage
  for (const key of keys) {
    if (!key.startsWith(RELAY_PREFIX)) continue
    if (key.endsWith('_exp')) {
      if (now > Number(localStorage.getItem(key))) {
        localStorage.removeItem(key)
        expiredBases.push(key.slice(0, -'_exp'.length))
      }
      continue
    }
    // Body without its _exp: unverifiable expiry → sweep it.
    if (!localStorage.getItem(`${key}_exp`)) {
      localStorage.removeItem(key)
    }
  }
  // A base whose _exp expired was removed above alongside its _exp key.
  for (const base of expiredBases) {
    localStorage.removeItem(base)
  }
}
