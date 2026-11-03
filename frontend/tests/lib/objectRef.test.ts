import { describe, expect, test, vi } from 'vitest'
import {
  clearActiveRef,
  consumeIncoming,
  EXPIRY_MS,
  getActiveRef,
  openObject,
  postObjectToTab,
  readRegistry,
  setActiveRef,
  sweepRelay,
  writeRegistry,
} from '../../src/lib/objectRef'

/** Seed a relay pair the way postObjectToTab writes it (bypassing the form
 *  POST; the relay contract is what consumeIncoming validates). */
function seedRelay(
  token: string,
  ref: { kind: string; name: string; namespace?: string },
  ageMs = 0,
): void {
  localStorage.setItem(
    `kd_ref_${token}`,
    JSON.stringify({ ...ref, ts: Date.now() - ageMs, origin: 'post' }),
  )
  localStorage.setItem(`kd_ref_${token}_exp`, String(Date.now() - ageMs + 60_000))
}

describe('registry', () => {
  test('round-trips a token-keyed entry through sessionStorage', () => {
    const reg = { t1: { kind: 'secret', name: 'db-creds', namespace: 'team-a', ts: 123, origin: 'click' as const } }
    writeRegistry(reg)
    expect(readRegistry()).toEqual(reg)
  })

  test('empty when nothing was written', () => {
    expect(readRegistry()).toEqual({})
  })

  test('corrupt JSON degrades to an empty registry, not a throw', () => {
    sessionStorage.setItem('kd_object_refs', '{not json')
    expect(readRegistry()).toEqual({})
  })
})

describe('active pointer', () => {
  test('setActiveRef + getActiveRef resolves through the registry', () => {
    writeRegistry({ t1: { kind: 'node', name: 'n1', ts: Date.now(), origin: 'link' } })
    setActiveRef('t1')
    expect(getActiveRef()).toEqual({
      kind: 'node',
      name: 'n1',
      ts: expect.any(Number),
      origin: 'link',
    })
  })

  test('null when no active token is set', () => {
    expect(getActiveRef()).toBeNull()
  })

  test('null when the active token is not in the registry', () => {
    setActiveRef('ghost')
    expect(getActiveRef()).toBeNull()
  })

  test('backdated > 15 min: lazy expiry clears the active pointer and drops the entry', () => {
    const ts = Date.now() - 16 * 60 * 1000
    writeRegistry({ old: { kind: 'secret', name: 's', ts, origin: 'click' } })
    setActiveRef('old')
    expect(getActiveRef()).toBeNull()
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    expect(readRegistry()).not.toHaveProperty('old')
  })

  test('a fresh ref survives the expiry check', () => {
    writeRegistry({ fresh: { kind: 'secret', name: 's', ts: Date.now() - EXPIRY_MS + 1000, origin: 'click' } })
    setActiveRef('fresh')
    expect(getActiveRef()?.name).toBe('s')
  })

  test('clearActiveRef drops the pointer but keeps the registry', () => {
    writeRegistry({ t1: { kind: 'secret', name: 's', ts: Date.now(), origin: 'click' } })
    setActiveRef('t1')
    clearActiveRef()
    expect(getActiveRef()).toBeNull()
    expect(readRegistry()).toHaveProperty('t1')
  })
})

describe('openObject', () => {
  test('mints a registry entry, sets the active pointer, and navigates to the list route', () => {
    const navigate = vi.fn()
    openObject('secret', 'db-creds', 'team-a', '/security/secret', navigate)
    expect(navigate).toHaveBeenCalledWith('/security/secret')
    const reg = readRegistry()
    expect(Object.keys(reg)).toHaveLength(1)
    const [token, ref] = Object.entries(reg)[0]
    expect(ref).toMatchObject({ kind: 'secret', name: 'db-creds', namespace: 'team-a', origin: 'click' })
    expect(getActiveRef()?.name).toBe('db-creds')
    // The relay is in-tab only: openObject must not touch localStorage.
    expect(localStorage.length).toBe(0)
    // No identity anywhere in sessionStorage keys beyond the token registry.
    expect(Object.keys(sessionStorage).filter((k) => k.startsWith('kd_ref_'))).toHaveLength(0)
  })

  test('token mint: two consecutive opens get distinct tokens', () => {
    const navigate = vi.fn()
    openObject('secret', 'a', 'team-a', '/security/secret', navigate)
    openObject('secret', 'b', 'team-a', '/security/secret', navigate)
    expect(Object.keys(readRegistry()).length).toBeGreaterThanOrEqual(2)
  })

  test('minted tokens are 8-char hex (32-bit)', () => {
    const navigate = vi.fn()
    openObject('secret', 'a', 'team-a', '/security/secret', navigate)
    const [token] = Object.keys(readRegistry())
    expect(token).toMatch(/^[0-9a-f]{8}$/)
  })
})

describe('postObjectToTab', () => {
  test('writes the token-scoped relay with a ~60s expiry and POSTs only the token', () => {
    postObjectToTab('secret', 'db-creds', 'team-a', '/security/secret')
    // The relay is a bus: identity lives under exactly one token-scoped
    // body key and its _exp companion. No other key carries identity.
    const tokenBodies = Object.keys(localStorage).filter(
      (k) => k.startsWith('kd_ref_') && !k.endsWith('_exp') && k.length > 7,
    )
    expect(tokenBodies).toHaveLength(1)
    const key = tokenBodies[0]
    const token = key.slice('kd_ref_'.length)
    const body = JSON.parse(localStorage.getItem(key) ?? '')
    expect(body).toMatchObject({ kind: 'secret', name: 'db-creds', namespace: 'team-a', origin: 'post' })
    const exp = Number(localStorage.getItem(`${key}_exp`))
    expect(exp).toBeGreaterThan(Date.now() + 50_000)
    expect(exp).toBeLessThanOrEqual(Date.now() + 60_000)
  })

  test('hidden form: POST to the list route, target _blank, single hidden input "o" = token', () => {
    postObjectToTab('node', 'n1', undefined, '/cluster/node', (form) => {
      expect(form.method.toUpperCase()).toBe('POST')
      expect(form.action).toContain('/cluster/node')
      expect(form.target).toBe('_blank')
      expect(form.innerHTML).toContain('name="o"')
      const input = (form as HTMLFormElement).querySelector('input[name="o"]')
      expect(input?.getAttribute('value')).toMatch(/^[0-9a-f]{8}$/)
      // No identity in the form body — only the opaque token.
      expect(form.innerHTML).not.toContain('n1')
      expect(form.innerHTML).not.toContain('node')
    })
  })

  test('no localStorage identity outside the kd_ref_ relay keys', () => {
    postObjectToTab('secret', 'db-creds', 'team-a', '/security/secret', (form) => form.submit())
    for (const key of Object.keys(localStorage)) {
      expect(key.startsWith('kd_ref_')).toBe(true)
      if (key.endsWith('_exp')) continue
      const body = JSON.parse(localStorage.getItem(key) ?? '')
      expect(body.kind).toBe('secret')
    }
  })
})

describe('consumeIncoming', () => {
  test('hydrates the relay into the registry + active pointer and self-deletes both keys', () => {
    seedRelay('tok1', { kind: 'secret', name: 'db-creds', namespace: 'team-a' })
    window.history.replaceState(null, '', '/security/secret?o=tok1')
    const ref = consumeIncoming()
    expect(ref).toMatchObject({ kind: 'secret', name: 'db-creds', namespace: 'team-a', origin: 'post' })
    // Relay consumed: no kd_ref_ key survives the handoff.
    expect(Object.keys(localStorage).filter((k) => k.startsWith('kd_ref_'))).toHaveLength(0)
    // Hydrated in-tab: the active ref resolves.
    expect(getActiveRef()?.name).toBe('db-creds')
    // R1: the ?o= param is stripped from the address bar.
    expect(window.location.search).toBe('')
  })

  test('expired relay (age > 60s) → null, relay keys swept, no hydration', () => {
    seedRelay('tok2', { kind: 'secret', name: 's' }, 90_000)
    window.history.replaceState(null, '', '/security/secret?o=tok2')
    expect(consumeIncoming()).toBeNull()
    expect(Object.keys(localStorage).filter((k) => k.startsWith('kd_ref_'))).toHaveLength(0)
    expect(getActiveRef()).toBeNull()
  })

  test('absent relay for a guessed token → null (a miss renders the list, never a wrong object)', () => {
    window.history.replaceState(null, '', '/security/secret?o=deadbeef0001')
    expect(consumeIncoming()).toBeNull()
    expect(getActiveRef()).toBeNull()
  })

  test('no ?o= param (plain GET) → null and no relay keys are ever consumed', () => {
    seedRelay('tok3', { kind: 'secret', name: 's' })
    window.history.replaceState(null, '', '/security/secret')
    expect(consumeIncoming()).toBeNull()
    // The GET left the relay untouched — only sweepRelay removes it, or a
    // future POST with the same token would have consumed it.
    expect(localStorage.getItem('kd_ref_tok3')).not.toBeNull()
  })
})

describe('sweepRelay', () => {
  test('removes only expired relay pairs, keeps fresh ones', () => {
    seedRelay('fresh', { kind: 'secret', name: 's' }, 0)
    seedRelay('stale', { kind: 'secret', name: 's' }, 90_000)
    sweepRelay()
    expect(localStorage.getItem('kd_ref_fresh')).not.toBeNull()
    expect(localStorage.getItem('kd_ref_stale')).toBeNull()
    expect(localStorage.getItem('kd_ref_stale_exp')).toBeNull()
  })

  test('is idempotent: a second sweep changes nothing', () => {
    seedRelay('fresh', { kind: 'secret', name: 's' }, 0)
    sweepRelay()
    const snapshot = { ...localStorage }
    sweepRelay()
    expect({ ...localStorage }).toEqual(snapshot)
  })

  test('an orphaned body without its _exp key is swept (unverifiable expiry)', () => {
    localStorage.setItem('kd_ref_orphan', JSON.stringify({ kind: 'secret', name: 's', ts: 1, origin: 'post' }))
    sweepRelay()
    expect(localStorage.getItem('kd_ref_orphan')).toBeNull()
  })
})
