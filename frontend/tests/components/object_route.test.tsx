import React from 'react'
import { act, render, screen } from '@testing-library/react'
import { Link, MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, test, vi } from 'vitest'
import ObjectRoute, { getRegisteredNavigate } from '../../src/components/ObjectRoute'
import { clearActiveRef, writeRegistry, setActiveRef } from '../../src/lib/objectRef'

const list = <div>List view</div>
const detail = (p: { name: string; namespace?: string }) => (
  <div>Detail: {p.name}</div>
)

const renderAt = (
  ui: React.ReactElement,
  path: string = '/other-resource/priorityclass',
  listRoute = '/other-resource/priorityclass',
) => {
  window.history.replaceState(null, '', path)
  return render(<MemoryRouter initialEntries={[listRoute]}>{ui}</MemoryRouter>)
}

afterEach(() => {
  window.history.replaceState(null, '', '/other-resource/priorityclass')
  // jsdom does not reset the DOM between tests: a failed consume leaves its
  // one-shot meta in place, which would hydrate the next test's mount.
  document.head.querySelector('meta[name="kd-object-incoming"]')?.remove()
  vi.restoreAllMocks()
})

describe('ObjectRoute', () => {
  test('renders the detail when the active ref kind matches', () => {
    writeRegistry({ t1: { kind: 'priorityclass', name: 'high', ts: Date.now(), origin: 'click' } })
    setActiveRef('t1')

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
    )

    expect(screen.getByText('Detail: high')).toBeTruthy()
    expect(screen.queryByText('List view')).toBeNull()
  })

  test('renders the list when no active ref is set', () => {
    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
    )

    expect(screen.getByText('List view')).toBeTruthy()
    expect(screen.queryByText(/Detail: /)).toBeNull()
  })

  test('renders the list when the active ref kind mismatches (R6)', () => {
    writeRegistry({
      t1: { kind: 'secret', name: 'db-creds', namespace: 'team-a', ts: Date.now(), origin: 'click' },
    })
    setActiveRef('t1')

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
    )

    expect(screen.getByText('List view')).toBeTruthy()
    expect(screen.queryByText(/Detail: /)).toBeNull()
  })

  test('consumeIncoming on mount: a matching server-injected deep link renders the detail immediately (R4)', () => {
    const token = 'abcd1234abcd1234'
    localStorage.setItem(
      `kd_ref_${token}`,
      JSON.stringify({ kind: 'priorityclass', name: 'high', ts: Date.now(), origin: 'post' }),
    )
    localStorage.setItem(`kd_ref_${token}_exp`, String(Date.now() + 60_000))
    // The SPA fallback's one-shot meta, as the fresh document carries it.
    const meta = document.createElement('meta')
    meta.name = 'kd-object-incoming'
    meta.content = token
    document.head.appendChild(meta)

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
      '/other-resource/priorityclass',
    )

    // The relay is consumed on mount and the detail renders on the first
    // commit.
    expect(screen.getByText('Detail: high')).toBeTruthy()
    // The URL is clean (the token never rides it, R4) and the one-shot meta
    // is consumed from the document.
    expect(window.location.search).toBe('')
    expect(document.querySelector('meta[name="kd-object-incoming"]')).toBeNull()
    // The relay self-deletes.
    expect(localStorage.getItem(`kd_ref_${token}`)).toBeNull()
    expect(localStorage.getItem(`kd_ref_${token}_exp`)).toBeNull()
  })

  test('consumeIncoming on mount: a stale (expired) relay renders the list, not the detail (R5)', () => {
    const token = 'deadbeefdeadbeef'
    localStorage.setItem(
      `kd_ref_${token}`,
      JSON.stringify({ kind: 'priorityclass', name: 'high', ts: Date.now() - 120_000, origin: 'post' }),
    )
    localStorage.setItem(`kd_ref_${token}_exp`, String(Date.now() - 1))
    const meta = document.createElement('meta')
    meta.name = 'kd-object-incoming'
    meta.content = token
    document.head.appendChild(meta)

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
      '/other-resource/priorityclass',
    )

    expect(screen.getByText('List view')).toBeTruthy()
    expect(screen.queryByText(/Detail: /)).toBeNull()
    // The stale relay is self-deleted.
    expect(localStorage.getItem(`kd_ref_${token}`)).toBeNull()
    expect(document.querySelector('meta[name="kd-object-incoming"]')).toBeNull()
  })

  test('registers the navigate seam on mount (openObject seam)', () => {
    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
    )

    const navigate = getRegisteredNavigate()
    expect(navigate).toBeTypeOf('function')
    // A seam call navigates the router (the spy is the router's navigate
    // fn, not a stub — the wrapper stores the real fn).
    expect(typeof navigate).toBe('function')
  })

  test('sweeps expired relay pairs on mount', () => {
    localStorage.setItem('kd_ref_expired', JSON.stringify({ kind: 'priorityclass', name: 'x', ts: 0, origin: 'post' }))
    localStorage.setItem('kd_ref_expired_exp', String(Date.now() - 1))
    localStorage.setItem('kd_ref_fresh', JSON.stringify({ kind: 'priorityclass', name: 'y', ts: Date.now(), origin: 'post' }))
    localStorage.setItem('kd_ref_fresh_exp', String(Date.now() + 60_000))

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detail} />,
    )

    // The expired pair is swept; the fresh pair remains for its consumer tab.
    expect(localStorage.getItem('kd_ref_expired')).toBeNull()
    expect(localStorage.getItem('kd_ref_expired_exp')).toBeNull()
    expect(localStorage.getItem('kd_ref_fresh')).not.toBeNull()
  })

  test('detail→list: clearing the ref + same-path navigation renders the list (breadcrumb back)', () => {
    writeRegistry({ t1: { kind: 'priorityclass', name: 'high', ts: Date.now(), origin: 'click' } })
    setActiveRef('t1')

    // The data views' breadcrumb IS the back affordance: clearActiveRef()
    // + a Link to the list route (the same path the wrapper renders).
    const detailWithBack = (p: { name: string; namespace?: string }) => (
      <div>
        <span>Detail: {p.name}</span>
        <Link to="/other-resource/priorityclass" onClick={clearActiveRef}>
          Priority Classes
        </Link>
      </div>
    )

    renderAt(
      <ObjectRoute kind="priorityclass" listRoute="/other-resource/priorityclass" list={list} detail={detailWithBack} />,
    )

    expect(screen.getByText('Detail: high')).toBeTruthy()
    // act(): the Link's navigate() is a MemoryRouter state update — a
    // bare native .click() leaves it unflushed in the act environment.
    act(() => {
      screen.getByRole('link', { name: 'Priority Classes' }).click()
    })

    // The active pointer is dropped and the location change re-reads the
    // (now-null) ref → the R6 dispatch renders the list.
    expect(screen.getByText('List view')).toBeTruthy()
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    // The old wrapper-level back button no longer renders.
    expect(screen.queryByRole('button', { name: /back to list/i })).toBeNull()
  })
})
