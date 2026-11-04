import React, { useEffect, useMemo, useReducer, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { consumeIncoming, getActiveRef, openObject, sweepRelay } from '../lib/objectRef'
import type { ObjectRef } from '../lib/objectRef'

export interface ObjectRouteProps {
  /** Registry kind, e.g. 'priorityclass'. The detail renders only for a ref of THIS kind (R6). */
  kind: string
  /** Clean list route, e.g. '/other-resource/priorityclass'. */
  listRoute: string
  /** The list view, rendered when no ref of this kind is active. */
  list: React.ReactNode
  /** The detail view; identity arrives from the active ref, never from useSearchParams (R8). */
  detail: (params: { name: string; namespace?: string }) => React.ReactNode
}

/**
 * One wrapper per kind (ADR-0040): renders the LIST when the active ref is
 * absent or its kind mismatches; renders the DETAIL when it matches (R6).
 *
 * - mount: `consumeIncoming()` resolves a cross-tab server-injected handoff
 *   (R4 deep link — the one-shot meta + relay self-delete on consumption)
 *   and `sweepRelay()` drops expired relay pairs; a matching incoming ref
 *   makes the detail render on the first commit.
 * - the active ref's namespace is authoritative for the detail (R8):
 *   `detail` receives `{ name, namespace }` from the ref, never from the URL.
 * - history: list→detail is `openObject`'s navigate(listRoute) push;
 *   detail→list is the data view's breadcrumb list item (it clears the
 *   active ref; the URL is already the clean list route).
 * - on mount, registers the router's navigate fn (openObject's seam — the
 *   lib stays router-free); list views call `openObject(kind, name, ns,
 *   listRoute, navigate)` with their own `useNavigate()` (same seam).
 */

const ObjectRoute: React.FC<ObjectRouteProps> = ({ kind, listRoute, list, detail }) => {
  const navigate = useNavigate()
  const location = useLocation()

  // The incoming relay self-deletes on consumption, so consumeIncoming()
  // must run exactly once per mount (the first useState pass); the incoming
  // ref (if any) is cached in instance state so a later re-read
  // (post-navigation) does not re-consume (and re-strip) the relay.
  const [incoming] = useState<ObjectRef | null>(() => consumeIncoming())
  // Bumped by the registered navigate seam: openObject sets the active
  // pointer then navigates to the list route (the SAME path the wrapper
  // already renders), so a plain location memo would not re-run. The seam
  // bumps this state so the ref is re-read and the detail renders.
  const [, bump] = useReducer((c: number) => c + 1, 0)

  // Resolve the active ref: the cached incoming ref (cross-tab server
  // handoff) or the tab-private active pointer, re-read on every navigation
  // (location change or seam bump) so a list→detail openObject renders the
  // detail on the next commit.
  const ref = useMemo(
    () => incoming ?? getActiveRef(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [location, bump, incoming],
  )
  const matches = ref !== null && ref.kind === kind

  // Register the navigate seam + sweep expired relay pairs once on mount.
  const seamRef = useRef(navigate)
  seamRef.current = navigate
  useEffect(() => {
    sweepRelay()
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])

  if (!matches) {
    return <>{list}</>
  }

  return detail({ name: ref.name, namespace: ref.namespace })
}

// The router's navigate fn, registered by the mounted ObjectRoute (openObject's
// seam — the lib is router-free). The legacy /data route's OldDataRedirect
// (TICKET-07) reads it after the wrapper registers it; the view itself always
// has the fn directly via useNavigate, so this is the redirect path's seam.
let registeredNavigate: ((path: string) => void) | null = null

export function getRegisteredNavigate(): ((path: string) => void) | null {
  return registeredNavigate
}

// The navigate seam's writer. ObjectRoute registers it on mount; the
// network-policy dispatcher (App.tsx, TICKET-03) does the same because it
// matches the active ref against THREE kinds in one component (a single
// ObjectRoute renders one list, but its fixed `kind` could only match one).
export function registerNavigate(fn: ((path: string) => void) | null): void {
  registeredNavigate = fn
}

export { openObject }

export default ObjectRoute
