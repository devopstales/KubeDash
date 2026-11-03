import React from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { mintToken, readRegistry, setActiveRef, writeRegistry } from '../lib/objectRef'
import { useClusterStore } from '../store/cluster'

export interface OldDataRedirectProps {
  /** Registry kind, e.g. 'secret'. The kind the detail render requires. */
  kind: string
  /** Clean list route, e.g. '/security/legacy-secret'. */
  listRoute: string
  /** True for cluster-scoped kinds: no ?namespace= is read (ref carries none). */
  clusterScoped?: boolean
  /**
   * network-policy only: the registry kind is the policy's API kind (R6 —
   * the detail read maps the kind to its resource plural), so the legacy
   * ?kind= param names the kind; when absent it falls back to `kind`.
   */
  kindFromParam?: boolean
}

/**
 * ADR-0040 TICKET-07 (R7): the legacy /.../data route is now a REDIRECT,
 * not a primary route — the old URL still works, it just lands on the clean
 * route's ref-driven detail.
 *
 * Reads the legacy ?name=/?namespace= (and ?kind= for network-policy)
 * query params, hydrates the sessionStorage object ref with
 * `origin: 'link'` (the URL was the identity carrier; the click path uses
 * 'click', the cross-tab POST uses 'post'), and <Navigate>s to the clean
 * route with replace. The ObjectRoute at the clean route renders the detail
 * from that ref (R6) — identity now rides the registry, never the URL (R1).
 *
 * namespace semantics match the pre-migration views (4.1 parity):
 * - namespaced kinds: ?namespace= → header's selectedNamespace → 'default';
 * - cluster-scoped kinds: no namespace at all (the ref carries none).
 */
const OldDataRedirect: React.FC<OldDataRedirectProps> = ({
  kind,
  listRoute,
  clusterScoped = false,
  kindFromParam = false,
}) => {
  const [params] = useSearchParams()
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)

  const reg = readRegistry()
  const token = mintToken()
  const ref = {
    kind: kindFromParam ? (params.get('kind') ?? kind) : kind,
    name: params.get('name') ?? '',
    namespace: clusterScoped
      ? undefined
      : params.get('namespace') || selectedNamespace || 'default',
    ts: Date.now(),
    origin: 'link' as const,
  }
  reg[token] = ref
  writeRegistry(reg)
  setActiveRef(token)

  return <Navigate to={listRoute} replace />
}

export default OldDataRedirect
