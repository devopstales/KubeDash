import React from 'react'
import { postObjectToTab } from '../lib/objectRef'

interface ShareObjectButtonProps {
  /** Registry kind, e.g. 'priorityclass'. */
  kind: string
  /** Object name (never in the URL; the relay carries it). */
  name: string
  /** Object namespace (cluster-scoped kinds pass undefined). */
  namespace?: string
  /** The clean list route the new tab lands on (R4). */
  listRoute: string
}

/**
 * ⧉ share button (ADR-0040): `postObjectToTab` opens a hidden same-origin
 * form POST to `listRoute` in a new tab; the relay (localStorage,
 * token-scoped, 60 s) carries the identity and the form body carries only
 * the opaque token. The URL stays clean in the new tab (R4).
 *
 * Placed in list-row name cells and in each data-page header.
 */
const ShareObjectButton: React.FC<ShareObjectButtonProps> = ({ kind, name, namespace, listRoute }) => (
  <button
    type="button"
    className="btn btn-sm btn-link text-secondary p-0"
    title="Share this object"
    aria-label={`Share ${name}`}
    onClick={() => postObjectToTab(kind, name, namespace, listRoute)}
  >
    ⧉
  </button>
)

export default ShareObjectButton
