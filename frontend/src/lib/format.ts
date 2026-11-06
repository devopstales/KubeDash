/** Render a Kubernetes creationTimestamp in the BROWSER's local time
 * (Decision note: the user reads the dashboard in their timezone — if
 * that is CET, CET). Not ISO: a raw `T`-string is the 4.1 shape, not the
 * chosen one. `null`/unparseable -> "—" (certainty rule: no fake dates).
 */
export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString()
}

/** Render a creationTimestamp as a k8s-style relative age for the list's
 * Age column: `3d` / `5h` / `2m` / `42s`, "—" when absent/unparseable
 * (certainty rule: no fake ages). The exact timestamp lives in the data
 * view's CTable + JSON block; the Age column is the 4.1 list shape for the
 * Gateway API kinds (no raw ISO in a list cell).
 */
export function formatAge(ts: string | null | undefined): string {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  const days = Math.floor(seconds / 86400)
  if (days > 0) return `${days}d`
  const hours = Math.floor(seconds / 3600)
  if (hours > 0) return `${hours}h`
  const minutes = Math.floor(seconds / 60)
  if (minutes > 0) return `${minutes}m`
  return `${seconds}s`
}
