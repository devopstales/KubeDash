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
