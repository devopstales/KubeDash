import { formatTimestamp } from '../src/lib/format'

test('formatTimestamp renders browser-local time, not raw ISO', () => {
  // pinned with a fixed input; the assertion is locale-stable:
  const ts = '2026-10-26T10:00:00Z'
  const out = formatTimestamp(ts)
  expect(out).not.toContain('T') // not the raw ISO string
  expect(out).toMatch(/2026/) // the date is present
})

test('formatTimestamp handles null and invalid input', () => {
  expect(formatTimestamp(null)).toBe('—')
  expect(formatTimestamp('not-a-date')).toBe('—')
})
