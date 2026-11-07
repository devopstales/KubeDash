/**
 * Minimal JSON -> YAML emitter for the Gateway API converter's per-resource
 * preview (ADR-0020: no third-party YAML dependency; the converter output is
 * plain nested dicts/arrays/scalars). Deterministic: object keys render in
 * insertion order. Double-quoted scalars use JSON escaping (a valid YAML
 * double-quoted escape set), so the preview round-trips for every value the
 * converter can emit.
 */

const PLAIN_SAFE = /^[A-Za-z_][A-Za-z0-9.:_-]*$/
// YAML 1.1 booleans / null / numbers: a plain scalar matching these would
// parse back as a non-string, so quote them.
const KEYWORD_OR_NUMBER =
  /^(null|~|true|false|yes|no|on|off|[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?|0x[0-9a-fA-F]+|0o[0-7]+|[-+]?\.(inf|Inf|INF)|\.(nan|NaN|NAN))$/

const quote = (s: string): string => JSON.stringify(s)

const scalar = (v: unknown): string => {
  if (v === null || v === undefined) return 'null'
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  const s = String(v)
  if (s === '' || !PLAIN_SAFE.test(s) || KEYWORD_OR_NUMBER.test(s)) return quote(s)
  return s
}

const key = (k: string): string => (PLAIN_SAFE.test(k) && !KEYWORD_OR_NUMBER.test(k) ? k : quote(k))

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

const renderObject = (obj: Record<string, unknown>, indent: number): string => {
  const pad = '  '.repeat(indent)
  return Object.entries(obj)
    .map(([k, v]) => {
      if (isObj(v) && Object.keys(v).length > 0) {
        return `${pad}${key(k)}:\n${renderObject(v, indent + 1)}`
      }
      if (Array.isArray(v) && v.length > 0) {
        return `${pad}${key(k)}:\n${renderArray(v, indent + 1)}`
      }
      return `${pad}${key(k)}: ${isObj(v) ? '{}' : Array.isArray(v) ? '[]' : scalar(v)}`
    })
    .join('\n')
}

const renderArray = (arr: unknown[], indent: number): string => {
  const pad = '  '.repeat(indent)
  return arr
    .map((v) => {
      if (isObj(v) && Object.keys(v).length > 0) {
        // Block style: the first key sits on the dash line, the remaining
        // lines keep their indent+1 block indentation.
        const lines = renderObject(v, indent + 1).split('\n')
        const first = lines[0].slice('  '.repeat(indent + 1).length)
        const rest = lines.slice(1).join('\n')
        return `${pad}- ${first}${rest ? `\n${rest}` : ''}`
      }
      if (Array.isArray(v) && v.length > 0) return `${pad}-\n${renderArray(v, indent + 1)}`
      return `${pad}- ${isObj(v) ? '{}' : Array.isArray(v) ? '[]' : scalar(v)}`
    })
    .join('\n')
}

export function toYaml(value: unknown): string {
  if (isObj(value) && Object.keys(value).length > 0) return renderObject(value, 0)
  if (Array.isArray(value) && value.length > 0) return renderArray(value, 0)
  return scalar(value)
}
