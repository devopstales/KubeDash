import React from 'react'
import type { Chart, Plugin } from 'chart.js'
import { CChart } from '@coreui/react-chartjs'
import { getStyle } from '@coreui/utils'

// Color model (Option C prototype): one base hue per resource (blue = CPU,
// amber = Memory). Used / Requests / Limits are progressively lighter tones
// of that hue (alpha 1.0 / 0.7 / 0.45). The part of a value OVER 100% of
// capacity is NOT in the ring (each ring's full 360° is the capacity) — it is
// shown as the RED overflow bar below (CoreUI danger token, ADR-0005).
//
// Certainty rule (AGENTS.md): `used` is a READ value (metrics.k8s.io). When
// it is null the metrics API is unreachable, so the center says "unknown" and
// the used ring is painted as empty track — never `0%`, never a healthy tone.
// requests/limits are DECLARED state (pod specs) and always render.

const DANGER = 'var(--cui-danger)'
const UNKNOWN_RING = 'rgba(128, 128, 128, 0.35)'
const TRACK_LIGHT = 'rgba(128, 128, 128, 0.12)'
const TRACK_DARK = 'rgba(128, 128, 128, 0.25)'

// ponytail: theme is read once per render from data-coreui-theme via
// @coreui/utils getStyle; AppHeader's useColorModes dispatches
// ColorSchemeChange on <html>, which re-renders this component and lets
// CChart's built-in update() pick up the new colors — no imperative
// destroy/redraw. A MutationObserver on the attribute would also work and is
// the upgrade path if another owner (not useColorModes) flips the attribute.
function useColorMode(): 'light' | 'dark' {
  const [mode, setMode] = React.useState<'light' | 'dark'>(() =>
    document.documentElement.getAttribute('data-coreui-theme') === 'dark' ? 'dark' : 'light',
  )
  React.useEffect(() => {
    const handler = () => {
      const dark = document.documentElement.getAttribute('data-coreui-theme') === 'dark'
      setMode(dark ? 'dark' : 'light')
    }
    document.documentElement.addEventListener('ColorSchemeChange', handler)
    return () => document.documentElement.removeEventListener('ColorSchemeChange', handler)
  }, [])
  return mode
}

/**
 * Center-text plugin factory (closure). The React wrapper (CChart) owns the
 * Chart.js lifecycle — the vanilla prototype stored `$pct`/`$sub` on the
 * instance, which is unsafe under React StrictMode double-mount. Receiving
 * the values via the closure makes afterDraw idempotent: every call repaints
 * the same text from the captured props.
 *
 * ponytail: `color` is resolved at render time and captured in the closure.
 * CChart v3's updateChart() does NOT re-register plugin instances — it only
 * copies data/options into the existing chart. The center text repaints on
 * every draw because afterDraw reads the closure's `color` directly, not a
 * stored instance property. A theme switch changes `color` → new closure →
 * new plugin array → CChart.update() → redraw with the new color.
 */
export function makeCenterText({
  pct,
  sub,
  color,
}: {
  pct: number | 'unknown'
  sub: string
  color: string
}): Plugin {
  const text = pct === 'unknown' ? 'unknown' : `${pct}%`
  return {
    id: 'kubedash-center-text',
    afterDraw(chart: Chart<'doughnut'>) {
      const arc = chart.getDatasetMeta(0).data[0] as { x: number; y: number } | undefined
      if (!arc) return
      const { x, y } = arc
      const ctx = chart.ctx
      ctx.save()
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillStyle = color
      ctx.font =
        pct === 'unknown' ? '600 0.85rem system-ui, sans-serif' : '600 1.3rem system-ui, sans-serif'
      ctx.fillText(text, x, y - 6)
      ctx.font = '400 0.62rem system-ui, sans-serif'
      ctx.fillText(sub, x, y + 12)
      ctx.restore()
    },
  }
}

const clampPct = (v: number, capacity: number) =>
  capacity > 0 ? Math.min(100, (v / capacity) * 100) : 0

export interface ConcentricDonutProps {
  /** Read (metrics.k8s.io) — null when the metrics API is unreachable. */
  used: number | null
  /** Declared (pod spec). */
  requests: number
  /** Declared (pod spec). */
  limits: number
  /** Node capacity. */
  capacity: number
  /** Base hue [r, g, b] (blue = CPU, amber = Memory). */
  hue: [number, number, number]
  /** Resource name (e.g. "CPU", "Memory") — shown in the overflow label. */
  label?: string
  ariaLabel: string
}

const ConcentricDonut = ({
  used,
  requests,
  limits,
  capacity,
  hue,
  label,
  ariaLabel,
}: ConcentricDonutProps) => {
  // Theme-aware: re-renders on ColorSchemeChange. The resolved colors below
  // flow into `data` and the centerText closure, so a theme switch changes
  // the data/options JSON → CChart.update() fires → chart redraws.
  const mode = useColorMode()
  const trackColor = mode === 'dark' ? TRACK_DARK : TRACK_LIGHT
  const bodyColor =
    getStyle('--cui-body-color', document.body) || (mode === 'dark' ? '#e5e7eb' : '#4e5860')

  const [r, g, b] = hue
  const ring = (val: number, alpha: number, label: string) => ({
    label,
    data: [clampPct(val, capacity), 100 - clampPct(val, capacity)],
    backgroundColor: [`rgba(${r}, ${g}, ${b}, ${alpha})`, trackColor],
    borderWidth: 0,
  })

  // Unknown used ring: empty track + gray tone, never 0% + healthy tone.
  const usedRing =
    used === null
      ? {
          label: 'Used',
          data: [0, 100],
          backgroundColor: [UNKNOWN_RING, trackColor],
          borderWidth: 0,
        }
      : ring(used, 1.0, 'Used')

  const data = {
    datasets: [
      ring(limits, 0.45, 'Limits'), // outer — lightest tone
      ring(requests, 0.7, 'Requests'), // middle
      usedRing, // inner — full tone (or unknown)
    ],
  }

  const options = {
    cutout: '40%',
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { enabled: false } },
  }

  // ponytail: the centerText plugin is rebuilt on every render so the closure
  // captures the fresh color (resolved from the current theme). CChart v3's
  // updateChart() copies data/options into the existing chart instance but
  // does NOT re-register plugin instances — the afterDraw hook repaints with
  // the closure's color on every draw. StrictMode double-mount is safe
  // because afterDraw is a pure draw with no stored state.
  const plugins = [
    makeCenterText({
      // The ring is a percentage of capacity — the center must be too.
      // `used` itself is a raw millicore/byte value: showing it as the pct
      // painted "247%" / "1141182364%" on a healthy cluster.
      pct: used === null ? 'unknown' : Math.round(clampPct(used, capacity)),
      sub: 'used',
      color: bodyColor,
    }),
  ]

  // M1: test-only capture plugin. The test file sets __kubedashCaptureCharts
  // before render; the plugin pushes the created chart there so the test can
  // assert on the config. In prod the flag is undefined → no-op.
  // vitest resolves chart.js to ESM while CChart bundles CJS — two separate
  // instance registries — so the static getChart lookup can't reach
  // CChart's chart from the test's import.
  const gl = globalThis as Record<string, unknown>
  if (Array.isArray(gl.__kubedashCaptureCharts)) {
    // __kubedashCaptureCenterText: the plugin instance itself. The chart
    // captured above belongs to CChart's chart.js registry (CJS) while the
    // test's import is ESM — two registries, so chart._plugins.get() from the
    // test side can't see this instance. Storing the plugin object directly
    // sidesteps the split.
    gl.__kubedashCaptureCenterText = plugins[0]
    plugins.push({
      id: 'kubedash-capture',
      afterInit(chart: Chart) {
        ;(gl.__kubedashCaptureCharts as Chart[]).push(chart)
      },
    })
  }

  // Over-capacity bar. Certainty rule: when `used` is null the used term is
  // SKIPPED (0, not NaN) — the bar is computed from requests/limits only.
  // M3: capacity <= 0 → no capacity read → skip the bar, label says so.
  const hasCapacity = capacity > 0
  const over = (v: number) => Math.max(0, v - capacity) / capacity
  const overRequest = hasCapacity ? over(requests) : 0
  const overLimit = hasCapacity ? over(limits) : 0
  const overUsed = used === null ? 0 : hasCapacity ? over(used) : 0
  const maxOver = Math.max(overRequest, overLimit, overUsed)
  const parts: string[] = []
  if (overRequest > 0) parts.push(`requests +${Math.round(overRequest * 100)}%`)
  if (overLimit > 0) parts.push(`limits +${Math.round(overLimit * 100)}%`)
  const overflowLabel = !hasCapacity ? 'no capacity' : parts.length ? parts.join(' · ') : 'none'

  return (
    <div>
      <CChart
        type="doughnut"
        data={data}
        options={options}
        plugins={plugins}
        aria-label={ariaLabel}
        customTooltips={false}
        height={200}
        width={200}
        style={{ width: '100%', height: '200px' }}
      />
      <div className="overflow-wrap" style={{ marginTop: '0.6rem', width: '100%' }}>
        <div
          className="overflow-label"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            fontSize: '.68rem',
            marginBottom: '.2rem',
          }}
        >
          <span className="text-muted">{label ? `${label} — Over capacity` : 'Over capacity'}</span>
          <span data-testid="overflow-label">{overflowLabel}</span>
        </div>
        {hasCapacity && maxOver > 0 && (
          <div
            className="overflow-track"
            style={{
              height: '8px',
              borderRadius: '4px',
              background: 'rgba(128,128,128,0.18)',
              overflow: 'hidden',
            }}
          >
            <div
              data-testid="overflow-bar"
              style={{
                height: '100%',
                background: DANGER,
                width: `${Math.min(100, maxOver * 100)}%`,
              }}
            />
          </div>
        )}
      </div>
    </div>
  )
}

export default ConcentricDonut
