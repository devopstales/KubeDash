import React from 'react'
import { render, screen } from '@testing-library/react'
import type { Chart, ChartConfiguration, Plugin } from 'chart.js'
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest'
import ConcentricDonut, {
  makeCenterText,
  type ConcentricDonutProps,
} from '../../src/components/ConcentricDonut'

// ponytail: jsdom's canvas getContext('2d') returns null (no layout), which
// Chart.js' DOM platform rejects. Stub a minimal 2d context so the chart
// creates, updates, and destroys in the test env. Add jsdom-canvas only if
// we start asserting on pixels.
const minimalContext = (): Record<string, unknown> => ({
  canvas: null,
  clearRect: () => {},
  save: () => {},
  restore: () => {},
  translate: () => {},
  rotate: () => {},
  scale: () => {},
  transform: () => {},
  setTransform: () => {},
  resetTransform: () => {},
  beginPath: () => {},
  closePath: () => {},
  moveTo: () => {},
  lineTo: () => {},
  arc: () => {},
  bezierCurveTo: () => {},
  quadraticCurveTo: () => {},
  rect: () => {},
  fill: () => {},
  stroke: () => {},
  clip: () => {},
  fillRect: () => {},
  strokeRect: () => {},
  setLineDash: () => {},
  getLineDash: () => [],
  lineDashOffset: 0,
  drawImage: () => {},
  measureText: () => ({ width: 0 }),
  createLinearGradient: () => ({ addColorStop: () => {} }),
  fillStyle: '',
  strokeStyle: '',
  font: '',
  textAlign: '',
  textBaseline: '',
  lineWidth: 1,
  lineCap: 'butt',
  lineJoin: 'miter',
  globalAlpha: 1,
})

// ponytail: Chart.js' DOM platform reads getComputedStyle on a detached
// canvas in jsdom (ownerDocument is null → throws). Fall back to a fixed-size
// style object for non-DOM elements.
const origGetComputedStyle = window.getComputedStyle.bind(window)
window.getComputedStyle = (el: Element | null, pseudo?: string | null) =>
  el && 'ownerDocument' in el
    ? (origGetComputedStyle(el, pseudo) as CSSStyleDeclaration)
    : ({
        width: '300px',
        height: '150px',
        maxWidth: '300px',
        maxHeight: '150px',
      } as unknown as CSSStyleDeclaration)

// The doughnut's 3 rings, outermost first (Chart.js draws dataset 0 outermost).
const RINGS = ['Limits', 'Requests', 'Used']

// ponytail: vitest resolves chart.js to ESM while CChart bundles its own CJS
// require — two separate Chart classes with independent instance registries.
// The capture plugin bridges them by pushing CChart's chart into our array.

const props = (over: Partial<ConcentricDonutProps> = {}) => ({
  used: 41,
  requests: 98,
  limits: 115,
  capacity: 100,
  hue: [22, 92, 255] as [number, number, number],
  ariaLabel: 'CPU used, requests, limits concentric donut',
  ...over,
})

describe('ConcentricDonut', () => {
  // Patch once per test file so the chart's initial mount gets a 2d context
  // and a ResizeObserver (Chart.js' responsive platform uses both).
  beforeAll(() => {
    const proto = window.HTMLCanvasElement.prototype as unknown as Record<string, unknown>
    proto.getContext = function (this: HTMLCanvasElement, type: string) {
      if (type !== '2d') return null
      const ctx = minimalContext() as Record<string, unknown>
      ctx.canvas = this
      return ctx
    }
    if (!window.ResizeObserver) {
      // ponytail: a no-op ResizeObserver is enough for Chart.js' DOM
      // platform; it only observes for resize events we never fire in tests.
      window.ResizeObserver = class {
        observe() {}
        unobserve() {}
        disconnect() {}
      } as unknown as typeof ResizeObserver
    }
  })

  afterEach(() => {
    const g = globalThis as Record<string, unknown>
    const arr = (g.__kubedashCharts as Chart[] | undefined) || []
    arr.forEach((c) => c.destroy())
    g.__kubedashCharts = []
  })

  const lastChart = () => {
    const g = globalThis as Record<string, unknown>
    const arr = (g.__kubedashCharts as Chart[] | undefined) || []
    return arr[arr.length - 1]
  }

  test('donut-renders-rings: 3 doughnut rings with progressively darker tones', () => {
    render(<ConcentricDonut {...props()} />)
    const chart = lastChart()
    expect(chart).toBeTruthy()

    // The chart is created by CChart's bundled CJS chart.js, not our ESM import.
    // Use the config from the chart instance directly.
    const config = chart!.config as unknown as ChartConfiguration<'doughnut'>
    expect(config.type).toBe('doughnut')
    const datasets = (config.data.datasets ?? []) as unknown as Record<string, unknown>[]
    expect(datasets.map((d) => d.label)).toEqual(RINGS)
    // Limits α=0.45 (outer), Requests α=0.7, Used α=1.0 (inner full tone).
    for (const [i, alpha] of [0.45, 0.7, 1].entries()) {
      expect((datasets[i].backgroundColor as string[])[0]).toBe(`rgba(22, 92, 255, ${alpha})`)
    }
    expect((chart!.options as Record<string, unknown>).cutout).toBe('40%')
    expect(
      screen.getByRole('img', { name: 'CPU used, requests, limits concentric donut' }),
    ).toBeTruthy()
  })

  test('donut-overcommit-red-bar: over-capacity requests size the danger bar', () => {
    const { container } = render(<ConcentricDonut {...props({ requests: 120, limits: 100 })} />)

    const bar = container.querySelector('[data-testid="overflow-bar"]') as HTMLElement
    expect(bar).toBeTruthy()
    // max(0, max(120, 100) − 100) / 100 = 20%
    expect(bar.style.width).toBe('20%')
    expect(bar.style.background).toBe('var(--cui-danger)')
    expect(screen.getByTestId('overflow-label')).toHaveTextContent('requests +20%')
  })

  test('dashboard-unknown-used: used=null → unknown center, bar from requests/limits only', () => {
    const { container } = render(
      <ConcentricDonut {...props({ used: null, requests: 120, limits: 180 })} />,
    )

    // Certainty rule: the used ring carries no read value — 0 is forbidden.
    const chart = lastChart()
    const datasets = (chart!.config.data.datasets ?? []) as unknown as Record<string, unknown>[]
    const usedRing = datasets[2] as Record<string, unknown>
    expect(usedRing.data).toEqual([0, 100])
    expect((usedRing.backgroundColor as string[])[0]).toBe('rgba(128, 128, 128, 0.35)')

    // The over-capacity bar skips the used term — limits 180/100 = +80%, no NaN.
    const bar = container.querySelector('[data-testid="overflow-bar"]') as HTMLElement
    expect(bar.style.width).toBe('80%')
    expect(Number.isNaN(parseFloat(bar.style.width))).toBe(false)
    expect(screen.getByTestId('overflow-label')).toHaveTextContent('limits +80%')
  })

  test('dashboard-renders-rows: no red overflow bar while requests are at or under capacity', () => {
    const { container } = render(
      <ConcentricDonut {...props({ used: 80, requests: 98, limits: 115, capacity: 200 })} />,
    )
    // All three terms (used 80, requests 98, limits 115) are under 200 → no bar.
    expect(container.querySelector('[data-testid="overflow-bar"]')).toBeFalsy()
  })

  test('makeCenterText: paints pct and sub, idempotent across re-draws', () => {
    // jsdom has no canvas 2d context — the plugin's draw target is faked.
    const fillText = vi.fn()
    const ctx = {
      save: vi.fn(),
      restore: vi.fn(),
      fillText,
      fillStyle: '',
      font: '',
      textAlign: '',
      textBaseline: '',
    } as unknown as CanvasRenderingContext2D

    // ponytail: the plugin reads --cui-body-color from the canvas owner at
    // draw time; a fake chart cannot carry one, so the fallback color is
    // what gets painted. Add jsdom-canvas only if we start asserting on pixels.
    const fakeChart = () =>
      ({
        getDatasetMeta: () => ({ data: [{ x: 100, y: 100 }] }),
        ctx,
        canvas: null,
      }) as unknown as Chart<'doughnut'>

    const plugin = makeCenterText({ pct: 41, sub: 'used' })
    expect(plugin.id).toBe('kubedash-center-text')

    // ponytail: chart.js 4.5.1 type definitions declare afterDraw with 3
    // parameters (chart, args, options) but the runtime `notify` calls it
    // with exactly those 3 — the extra args/options are always passed.
    const draw = () => plugin.afterDraw?.(fakeChart(), {}, {})

    draw()
    expect(fillText).toHaveBeenNthCalledWith(1, '41%', 100, 94)
    expect(fillText).toHaveBeenNthCalledWith(2, 'used', 100, 112)
    expect((ctx as unknown as Record<string, unknown>)['fillStyle']).toBe('#4e5860')

    // React StrictMode double-mounts: a second afterDraw must not throw and
    // must re-paint the same text (idempotent, no stored instance state).
    fillText.mockClear()
    expect(() => draw()).not.toThrow()
    expect(fillText).toHaveBeenCalledTimes(2)
  })
})
