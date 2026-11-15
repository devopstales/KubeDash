/**
 * KubeDataTable sink tests (review 2026-10-28-vpa-views, security lens).
 *
 * The REAL component — not the view-test fake
 * (tests/components/kube-data-table.test-utils.tsx): the fake renders cell
 * values as React text children, which would mask the DataTables display
 * path under test.
 *
 * DataTables' writeCell appends a DOM node but writes a plain string with
 * cell.html() (innerHTML). Cluster content in a `data` column (e.g. a VPA's
 * spec.targetRef.kind) or in a renderer's string return could otherwise
 * plant live markup (stored XSS — the kind's CRD field is a plain string,
 * verified accepted verbatim by the API server).
 */
import React from 'react'
import { render, waitFor } from '@testing-library/react'
import { expect, test } from 'vitest'
import KubeDataTable, { Column } from '../../src/components/KubeDataTable'

const XSS = '<img src="x" data-flag="dt-xss">'

const firstRowCells = (tableId: string): HTMLElement[] =>
  Array.from(document.querySelector(`#${tableId} tbody tr`)?.children ?? []) as HTMLElement[]

const assertEscaped = async (tableId: string) => {
  const cells = await waitFor(() => {
    const c = firstRowCells(tableId)
    expect(c.length).toBeGreaterThan(0)
    return c
  })
  expect(cells[0].textContent).toContain(XSS)
  expect(cells[0].querySelector('img[data-flag="dt-xss"]')).toBeNull()
}

test('escapes-html-in-plain-data-cells', async () => {
  render(
    <KubeDataTable id="kd-dt-esc-plain" data={[{ name: XSS }]}>
      <Column title="Name" data="name" />
    </KubeDataTable>,
  )
  await assertEscaped('kd-dt-esc-plain')
})

test('escapes-string-returns-from-function-renderers', async () => {
  render(
    <KubeDataTable id="kd-dt-esc-fn" data={[{ name: XSS }]}>
      <Column title="Name" data="name">
        {(v: unknown) => (typeof v === 'string' ? v : '')}
      </Column>
    </KubeDataTable>,
  )
  await assertEscaped('kd-dt-esc-fn')
})

test('keeps-element-renderers-as-dom-nodes', async () => {
  render(
    <KubeDataTable id="kd-dt-esc-el" data={[{ name: 'x' }]}>
      <Column title="Name" data={null}>
        {(row: { name: string }) => <span data-flag="dt-el">{row.name}</span>}
      </Column>
    </KubeDataTable>,
  )
  await waitFor(() =>
    expect(document.querySelector('#kd-dt-esc-el span[data-flag="dt-el"]')).not.toBeNull(),
  )
})

test('passes-plain-text-and-numbers-through', async () => {
  render(
    <KubeDataTable id="kd-dt-esc-passthrough" data={[{ s: 'hello world', n: 42 }]}>
      <Column title="S" data="s" />
      <Column title="N" data="n" />
    </KubeDataTable>,
  )
  const cells = await waitFor(() => {
    const c = firstRowCells('kd-dt-esc-passthrough')
    expect(c.length).toBe(2)
    return c
  })
  expect(cells[0].textContent).toBe('hello world')
  expect(cells[1].textContent).toBe('42')
})
