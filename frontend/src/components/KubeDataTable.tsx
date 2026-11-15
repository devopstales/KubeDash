import React, { Children, cloneElement, isValidElement, useEffect, useRef } from 'react'
import DataTable, { Column, type DataTableRef } from 'datatables.net-react'
import DT from 'datatables.net-bs5'
import 'datatables.net-bs5/css'

/**
 * 4.1 list grid (ADR-0023): DataTables React with the Bootstrap 5 skin
 * 4.1 already loads (`dataTables.bootstrap5`), inside a CoreUI card.
 * `responsive` and `pageLength: 25` match `users/user.html.j2`.
 */
DataTable.use(DT)

const tableOptions = { responsive: true, pageLength: 25 }

export { Column }

// DataTables' display path (writeCell) appends a DOM node but writes a plain
// string with cell.html() (innerHTML) — cluster content in a `data` column
// (e.g. a VPA's spec.targetRef.kind) or in a renderer's string return could
// otherwise plant live markup (stored XSS; review 2026-10-28-vpa-views).
// Escape string outputs at this shared sink; element returns are untouched
// (the wrapper portals them to real DOM nodes, which writeCell appends) and
// non-strings pass through exactly as before.
const escapeString = (v: unknown) => (typeof v === 'string' ? DT.util.escapeHtml(v) : v)

// The wrapper's slotRenderer dispatches on the renderer's ARITY (4/3-arg fns
// get (data, type, row, meta); shorter fns a 2-arg cached call), so the
// escaping wrapper must expose arity 4 to preserve the dispatch.
const escapeRenderer =
  (fn: (...args: unknown[]) => unknown) =>
  (data: unknown, type: unknown, row: unknown, meta: unknown) =>
    escapeString(fn(data, type, row, meta))

const escapeColumns = (children: React.ReactNode): React.ReactNode =>
  Children.map(children, (child) => {
    if (!isValidElement(child)) return child
    const col = child as React.ReactElement<{
      data?: unknown
      render?: unknown
      children?: unknown
    }>
    if (typeof col.props.children === 'function') {
      return cloneElement(col, {
        children: escapeRenderer(col.props.children as (...args: unknown[]) => unknown),
      })
    }
    if (col.props.render === undefined && col.props.data !== undefined && col.props.children === undefined) {
      // A plain data column: DataTables would cell.html() the raw value.
      return cloneElement(col, { render: escapeString })
    }
    return child
  })

const KubeDataTable = ({
  data,
  children,
  id,
  className,
  onRowClick,
}: {
  data: object[]
  children: React.ReactNode
  /** Optional table id (lets a view scope CSS, e.g. the events table wrap). */
  id?: string
  /** Extra classes merged with the default `table table-bordered`. */
  className?: string
  /** Optional full-row click handler (4.1 list rows navigate on click). */
  onRowClick?: (row: object, event: Event) => void
}) => {
  const ref = useRef<DataTableRef>(null)
  // Keep the latest handler without re-binding the DataTables listener on
  // every parent render (views pass an inline arrow = new identity each
  // render). The listener itself is bound once and stays valid across the
  // component's clear/rows.add/draw data refresh (same API instance for
  // the component's lifetime).
  const onRowClickRef = useRef(onRowClick)
  useEffect(() => {
    onRowClickRef.current = onRowClick
  }, [onRowClick])
  useEffect(() => {
    const dt = ref.current?.dt()
    if (!dt) return
    const fn = (event: Event) => {
      const handler = onRowClickRef.current
      if (!handler) return
      const target = event.target instanceof HTMLElement ? event.target : null
      const tr = target?.closest('tbody tr')
      if (!tr) return
      const row = dt.row(tr)
      if (!row.any()) return
      handler(row.data() as object, event)
    }
    dt.on('click', 'tbody tr', fn)
    return () => {
      dt.off('click', 'tbody tr', fn)
    }
  }, [])
  return (
    <DataTable
      ref={ref}
      data={data}
      id={id}
      className={className ? `table table-bordered ${className}` : 'table table-bordered'}
      options={tableOptions as React.ComponentProps<typeof DataTable>['options']}
    >
      {escapeColumns(children)}
    </DataTable>
  )
}

export default KubeDataTable
