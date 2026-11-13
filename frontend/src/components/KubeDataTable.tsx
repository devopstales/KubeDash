import React, { useEffect, useRef } from 'react'
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
      {children}
    </DataTable>
  )
}

export default KubeDataTable
