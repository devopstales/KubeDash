import React from 'react'
import DataTable, { Column } from 'datatables.net-react'
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
}: {
  data: object[]
  children: React.ReactNode
  /** Optional table id (lets a view scope CSS, e.g. the events table wrap). */
  id?: string
  /** Extra classes merged with the default `table table-bordered`. */
  className?: string
}) => (
  <DataTable
    data={data}
    id={id}
    className={className ? `table table-bordered ${className}` : 'table table-bordered'}
    options={tableOptions as React.ComponentProps<typeof DataTable>['options']}
  >
    {children}
  </DataTable>
)

export default KubeDataTable
