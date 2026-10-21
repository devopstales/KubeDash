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

const KubeDataTable = ({ data, children }: { data: object[]; children: React.ReactNode }) => (
  <DataTable
    data={data}
    className="table table-bordered"
    options={tableOptions as React.ComponentProps<typeof DataTable>['options']}
  >
    {children}
  </DataTable>
)

export default KubeDataTable
