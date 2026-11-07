/**
 * Shared KubeDataTable fake for the view-test fleet (TICKET-05).
 *
 * Faithful to the datatables.net-react quirk that bit the Usage column:
 * the real wrapper binds Column render fns to the table instance only at
 * INITIALISATION and re-renders cells only when the data prop changes. A
 * render fn closing over a second query's data goes stale when that query
 * resolves after the list (cell stuck at "—" until a remount). The fake
 * therefore captures the column definitions on first render and renders
 * the CURRENT data with the CAPTURED render fns — join-in-the-row (pure
 * render fns) is the only way cells update, exactly like the real
 * component.
 *
 * Cell contract (the union of the inline variants this replaced, matching
 * the real wrapper's slotRenderer):
 * - a Column with `data={null}` (or no `data` prop) hands the render fn
 *   the WHOLE row — the datatables.net-react contract; a string key looks
 *   up the cell value.
 * - the render fn is called with the arity the real wrapper dispatches:
 *   3-arg fns get (data, 'display', row) — some views read `row` from the
 *   third arg — 1/2-arg fns get (data, row).
 * - a Column whose children are not a function renders the raw cell value.
 *
 * Tests keep their own canned data and their own `vi.mock`; only the fake
 * is shared. The mock factory must stay async: a hoisted `vi.mock` may not
 * touch module-scope consts, so the shared module is imported inside it.
 */
import React from 'react'

/** The real DataTables column callback shape (data, type, row). */
export type KubeDataTableRenderFn = (
  data: unknown,
  type: string,
  row: Record<string, unknown>,
) => React.ReactNode

type ColProps = { title: string; data: string | null; children?: unknown }

export const Column = () => null

export const KubeDataTable = ({
  data,
  children,
}: {
  data: Record<string, unknown>[]
  children: React.ReactNode
}) => {
  // The real wrapper captures the column definitions at table init and
  // never re-reads them — replicate that here.
  const colsRef = React.useRef<ColProps[] | null>(null)
  if (colsRef.current === null) {
    colsRef.current = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map((child) => (child as React.ReactElement<ColProps>).props)
  }
  const cols = colsRef.current
  return (
    <table>
      <thead>
        <tr>
          {cols.map((col) => (
            <th key={col.title}>{col.title}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, i) => (
          <tr key={i}>
            {cols.map((col) => {
              const value = col.data == null ? row : row[col.data]
              const node =
                typeof col.children === 'function'
                  ? (col.children as KubeDataTableRenderFn).length >= 3
                    ? (col.children as KubeDataTableRenderFn)(value, 'display', row)
                    : ((col.children as (v: unknown, r: Record<string, unknown>) => React.ReactNode)(
                        value,
                        row,
                      ))
                  : (value as React.ReactNode)
              return <td key={col.title}>{node ?? ''}</td>
            })}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
