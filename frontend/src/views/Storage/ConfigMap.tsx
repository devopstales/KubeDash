import { useNavigate } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import { formatTimestamp } from '../../lib/format'
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { ConfigMapItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders.
const KIND = 'configmap'
const LIST_ROUTE = '/storage/configmap'

type ConfigMapRow = {
  name: string
  namespace: string
  dataKeys: string
  created: string
}

const toRow = (item: ConfigMapItem, namespace: string): ConfigMapRow => ({
  name: item.metadata?.name ?? '',
  // The list read is namespaced, but the row's own namespace wins when
  // present (the openObject ref must follow the row, not the store).
  namespace: item.metadata?.namespace ?? namespace,
  // The Data Keys column is the count of ``data`` keys (4.1's list showed
  // Name/Created only; this is the one ratified addition — the count is
  // free because ``data`` is on the list read, NOT stripped, unlike
  // secrets). ``0`` is a valid count (rendered as "0", NOT "—"); "—" only
  // when ``data`` is entirely absent. ``binaryData`` is NOT counted
  // (4.1's list read projected only ``data``).
  dataKeys: item.data == null ? '—' : String(Object.keys(item.data).length),
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: ConfigMapRow, selected: string | null, navigate: (p: string) => void) =>
  row.name ? (
    <>
      <button
        type="button"
        className={
          'btn btn-link btn-sm p-0 text-primary text-decoration-underline' +
          (row.name === selected ? ' fw-bold' : '')
        }
        aria-current={row.name === selected ? 'true' : undefined}
        onClick={() => openObject(KIND, row.name, row.namespace, LIST_ROUTE, navigate)}
      >
        {row.name}
      </button>
    </>
  ) : null

/**
 * 4.1 `storage/configmap.html.j2` parity: ConfigMaps in the
 * header-selected namespace (the ResourceQuota pattern — the namespace
 * comes from the selected-namespace store, `?? 'default'`; 4.1's
 * `session['ns_select']` hidden form is the ratified ADR-0040 objectRef
 * delta, briefing.md). A name opens the configmap data page via
 * openObject (ADR-0040): the URL never carries object identity (R1). The
 * card title is EXACTLY "Configmaps List": 4.1's casing verbatim (the
 * e2e smoke contract; the nav label stays "ConfigMaps"). The list stays
 * 4.1-sparse (Name / Created) plus the one ratified addition, a
 * `Data Keys` count column — the count is free because `data` is on the
 * list read, NOT stripped (a ConfigMap's `data` is public, unlike a
 * Secret's).
 */
const ConfigMapView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<ConfigMapRow[]>({
    queryKey: ['configmaps', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ConfigMapItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/configmaps?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem active>Configmaps List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Configmaps List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading configmaps...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading configmaps: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No configmaps found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as ConfigMapRow, selected, navigate)}
            </Column>
            <Column title="Data Keys" data="dataKeys" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ConfigMapView
