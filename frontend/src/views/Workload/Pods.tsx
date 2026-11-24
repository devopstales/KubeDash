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
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { Pod, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (singular API resource name) and the clean
// list route this view renders (the pods-deployments-views change).
const KIND = 'pod'
const LIST_ROUTE = '/workload/pods'

type PodRow = {
  name: string
  namespace: string
  status: string
  podIp: string
  owner: string
}

// 4.1's effective phase (workload.py k8sPodListGet): status.phase,
// overridden to `Terminated` when metadata.deletion_timestamp is set (the
// pod is mid-deletion — the phase still says Running but the pod is going
// away). 5.0's badge mapping (the 4.1 four-tier + Terminated red):
// Running -> success, Pending -> warning, Succeeded -> secondary,
// Terminated/CrashLoopBackOff -> danger, else info.
const effectivePhase = (pod: Pod): string =>
  pod.metadata?.deletion_timestamp ? 'Terminated' : (pod.status?.phase ?? '')

const PHASE_BADGE: Record<string, string> = {
  Running: 'badge-success',
  Pending: 'badge-warning',
  Succeeded: 'badge-secondary',
  Terminated: 'badge-danger',
  CrashLoopBackOff: 'badge-danger',
}

// The 5.0 owner cell (the Service data page's podOwner precedent): the
// first owner reference as `kind.lower() + "/" + name` — plain text (the
// owning-workload views are other not-yet-landed changes; the 4.1 hidden-
// form owner POST is the ADR-0040 objectRef delta). "—" when absent.
const ownerOf = (pod: Pod): string => {
  const ref = pod.metadata?.owner_references?.[0]
  if (!ref) return '—'
  return `${String(ref.kind ?? '').toLowerCase()}/${ref.name ?? ''}`
}

const toRow = (item: Pod, namespace: string): PodRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: an all-namespaces list would carry mixed
  // namespaces, and the name link must follow the row, not the store.
  namespace: item.metadata?.namespace ?? namespace,
  status: effectivePhase(item),
  podIp: item.status?.pod_ip ?? '—',
  owner: ownerOf(item),
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). The bold is driven by the active ref
// (R9).
const nameCell = (row: PodRow, selected: string | null, navigate: (p: string) => void) =>
  row.name ? (
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
  ) : null

/**
 * 4.1 `workload/pod.html.j2` parity: Pods in the header-selected namespace
 * (the Secret pattern — the namespace comes from the selected-namespace
 * store, `?? 'default'`; 4.1's `session['ns_select']` hidden form is the
 * ratified ADR-0040 objectRef delta, briefing.md). A name opens the data
 * page via openObject (ADR-0040): the URL never carries object identity
 * (R1). The card title is EXACTLY "Pod List": the e2e smoke asserts that
 * string with exact: true. 4.1 deviations (recorded in the change's
 * adr.md): the Report columns + the delete action are commented out in
 * 4.1 (not ported); the Owner cell is plain text (the owning-workload
 * views are not yet landed); the 4.1 hidden-form Name POST is the ADR-0040
 * openObject delta.
 */
const PodsWorkloadView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<PodRow[]>({
    queryKey: ['workload-pods', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<Pod>>(
        `/api/v1/clusters/${cluster!.id}/resources/pods?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Workloads</CBreadcrumbItem>
          <CBreadcrumbItem active>Pod List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pods...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading pods: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No pods found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as PodRow, selected, navigate)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Status" data={null}>
              {(row: unknown) => {
                const r = row as PodRow
                return r.status ? (
                  <span className={`badge ${PHASE_BADGE[r.status] ?? 'badge-info'}`}>
                    {r.status}
                  </span>
                ) : (
                  '—'
                )
              }}
            </Column>
            <Column title="Pod IP" data="podIp" />
            <Column title="Owner" data="owner" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PodsWorkloadView
