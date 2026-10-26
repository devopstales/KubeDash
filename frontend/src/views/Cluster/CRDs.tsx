import React from 'react'
import { Link } from 'react-router-dom'
import { CBadge, CBreadcrumb, CBreadcrumbItem, CCard, CCardBody, CCardHeader, CCardTitle } from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { apiFetch } from '../../lib/api'
import type { K8sCrd, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

/**
 * 4.1 `cluster/crd.html.j2` (the Interface → Cluster → CRDs list), rewritten
 * for 5.0: a KubeDataTable (ADR-0023) instead of the jQuery snippet, a
 * `<Link>` instead of 4.1's hidden-form + sessionStorage navigation, and the
 * served-versions column (4.1 collapsed to a single "Version"). The list is
 * SAR-gated on `list customresourcedefinitions` — a 403 renders as the
 * standard error row, never a fake empty table.
 */

const fmtCreated = (ts: string | null | undefined): string => {
  if (!ts) return '\u2014'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

type ServedVersion = { name: string; storage: boolean }

type CrdRow = {
  kind: string
  group: string
  plural: string
  scope: string
  served: ServedVersion[]
  created: string
  // Composite field the Kind column renders a <Link> from: {kind, crdName}.
  // The renderer receives only row[data], so the link target must ride on the
  // field (the Roles/Namespaces views use the same toRow pattern).
  //
  // IMPORTANT: the detail route is keyed on the CRD's metadata.name
  // (`<plural>.<group>`, e.g. `ciliumbgpadvertisements.cilium.io`), NOT the
  // bare plural — the backend `get_crd` API call 404s on a bare plural.
  kindLink: { kind: string; crdName: string }
}

const toRow = (crd: K8sCrd): CrdRow => {
  const spec = crd.spec ?? {}
  const versions = (spec.versions ?? [])
    .filter((v) => v.served && v.name)
    .map((v) => ({ name: v.name as string, storage: Boolean(v.storage) }))
  const kind = spec.names?.kind ?? ''
  const plural = spec.names?.plural ?? ''
  const crdName = crd.metadata?.name ?? ''
  return {
    kind,
    group: spec.group ?? '',
    plural,
    scope: spec.scope ?? 'Unknown',
    served: versions,
    created: crd.metadata?.creationTimestamp ?? '',
    kindLink: { kind, crdName },
  }
}

const kindLink = ({ kind, crdName }: CrdRow['kindLink']) =>
  crdName ? (
    <Link to={`/cluster/crd/data?name=${encodeURIComponent(crdName)}`}>{kind || '\u2014'}</Link>
  ) : (
    kind || '\u2014'
  )

const scopeBadge = (scope: string) => (
  <CBadge color={scope === 'Namespaced' ? 'info' : 'secondary'}>{scope}</CBadge>
)

const servedCell = (versions: ServedVersion[]) =>
  versions.length === 0 ? (
    <span className="text-muted">none served</span>
  ) : (
    <span className="d-inline-flex gap-1 flex-wrap">
      {versions.map((v) => (
        <CBadge key={v.name} color={v.storage ? 'primary' : 'secondary'}>
          {v.name}
          {v.storage ? ' \u2726' : ''}
        </CBadge>
      ))}
    </span>
  )

const CrdsView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<ResourceList<K8sCrd>['items']>({
    queryKey: ['crds', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sCrd>>(
        `/api/v1/clusters/${cluster!.id}/resources/crds`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  const rows = (query.data ?? []).map(toRow)

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster</CBreadcrumbItem>
          <CBreadcrumbItem active>CRDs</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">CRD List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading CRDs...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading CRDs: {query.error.message}</div>
        ) : rows.length === 0 ? (
          <div className="text-center text-muted">No CRDs found</div>
        ) : (
          <KubeDataTable data={rows}>
            <Column title="Kind" data="kindLink">
              {kindLink}
            </Column>
            <Column title="Group" data="group" />
            <Column title="Plural" data="plural" />
            <Column title="Scope" data="scope">
              {scopeBadge}
            </Column>
            <Column title="Served" data="served">
              {servedCell}
            </Column>
            <Column title="Created" data="created">
              {(created: string) => fmtCreated(created)}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default CrdsView
