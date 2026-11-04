import React from 'react'
import { Link } from 'react-router-dom'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { K8sNamespace, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// ADR-0040: cluster-scoped kind — the ref carries no namespace.
const KIND = 'namespace'
const LIST_ROUTE = '/cluster/namespace'

const KeyValueTable = ({ entries, empty }: { entries: [string, string][]; empty: string }) =>
  entries.length === 0 ? (
    <>{empty}</>
  ) : (
    <CTable bordered small className="mb-0">
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([key, value]) => (
          <tr key={key}>
            <td>{key}</td>
            <td className="text-break">{value}</td>
          </tr>
        ))}
      </tbody>
    </CTable>
  )

/**
 * 4.1 `cluster/namespace-data.html.j2`: one Namespace's status, name,
 * created time, annotations, and labels.
 *
 * ADR-0040: identity arrives as props from ObjectRoute (the active ref),
 * never from useSearchParams — the URL stays clean (R1/R8). The 4.1
 * `?namespace=` bookmark read moved off the view: the legacy /data route
 * (TICKET-07's redirect layer) passes `?name= ?? ?namespace=` through as
 * the prop, so existing 4.1 bookmarks keep working until the R7 redirect
 * supersedes them.
 */
const NamespaceDataView = ({ name }: { name: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<K8sNamespace[]>({
    queryKey: ['namespaces', cluster?.id],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sNamespace>>(
        `/api/v1/clusters/${cluster!.id}/resources/namespaces`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  const namespace = (query.data ?? []).find((item) => item.metadata?.name === name)
  const annotations = Object.entries(namespace?.metadata?.annotations ?? {})
  const labels = Object.entries(namespace?.metadata?.labels ?? {})
  const status = namespace?.status?.phase ?? 'Unknown'

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/cluster/namespace">Namespaces</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6 d-flex align-items-center gap-2">
          Namespace Data
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: Namespace name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading namespace data...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading namespace: {query.error.message}</div>
        ) : !namespace ? (
          <div className="text-danger">Error: Namespace '{name}' not found</div>
        ) : (
          <CTable bordered>
            <tbody>
              <tr>
                <th scope="row">Status:</th>
                <td>
                  <CBadge color={status === 'Active' ? 'success' : 'danger'}>{status}</CBadge>
                </td>
              </tr>
              <tr>
                <th scope="row">Name:</th>
                <td>{namespace.metadata?.name ?? ''}</td>
              </tr>
              <tr>
                <th scope="row">Created:</th>
                <td>{namespace.metadata?.creation_timestamp ?? ''}</td>
              </tr>
              <tr>
                <th scope="row">Annotations:</th>
                <td>
                  <KeyValueTable entries={annotations} empty="No annotations" />
                </td>
              </tr>
              <tr>
                <th scope="row">Labels:</th>
                <td>
                  <KeyValueTable entries={labels} empty="No labels" />
                </td>
              </tr>
            </tbody>
          </CTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default NamespaceDataView
