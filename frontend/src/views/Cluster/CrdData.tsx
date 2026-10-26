import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
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
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { apiFetch } from '../../lib/api'
import type { CrdInstance, K8sCrd, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

/**
 * 4.1 `cluster/crd-data.html.j2` (the CRD instance detail), rewritten for 5.0:
 * the served version + scope come from the CRD ITSELF (a `?name=` read on the
 * CRD), not 4.1's client-side namespaced→cluster fallback; the navigation is a
 * `?name=` query, not 4.1's sessionStorage + hidden form. Two API calls — the
 * CRD read (resolves group/version/scope/plural) and the instance list (SAR
 * `list` on the CRD + `list` on the instances, each 403 naming the denied
 * resource).
 */

const fmtCreated = (ts: string | null | undefined): string => {
  if (!ts) return '\u2014'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

const statusBadge = (status: string) => {
  let color: 'success' | 'danger' | 'secondary' = 'secondary'
  if (status === 'True' || status === 'Ready' || status === 'Active') color = 'success'
  else if (status === 'False' || status === 'Unknown' || status === 'Failed' || status === 'Error')
    color = 'danger'
  return <CBadge color={color}>{status || '\u2014'}</CBadge>
}

const CrdDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') || ''
  const cluster = useClusterStore((s) => s.selectedCluster)
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)

  // Call 1: the CRD itself — resolves group, served version, scope, plural.
  // The `?name=` path is SAR-gated with `get` on customresourcedefinitions.
  const crdQuery = useQuery<K8sCrd | null>({
    queryKey: ['crd', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sCrd>>(
        `/api/v1/clusters/${cluster!.id}/resources/crds?name=${encodeURIComponent(name)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items?.[0] ?? null
    },
  })

  const crd = crdQuery.data
  const spec = crd?.spec
  const scopeNamespaced = spec?.scope === 'Namespaced'
  const servedVersion = (spec?.versions ?? []).find((v) => v.served && v.name)?.name ?? null
  // The topbar namespace applies only to namespaced-scoped CRDs.
  const namespace = scopeNamespaced && selectedNamespace ? selectedNamespace : null

  // Call 2: the instance list. Gated by the CRD being resolved (we need its
  // group/version/scope/plural from call 1) — the dependency on crdQuery.data
  // keeps the two calls ordered, never concurrent.
  const instancesQuery = useQuery<ResourceList<CrdInstance>['items']>({
    queryKey: ['crd-instances', cluster?.id, name, servedVersion, namespace],
    enabled:
      cluster != null &&
      name !== '' &&
      crd != null &&
      spec?.group != null &&
      servedVersion != null,
    queryFn: async () => {
      const ns = namespace ? `&namespace=${encodeURIComponent(namespace)}` : ''
      const r = await apiFetch<ResourceList<CrdInstance>>(
        `/api/v1/clusters/${cluster!.id}/resources/crds/instances?name=${encodeURIComponent(name)}${ns}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  const instances = instancesQuery.data ?? []

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/cluster/crd">CRDs</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{spec?.names?.kind || name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">
          CRD Data — {spec?.names?.kind || name}
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: CRD name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : crdQuery.isLoading ? (
          <div>Loading CRD data...</div>
        ) : crdQuery.error ? (
          <div className="text-danger">Error loading CRD: {crdQuery.error.message}</div>
        ) : !crd ? (
          <div className="text-danger">Error: CRD '{name}' not found</div>
        ) : (
          <>
            {/* The CRD's own identity, resolved server-side (the 4.1
                namespaced→cluster fallback is gone — the CRD status is the
                authority on scope + served version). */}
            <CTable bordered small className="mb-4">
              <tbody>
                <tr>
                  <th scope="row">Group:</th>
                  <td>{spec?.group ?? '\u2014'}</td>
                </tr>
                <tr>
                  <th scope="row">Kind:</th>
                  <td>{spec?.names?.kind ?? '\u2014'}</td>
                </tr>
                <tr>
                  <th scope="row">Plural:</th>
                  <td>{spec?.names?.plural ?? '\u2014'}</td>
                </tr>
                <tr>
                  <th scope="row">Scope:</th>
                  <td>{statusBadge(scopeNamespaced ? 'Namespaced' : 'Cluster')}</td>
                </tr>
                <tr>
                  <th scope="row">Served Version:</th>
                  <td>{servedVersion ?? 'none'}</td>
                </tr>
              </tbody>
            </CTable>

            {instancesQuery.isLoading ? (
              <div>Loading instances...</div>
            ) : instancesQuery.error ? (
              <div className="text-danger">Error loading instances: {instancesQuery.error.message}</div>
            ) : instances.length === 0 ? (
              // The 4.1 first-class empty state: an empty result is the COMMON
              // case for a CRD detail, not an error.
              <div className="text-center text-muted">
                No {spec?.names?.kind ?? 'resource'} instances found
                {scopeNamespaced && namespace
                  ? ` in namespace '${namespace}'`
                  : scopeNamespaced
                    ? ' (cluster-scoped list — no namespace selected)'
                    : ' (cluster-scoped)'}
                . This is normal if no instances exist yet.
              </div>
            ) : (
              <KubeDataTable data={instances}>
                <Column title="Name" data="name" />
                <Column title="Namespace" data="namespace">
                  {(ns: string | null) => ns ?? '\u2014'}
                </Column>
                <Column title="Status" data="status">
                  {(status: string) => statusBadge(status)}
                </Column>
                <Column title="Type" data="type">
                  {(type: string) => type || '\u2014'}
                </Column>
                <Column title="Reason" data="reason">
                  {(reason: string) => reason || '\u2014'}
                </Column>
                <Column title="Message" data="message">
                  {(message: string) => message || '\u2014'}
                </Column>
                <Column title="Created" data="created">
                  {(created: string | null) => fmtCreated(created)}
                </Column>
              </KubeDataTable>
            )}
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default CrdDataView
