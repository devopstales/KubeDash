import { Link, useNavigate } from 'react-router-dom'
import {
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
import { clearActiveRef, openObject } from '../../lib/objectRef'
import type { ResourceList, ServiceAccount } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'

const SECRET_ROUTE = '/security/secret'

// ponytail: the ServiceAccount wire type carries `{ name?: string }` refs
// (types.ts) while `names` wants the SecretRef alias — the same shape, so
// widen the parameter to the wire type instead of casting at the two call
// sites. Ceiling: if the backend ever starts emitting refs without `name`,
// the `.filter((name) => name.length > 0)` already handles it.
const names = (refs: { name?: string }[] | null | undefined) =>
  (refs ?? []).map((ref) => ref.name ?? '').filter((name) => name.length > 0)

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
 * End page for one ServiceAccount: name, namespace, created time,
 * annotations (without last-applied), labels, and every token / image
 * pull secret. A secret opens the Secret kind's detail (openObject with
 * the target kind — R9: no ?selected= producer).
 *
 * ADR-0040: identity arrives as props (ObjectRoute's ref, R8) — the view
 * never reads useSearchParams; the URL stays clean (R1).
 */
const ServiceAccountDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<ServiceAccount>({
    queryKey: ['serviceaccounts', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ServiceAccount>>(
        `/api/v1/clusters/${cluster!.id}/resources/serviceaccounts?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const account = (r.data?.items ?? []).find((item) => item.metadata?.name === name)
      if (!account) throw new Error(`Service account '${name}' not found`)
      return account
    },
  })

  const account = query.data
  const annotations = Object.entries(account?.metadata?.annotations ?? {}).filter(
    ([key]) => key !== LAST_APPLIED,
  )
  const labels = Object.entries(account?.metadata?.labels ?? {})

  const secretLinks = (items: string[]) => {
    if (items.length === 0) return ' '
    return (
      <>
        {items.map((item, i) => (
          <span key={`${item}-${i}`}>
            {i > 0 ? <br /> : null}
            <button
              type="button"
              className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
              onClick={() => openObject('secret', item, namespace, SECRET_ROUTE, navigate)}
            >
              {item}
            </button>
          </span>
        ))}
      </>
    )
  }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster Permissions</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/cluster-permission/service-account" onClick={clearActiveRef}>
              Service Accounts
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Service Account Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: Service account name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading service account...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading service account: {query.error.message}</div>
        ) : (
          <CTable bordered>
            <tbody>
              <tr>
                <th scope="row">Name:</th>
                <td>{account?.metadata?.name ?? ''}</td>
              </tr>
              <tr>
                <th scope="row">Namespace:</th>
                <td>{account?.metadata?.namespace || namespace}</td>
              </tr>
              <tr>
                <th scope="row">Kind:</th>
                <td>ServiceAccount</td>
              </tr>
              <tr>
                <th scope="row">Created:</th>
                <td>{account?.metadata?.creation_timestamp ?? 'N/A'}</td>
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
              <tr>
                <th scope="row">Secret:</th>
                <td>{secretLinks(names(account?.secrets))}</td>
              </tr>
              <tr>
                <th scope="row">Pull Secret:</th>
                <td>{secretLinks(names(account?.image_pull_secrets))}</td>
              </tr>
            </tbody>
          </CTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ServiceAccountDataView
