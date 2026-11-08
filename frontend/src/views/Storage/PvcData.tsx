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
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { PvcItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as ResourceQuotaData.tsx / VolumeSnapshotData.tsx: the hljs
// language module is a singleton, so a second registration is harmless.
// Register `json` — the block is `JSON.stringify` of the to_dict object (a
// YAML subset), so the json grammar is the truthful classifier for the exact
// text rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// 4.1's three-tier Status badge (same tiers as the list): Bound → success,
// Terminating → danger, everything else non-empty → warning, "—" when
// absent (certainty rule).
const statusCell = (phase?: string) => {
  if (phase === 'Bound') return <CBadge color="success">Bound</CBadge>
  if (phase === 'Terminating') return <CBadge color="danger">Terminating</CBadge>
  if (phase) return <CBadge color="warning">{phase}</CBadge>
  return '—'
}

/**
 * 4.1 `storage/pvc-data.html.j2` parity: one PersistentVolumeClaim's
 * metadata (status, name, namespace, created, access mode, volume mode,
 * capacity, storage class, bound volume, labels, annotations) plus the full
 * object as a syntax-highlighted JSON block. The read is a SINGLE
 * `?name=&namespace=` fetch (not 4.1's list-then-filter); empty `items` is
 * a not-found STATE (pinned copy), not an error. 4.1 deviations (recorded
 * in the change's adr.md): the full-object block is JSON (truthful
 * classifier), 4.1's "Lables" typo is NOT replicated. `trimAnnotations`
 * IS replicated (2026-11-05 user request, overriding the 2026-10-28
 * "render verbatim" deviation — the override note is in the change's
 * adr.md).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. This kind was a stub until this change: the /data URL
// never shipped, so there is no legacy route (no R7 redirect).
const PvcDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<PvcItem>({
    queryKey: ['pvc-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PvcItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/persistentvolumeclaims?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  // 4.1's trimAnnotations (lib/helper_functions.py): the two machine-managed
  // keys are dropped from the rendered annotations. Replicated 2026-11-05 per
  // user request (overrides the 2026-10-28 "render verbatim" recorded
  // deviation; the HPA view already trims — 46929a10). The JSON block still
  // renders the full object.
  const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
    ([key]) =>
      key !== 'kubectl.kubernetes.io/last-applied-configuration'
      && key !== 'autoscaling.alpha.kubernetes.io/conditions',
  )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/storage/pvc" onClick={clearActiveRef}>
              Persistent Volume Claim List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume Claim Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: pvc name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pvc data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No PVC '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading pvc: {query.error.message}</div>
          )
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Status:</th>
                  <td>{statusCell(item?.status?.phase)}</td>
                </tr>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{item?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{namespace}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp) || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Access Mode:</th>
                  <td>{(item?.spec?.access_modes ?? []).join(', ') || '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Volume Mode:</th>
                  <td>{item?.spec?.volume_mode ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Capacity:</th>
                  <td>{item?.status?.capacity?.storage ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">StorageClass:</th>
                  <td>{item?.spec?.storage_class_name ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Persistent Volume:</th>
                  <td>{item?.spec?.volume_name ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Labels:</th>
                  <td>
                    {labels.length === 0 ? (
                      'No labels'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {labels.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Annotations:</th>
                  <td>
                    {annotations.length === 0 ? (
                      'No annotations'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {annotations.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
              </tbody>
            </CTable>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume Claim</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <SyntaxHighlighter
                  language="json"
                  style={anOldHope}
                  wrapLongLines
                  customStyle={{ margin: 0 }}
                  codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                >
                  {JSON.stringify(item, null, 2)}
                </SyntaxHighlighter>
              </CCardBody>
            </CCard>
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PvcDataView
