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
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { VolumeSnapshotItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as ConfigMapData.tsx / SecretData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the raw custom object (a YAML
// subset), so the json grammar is the truthful classifier for the exact
// text rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The Ready To Use cell: the 4.1 status.readyToUse badge (true → success
// "Ready", false → danger "Not Ready", absent → plain "—" — the 4.1
// deep-index KeyError is fixed by rendering certainty, never guessing).
const readyCell = (ready: boolean | undefined) =>
  ready === undefined ? (
    '—'
  ) : ready ? (
    <CBadge color="success">Ready</CBadge>
  ) : (
    <CBadge color="danger">Not Ready</CBadge>
  )

/**
 * 5.0 VolumeSnapshot data page (NEW — 4.1 had NO data page: the list's name
 * link was commented out, a dead link). One VolumeSnapshot rendered as a
 * CTable over the 4.1 list columns (Name / Created / Source /
 * SnapshotClass / Ready To Use / Restore Size / Bound Content) plus the
 * labels/annotations sub-tables, plus the full object as a
 * syntax-highlighted JSON block. The read is a SINGLE `?name=&namespace=`
 * fetch (not 4.1's list-then-filter); empty `items` is a not-found STATE
 * (pinned copy) that ALSO covers the CRD-absent case (the snapshot
 * operator is optional; the read degrades to []), not an error. 4.1
 * deviations (briefing.md): the full-object block is JSON (truthful
 * classifier), NOT a YAML dump; the deep-index fields (Source /
 * SnapshotClass / Restore Size) render "—" when absent (4.1's KeyError-500
 * fix); trimAnnotations is NOT replicated (annotations render verbatim).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. This kind was a stub until this change: the /data
// URL never shipped, so there is no legacy route (no R7 redirect).
const VolumeSnapshotDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<VolumeSnapshotItem>({
    queryKey: ['volume-snapshot-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<VolumeSnapshotItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/volumesnapshots?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  const annotations = Object.entries(item?.metadata?.annotations ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/storage/volumesnapshot" onClick={clearActiveRef}>
              Volume Snapshot List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Volume Snapshot Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: volume snapshot name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading volume snapshot data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No VolumeSnapshot '{name}' found</div>
          ) : (
            <div className="text-danger">
              Error loading volume snapshot: {query.error.message}
            </div>
          )
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{item?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creationTimestamp) || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Source:</th>
                  {/* 4.1 deep-indexed spec.source.persistentVolumeClaimName
                      (KeyError-500 on a SourceMode-less snapshot) — render
                      "—" when absent. */}
                  <td>{item?.spec?.source?.persistentVolumeClaimName ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">SnapshotClass:</th>
                  <td>{item?.spec?.volumeSnapshotClassName ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Ready To Use:</th>
                  <td>{readyCell(item?.status?.readyToUse)}</td>
                </tr>
                <tr>
                  <th scope="row">Restore Size:</th>
                  <td>{item?.status?.restoreSize ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Bound Content:</th>
                  <td>{item?.status?.boundVolumeSnapshotContentName ?? '—'}</td>
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
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Volume Snapshot</CCardTitle>
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

export default VolumeSnapshotDataView
