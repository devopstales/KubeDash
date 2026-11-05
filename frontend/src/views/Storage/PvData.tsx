import React from 'react'
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
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef, openObject } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { PersistentVolumeItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as StorageClassData.tsx: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the to_dict object (a YAML subset), so the
// json grammar is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * 4.1 `storage/pv-data.html.j2` parity: one PersistentVolume's metadata
 * (status, created, deleted, annotations, labels), the claim rows (storage
 * class, volume claim, claim namespace), the spec rows (access mode, volume
 * mode, reclaim policy, capacity), the 4.1 XOR rows (Local Path for hostPath
 * PVs, else CSI Driver + Filesystem Type) and the dynamic Volume Attributes
 * table — plus the full object as a syntax-highlighted block
 * (`JSON.stringify` of the `to_dict` item — JSON is a YAML subset; the block
 * is JSON text with the truthful `json` highlighter, ratified 2026-10-28).
 * The read is a SINGLE `?name=` fetch (4.1's list-then-filter is dropped);
 * the kind is cluster-scoped, so the URL carries no namespace param. Empty
 * `items` is a not-found STATE (pinned copy), not an error. 4.1 deviations
 * (adr.md): the row label is `Persistent Volume Claim` (4.1's `Clame` typo
 * is not carried over); trimAnnotations IS replicated (2026-11-05 user
 * decision). The StorageClass/Claim cells are ADR-0040 object refs
 * (cross-kind opens; the claim ref carries the claim's own namespace, R8).
 * This kind was a stub until this change: the /data URL never shipped, so
 * there is no legacy route (no R7 redirect).
 */
const PvDataView = ({ name }: { name: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<PersistentVolumeItem>({
    queryKey: ['pv-data', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PersistentVolumeItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/persistentvolumes?name=${encodeURIComponent(name)}`,
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
  // user request (the 2026-11-04 HPA shape, 46929a10). The JSON block still
  // renders the full object.
  const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
    ([key]) =>
      key !== 'kubectl.kubernetes.io/last-applied-configuration'
      && key !== 'autoscaling.alpha.kubernetes.io/conditions',
  )
  // 4.1: a deletion timestamp overrides the displayed status (Terminating).
  const deleting = Boolean(item?.metadata?.deletion_timestamp)
  const status = deleting
    ? 'Terminating'
    : (item?.status?.phase ?? '—')
  const claimRef = item?.spec?.claim_ref
  const csi = item?.spec?.csi
  const hostPath = item?.spec?.host_path
  const volumeAttributes = Object.entries(csi?.volume_attributes ?? {})
  const accessModes = (item?.spec?.access_modes ?? []).join(', ')

  // ADR-0040: cross-kind object refs (buttons, not Links) — openObject
  // writes the ref to sessionStorage and navigates to the target list
  // route; the URL never carries object identity (R1). The claim ref
  // carries the claim's OWN namespace (R8).
  const storageClassLink = (
    <button
      type="button"
      className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
      onClick={() =>
        openObject(
          'storageclass',
          item?.spec?.storage_class_name ?? '',
          undefined,
          '/storage/storage-class',
          navigate,
        )
      }
    >
      {item?.spec?.storage_class_name ?? '—'}
    </button>
  )

  const claimLink = (
    <button
      type="button"
      className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
      onClick={() =>
        openObject(
          // The target route's registry kind (App.tsx: ObjectRoute
          // kind="pvc") — ObjectRoute matches ref.kind === kind verbatim.
          'pvc',
          claimRef?.name ?? '',
          claimRef?.namespace,
          '/storage/pvc',
          navigate,
        )
      }
    >
      {claimRef?.name ?? '—'}
    </button>
  )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/storage/pv" onClick={clearActiveRef}>
              Persistent Volume List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: pv name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pv data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No PersistentVolume '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading pv: {query.error.message}</div>
          )
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Status:</th>
                  <td>{status}</td>
                </tr>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{item?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp)}</td>
                </tr>
                {deleting && (
                  <tr>
                    <th scope="row">Deleted:</th>
                    <td>{formatTimestamp(item?.metadata?.deletion_timestamp)}</td>
                  </tr>
                )}
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
                  <th scope="row">StorageClass:</th>
                  <td>{item?.spec?.storage_class_name ? storageClassLink : '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Persistent Volume Claim:</th>
                  <td>{claimRef?.name ? claimLink : '—'}</td>
                </tr>
                <tr>
                  <th scope="row">PVC Namespace:</th>
                  <td>{claimRef?.namespace ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Access Mode:</th>
                  <td>{accessModes || '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Volume Mode:</th>
                  <td>{item?.spec?.volume_mode ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Reclaim Policy:</th>
                  <td>{item?.spec?.persistent_volume_reclaim_policy ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Capacity:</th>
                  <td>{item?.spec?.capacity?.storage ?? '—'}</td>
                </tr>
                {hostPath && (
                  <tr>
                    <th scope="row">Local Path:</th>
                    <td>{hostPath.path ?? '—'}</td>
                  </tr>
                )}
                {csi && (
                  <tr>
                    <th scope="row">CSI Driver:</th>
                    <td>{csi.driver ?? '—'}</td>
                  </tr>
                )}
                {csi && (
                  <tr>
                    <th scope="row">Filesystem Type:</th>
                    <td>{csi.fs_type ?? '—'}</td>
                  </tr>
                )}
              </tbody>
            </CTable>
            {volumeAttributes.length > 0 && (
              <CCard className="mb-3">
                <CCardHeader className="py-2">
                  <CCardTitle className="m-0 fw-bold text-primary fs-6">Volume Attributes</CCardTitle>
                </CCardHeader>
                <CCardBody>
                  <CTable bordered>
                    <thead>
                      <tr>
                        <th>Key</th>
                        <th>Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {volumeAttributes.map(([key, value]) => (
                        <tr key={key}>
                          <td>{key}</td>
                          <td className="text-break">{value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </CTable>
                </CCardBody>
              </CCard>
            )}
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume</CCardTitle>
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

export default PvDataView
