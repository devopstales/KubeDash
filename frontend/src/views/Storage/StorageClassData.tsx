import React from 'react'
import { Link } from 'react-router-dom'
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
import { clearActiveRef } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { StorageClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact text
// rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * 4.1 `storage/storage-class-data.html.j2` parity: one StorageClass's
 * metadata (reclaim policy, volume binding mode, provisioner, labels,
 * annotations) plus the 4.1 dynamic-key Parameters table (one row per
 * `parameters` entry) plus the full object as a syntax-highlighted block
 * (`JSON.stringify` of the `to_dict` item — JSON is a YAML subset; the
 * block is JSON text with the truthful `json` highlighter, ratified
 * 2026-10-28). The read is a SINGLE `?name=` fetch (not 4.1's
 * list-then-filter); the kind is cluster-scoped, so the URL carries no
 * namespace param. Empty `items` is a not-found STATE (pinned copy), not
 * an error. 4.1 deviations (briefing.md): the "Binding Mode" label renders
 * as `Volume Binding Mode` (the 4.1 list header, kept verbatim);
 * trimAnnotations IS replicated (2026-11-05 user request, overriding the
 * 2026-10-28 "render verbatim" deviation — the override note is in the
 * change's adr.md).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). This kind was a
// stub until this change: the /data URL never shipped, so there is no
// legacy route (no R7 redirect) to pass the name through.
const StorageClassDataView = ({ name }: { name: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<StorageClassItem>({
    queryKey: ['storage-class-data', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<StorageClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/storageclasses?name=${encodeURIComponent(name)}`,
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
  // 4.1's dynamic-key Parameters card, one row per entry.
  const parameters = Object.entries(item?.parameters ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/storage/storage-class" onClick={clearActiveRef}>
              Storage Classes List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Storage Class Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: storage class name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading storage class data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No StorageClass '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading storage class: {query.error.message}</div>
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
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp)}</td>
                </tr>
                <tr>
                  <th scope="row">Reclaim Policy:</th>
                  <td>{item?.reclaim_policy ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Volume Binding Mode:</th>
                  <td>{item?.volume_binding_mode ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Provisioner:</th>
                  <td>{item?.provisioner ?? '—'}</td>
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
            <CCard className="mb-3">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Parameters</CCardTitle>
              </CCardHeader>
              <CCardBody>
                {parameters.length === 0 ? (
                  <div>No parameters</div>
                ) : (
                  <CTable bordered>
                    <thead>
                      <tr>
                        <th>Key</th>
                        <th>Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {parameters.map(([key, value]) => (
                        <tr key={key}>
                          <td>{key}</td>
                          <td className="text-break">{value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </CTable>
                )}
              </CCardBody>
            </CCard>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Storage Class</CCardTitle>
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

export default StorageClassDataView
