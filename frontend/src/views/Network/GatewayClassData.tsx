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
import type { GatewayClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as StorageClassData.tsx: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the FULL custom object, so the json grammar
// is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * NEW (4.1 had no Gateway API): one GatewayClass's metadata (controller,
 * created, labels, annotations) on the VPA CRD seam (full custom object,
 * camelCase — `spec.controllerName`, `metadata.creationTimestamp`) plus the
 * full object as a syntax-highlighted block. The read is a SINGLE `?name=`
 * fetch; the kind is cluster-scoped, so the URL carries no namespace param.
 * Empty `items` is a not-found STATE (pinned copy) — this is ALSO the
 * CRD-absent state (Gateway API not installed), never an error style.
 * trimAnnotations IS replicated (2026-11-05 user request — the override
 * note is in the change's adr.md); the JSON block still renders the full
 * object.
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). This kind was a
// stub until this change: the /data URL never shipped, so there is no
// legacy route (no R7 redirect) to pass the name through.
const GatewayClassDataView = ({ name }: { name: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<GatewayClassItem>({
    queryKey: ['gateway-class-data', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<GatewayClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/gatewayclasses?name=${encodeURIComponent(name)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  // 4.1's trimAnnotations: the two machine-managed keys are dropped from the
  // rendered annotations (replicated 2026-11-05 per user request). The JSON
  // block still renders the full object.
  const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
    ([key]) =>
      key !== 'kubectl.kubernetes.io/last-applied-configuration'
      && key !== 'autoscaling.alpha.kubernetes.io/conditions',
  )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/network/ingress-class" onClick={clearActiveRef}>
              IngressClass List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">GatewayClass Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: gateway class name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading gateway class data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No GatewayClass '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading gateway class: {query.error.message}</div>
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
                  <th scope="row">Controller:</th>
                  <td>{item?.spec?.controllerName ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creationTimestamp)}</td>
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
                <CCardTitle className="m-0 fw-bold text-primary fs-6">GatewayClass</CCardTitle>
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

export default GatewayClassDataView
