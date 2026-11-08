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
import type { ResourceList, ResourceQuotaItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact text
// rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The four 4.1 quota dimensions, in 4.1's order. A key missing from
// status.used or status.hard renders "—" (certainty rule: 4.1's template
// would KeyError here; 5.0 renders certainty, never guesses).
const STATUS_DIMENSIONS = ['limits.cpu', 'limits.memory', 'requests.cpu', 'requests.memory'] as const

/**
 * 4.1 `other-resources/resource-quota-data.html.j2` parity: one
 * ResourceQuota's metadata (name, created, namespace, scopes, labels,
 * annotations) plus a used-vs-hard Status table over the four 4.1 dimensions,
 * plus the full object as a syntax-highlighted JSON block. The read is a
 * SINGLE `?name=&namespace=` fetch (not 4.1's list-then-filter); empty
 * `items` is a not-found STATE (pinned copy), not an error. 4.1 deviations
 * (recorded in the change's adr.md): no Selectors table (the raw
 * `spec.scope_selector` stays in the JSON block), no `trimAnnotations`
 * (annotations render verbatim), and 4.1's duplicate `Creation` row is
 * collapsed into the single `Created` row. The list view's name links are
 * the sole producer of these query strings.
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. The legacy /data route (TICKET-07 keeps it working
// until the contract pass) passes the legacy ?name=/?namespace= through as
// props; this view no longer reads the URL.
const ResourceQuotaDataView = ({
  name,
  namespace,
}: {
  name: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<ResourceQuotaItem>({
    queryKey: ['resource-quota-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ResourceQuotaItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/resourcequotas?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
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
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/resource-quota" onClick={clearActiveRef}>
              Resource Quota List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Resource Quota Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: resource quota name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading resource quota data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No ResourceQuota '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading resource quota: {query.error.message}</div>
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
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp) || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{item?.metadata?.namespace ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Scope:</th>
                  <td>{item?.spec?.scopes?.join(', ') || '—'}</td>
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
            <CTable bordered className="mb-4">
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Used</th>
                  <th>Hard Limit</th>
                </tr>
              </thead>
              <tbody>
                {STATUS_DIMENSIONS.map((dim) => (
                  <tr key={dim}>
                    <td>{dim}</td>
                    <td>{item?.status?.used?.[dim] ?? '—'}</td>
                    <td>{item?.status?.hard?.[dim] ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </CTable>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Resource Quota</CCardTitle>
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

export default ResourceQuotaDataView
